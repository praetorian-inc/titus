package scoring

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// scorerAuth mirrors pkg/validator/yaml.go AuthDef — duplicated here since
// validator's types are in a separate package and this is package-private.
type scorerAuth struct {
	Type        string // "bearer" | "basic" | "header" | "query" | "api_key"
	SecretGroup string // named capture group containing the secret bytes
	HeaderName  string // for type=header
	QueryParam  string // for type=query
	Username    string // for type=basic (static username)
	KeyPrefix   string // for type=api_key
}

// scorerHeader is a static request header (value may contain {{group}} vars).
type scorerHeader struct {
	Name  string
	Value string
}

var defaultHTTPClient = &http.Client{Timeout: 30 * time.Second}

// renderedRequest is a request whose {{group}} template variables have already
// been substituted. Rendering once and using the same values for both the cache
// key and the outgoing request keeps the two in lockstep.
//
// This matters because substituteVarsInURL iterates NamedGroups in Go's
// unspecified map order. If one captured value happens to contain what looks
// like another placeholder, substituting twice can produce two different
// strings — so a key built by a second, independent substitution pass could
// describe a request that was never sent.
type renderedRequest struct {
	method  string
	url     string
	headers []scorerHeader
	body    string
}

// renderRequest substitutes template variables once, for every part of the request.
func renderRequest(method, rawURL string, headers []scorerHeader, body string, namedGroups map[string][]byte) renderedRequest {
	rendered := make([]scorerHeader, len(headers))
	for i, h := range headers {
		rendered[i] = scorerHeader{Name: h.Name, Value: substituteVarsInURL(h.Value, namedGroups)}
	}
	return renderedRequest{
		method:  method,
		url:     substituteVarsInURL(rawURL, namedGroups),
		headers: rendered,
		body:    substituteVarsInURL(body, namedGroups),
	}
}

// makeHTTPRequest renders the request and sends it. Callers that need the
// rendered values themselves — to build a cache key that matches what is
// actually sent — should call renderRequest and sendRenderedRequest instead.
// The context carries the per-modifier deadline; callers must set it.
func makeHTTPRequest(
	ctx context.Context,
	method, rawURL string,
	headers []scorerHeader,
	body string,
	auth scorerAuth,
	namedGroups map[string][]byte,
) (*cachedHTTPResponse, error) {
	r := renderRequest(method, rawURL, headers, body, namedGroups)
	return sendRenderedRequest(ctx, r, auth, string(namedGroups[auth.SecretGroup]))
}

// sendRenderedRequest performs an already-rendered request. It does no further
// template substitution.
func sendRenderedRequest(
	ctx context.Context,
	r renderedRequest,
	auth scorerAuth,
	secret string,
) (*cachedHTTPResponse, error) {
	var bodyReader io.Reader
	if r.body != "" {
		bodyReader = strings.NewReader(r.body)
	}

	req, err := http.NewRequestWithContext(ctx, r.method, r.url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("building HTTP request: %w", err)
	}

	for _, h := range r.headers {
		req.Header.Set(h.Name, h.Value)
	}

	// Auth
	if auth.Type != "" && auth.SecretGroup != "" {
		if err := applyScorerAuth(req, auth, secret); err != nil {
			return nil, fmt.Errorf("applying auth: %w", err)
		}
	}

	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	// Collect response headers (lower-cased)
	hdrs := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			hdrs[strings.ToLower(k)] = vs[0]
		}
	}

	return &cachedHTTPResponse{
		StatusCode: resp.StatusCode,
		Body:       bodyBytes,
		Headers:    hdrs,
	}, nil
}

// applyScorerAuth sets auth on the request from the auth config + secret string.
func applyScorerAuth(req *http.Request, auth scorerAuth, secret string) error {
	switch strings.ToLower(auth.Type) {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+secret)
	case "basic":
		encoded := base64.StdEncoding.EncodeToString([]byte(auth.Username + ":" + secret))
		req.Header.Set("Authorization", "Basic "+encoded)
	case "header":
		if auth.HeaderName == "" {
			return fmt.Errorf("auth type=header requires header_name")
		}
		req.Header.Set(auth.HeaderName, secret)
	case "query":
		if auth.QueryParam == "" {
			return fmt.Errorf("auth type=query requires query_param")
		}
		q := req.URL.Query()
		q.Set(auth.QueryParam, secret)
		req.URL.RawQuery = q.Encode()
	case "none":
		// The credential travels in the URL or body via a {{template}} variable
		// rather than a header. secret_group must still be set: the response cache
		// keys on it, and without it every finding sharing a URL template collides.
		return nil
	case "api_key":
		prefix := auth.KeyPrefix
		if prefix == "" {
			prefix = "key="
		}
		req.Header.Set("Authorization", prefix+secret)
	default:
		return fmt.Errorf("unknown auth type %q", auth.Type)
	}
	return nil
}

// substituteVarsInURL replaces {{group}} placeholders with values from namedGroups.
// Handles both {{name}} and {{ name }} (with spaces).
func substituteVarsInURL(s string, groups map[string][]byte) string {
	for k, v := range groups {
		s = strings.ReplaceAll(s, "{{"+k+"}}", string(v))
		s = strings.ReplaceAll(s, "{{ "+k+" }}", string(v))
	}
	return s
}

// supportedAuthTypes is the set applyScorerAuth accepts, kept next to that
// switch so the loader's validation cannot drift from what the request layer
// actually handles. An unsupported type used to load fine and fail at request
// time, where the engine logged it and skipped the modifier -- the scorer ran
// and silently did nothing (LAB-6049).
var supportedAuthTypes = map[string]bool{
	"bearer":  true,
	"basic":   true,
	"header":  true,
	"query":   true,
	"api_key": true,
	"none":    true,
}
