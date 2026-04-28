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

// makeHTTPRequest performs an HTTP request on behalf of an httpCondition.
// namedGroups is used to substitute {{group}} template variables in URL and headers.
// The context carries the per-modifier deadline; callers must set it.
func makeHTTPRequest(
	ctx context.Context,
	method, rawURL string,
	headers []scorerHeader,
	body string,
	auth scorerAuth,
	namedGroups map[string][]byte,
) (*cachedHTTPResponse, error) {
	url := substituteVarsInURL(rawURL, namedGroups)

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(substituteVarsInURL(body, namedGroups))
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("building HTTP request: %w", err)
	}

	// Static headers (template vars substituted)
	for _, h := range headers {
		req.Header.Set(h.Name, substituteVarsInURL(h.Value, namedGroups))
	}

	// Auth
	if auth.Type != "" && auth.SecretGroup != "" {
		secret := string(namedGroups[auth.SecretGroup])
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
