package scoring

import (
	"context"
	"crypto/md5" // #nosec G501 -- MD5 is required by HTTP Digest authentication (RFC 7616); not used as a cryptographic primitive.
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const atlasBaseURL = "https://cloud.mongodb.com"

// atlasAPI is the MongoDB Atlas API operation subset used by scorers.
type atlasAPI interface {
	// ListOrgs returns organizations the key has access to, with roles.
	// GET /api/atlas/v2/orgs
	ListOrgs(ctx context.Context) ([]AtlasOrgMembership, error)

	// ListProjects returns projects (groups) the key has access to, with roles.
	// GET /api/atlas/v2/groups
	ListProjects(ctx context.Context) ([]AtlasProjectMembership, error)
}

// AtlasOrgMembership describes a single organization the key can access.
type AtlasOrgMembership struct {
	OrgID string
	Roles []string // e.g. "ORG_OWNER", "ORG_MEMBER", "ORG_READ_ONLY"
}

// AtlasProjectMembership describes a single project (group) the key can access.
type AtlasProjectMembership struct {
	GroupID string
	Name    string
	Roles   []string // e.g. "GROUP_OWNER", "GROUP_READ_ONLY", "GROUP_DATA_ACCESS_READ_ONLY"
}

// atlasClientFactory creates an Atlas API client.
// For kingfisher.mongodb.1: digest auth using publicKey + privateKey.
// For kingfisher.mongodb.4: bearer auth using service account token.
// Inject a fake factory in tests.
type atlasClientFactory func(ctx context.Context, authType string, credentials map[string]string) (atlasAPI, error)

func defaultAtlasClientFactory(_ context.Context, authType string, creds map[string]string) (atlasAPI, error) {
	switch authType {
	case "digest":
		pub, ok1 := creds["publicKey"]
		priv, ok2 := creds["privateKey"]
		if !ok1 || !ok2 || pub == "" || priv == "" {
			return nil, fmt.Errorf("atlas digest: missing publicKey or privateKey")
		}
		return &atlasHTTPClient{
			httpClient: defaultHTTPClient,
			authType:   "digest",
			publicKey:  pub,
			privateKey: priv,
		}, nil
	case "bearer":
		tok, ok := creds["token"]
		if !ok || tok == "" {
			return nil, fmt.Errorf("atlas bearer: missing token")
		}
		return &atlasHTTPClient{
			httpClient: defaultHTTPClient,
			authType:   "bearer",
			token:      tok,
		}, nil
	default:
		return nil, fmt.Errorf("atlas: unknown authType %q", authType)
	}
}

// atlasHTTPClient implements atlasAPI over HTTP.
type atlasHTTPClient struct {
	httpClient *http.Client
	authType   string
	publicKey  string // digest only
	privateKey string // digest only
	token      string // bearer only
}

// get performs a GET to the given path and decodes the JSON body into dest.
// For digest auth it handles the 401 challenge/response cycle.
func (c *atlasHTTPClient) get(ctx context.Context, path string, dest interface{}) error {
	url := atlasBaseURL + path
	switch c.authType {
	case "bearer":
		return c.bearerGet(ctx, url, dest)
	case "digest":
		return c.digestGet(ctx, url, dest)
	default:
		return fmt.Errorf("atlas: unknown authType %q", c.authType)
	}
}

func (c *atlasHTTPClient) bearerGet(ctx context.Context, url string, dest interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.atlas.2023-02-01+json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("atlas: HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dest)
}

func (c *atlasHTTPClient) digestGet(ctx context.Context, url string, dest interface{}) error {
	// First request — expect 401 with WWW-Authenticate: Digest ...
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.atlas.2023-02-01+json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	// Discard body before closing to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("atlas digest: expected 401 on first request, got %d", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	authHeader, err := buildDigestAuthHeader(c.publicKey, c.privateKey, http.MethodGet, url, wwwAuth)
	if err != nil {
		return fmt.Errorf("atlas digest: %w", err)
	}

	// Second request — with computed Digest Authorization header.
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req2.Header.Set("Authorization", authHeader)
	req2.Header.Set("Accept", "application/vnd.atlas.2023-02-01+json")
	resp2, err := c.httpClient.Do(req2)
	if err != nil {
		return err
	}
	defer resp2.Body.Close()
	if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
		return fmt.Errorf("atlas: HTTP %d", resp2.StatusCode)
	}
	return json.NewDecoder(resp2.Body).Decode(dest)
}

// buildDigestAuthHeader constructs a Digest Authorization header value.
// Implements RFC 7616 MD5 variant (Atlas uses MD5).
func buildDigestAuthHeader(username, password, method, uri, wwwAuthenticate string) (string, error) {
	params := parseDigestChallenge(wwwAuthenticate)
	realm, ok1 := params["realm"]
	nonce, ok2 := params["nonce"]
	if !ok1 || !ok2 {
		return "", fmt.Errorf("missing realm or nonce in WWW-Authenticate")
	}

	qop := params["qop"] // may be empty or "auth"
	opaque := params["opaque"]

	// Strip scheme+host from uri for the digest URI field.
	digestURI := uri
	if idx := strings.Index(uri, "://"); idx >= 0 {
		rest := uri[idx+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			digestURI = rest[slash:]
		}
	}

	// HA1 = MD5(username:realm:password)
	ha1 := md5hex(username + ":" + realm + ":" + password) // #nosec G401
	// HA2 = MD5(method:uri)
	ha2 := md5hex(method + ":" + digestURI) // #nosec G401

	var response, nc, cnonce string
	if qop == "auth" {
		nc = "00000001"
		cnonce = hex.EncodeToString([]byte("titusscorer")) // deterministic; fine for one-shot use
		response = md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2) // #nosec G401
	} else {
		response = md5hex(ha1 + ":" + nonce + ":" + ha2) // #nosec G401
	}

	var sb strings.Builder
	sb.WriteString(`Digest username="`)
	sb.WriteString(username)
	sb.WriteString(`", realm="`)
	sb.WriteString(realm)
	sb.WriteString(`", nonce="`)
	sb.WriteString(nonce)
	sb.WriteString(`", uri="`)
	sb.WriteString(digestURI)
	sb.WriteString(`", response="`)
	sb.WriteString(response)
	sb.WriteString(`"`)
	if qop == "auth" {
		sb.WriteString(`, qop=auth, nc=`)
		sb.WriteString(nc)
		sb.WriteString(`, cnonce="`)
		sb.WriteString(cnonce)
		sb.WriteString(`"`)
	}
	if opaque != "" {
		sb.WriteString(`, opaque="`)
		sb.WriteString(opaque)
		sb.WriteString(`"`)
	}
	return sb.String(), nil
}

// md5hex returns the lowercase hex MD5 of s.
func md5hex(s string) string {
	h := md5.Sum([]byte(s)) // #nosec G401
	return hex.EncodeToString(h[:])
}

// parseDigestChallenge parses key=value or key="value" pairs from a
// WWW-Authenticate: Digest ... header value.
func parseDigestChallenge(header string) map[string]string {
	result := make(map[string]string)
	// Strip "Digest " prefix (case-insensitive).
	body := header
	if len(header) > 7 && strings.EqualFold(header[:7], "Digest ") {
		body = header[7:]
	}
	for _, part := range strings.Split(body, ",") {
		part = strings.TrimSpace(part)
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(part[:eq])
		v := strings.TrimSpace(part[eq+1:])
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		result[k] = v
	}
	return result
}

// JSON response structs used by ListOrgs / ListProjects.

type atlasOrgsResponse struct {
	Results []struct {
		ID    string `json:"id"`
		Roles []struct {
			RoleName string `json:"roleName"`
		} `json:"roles"`
	} `json:"results"`
}

type atlasGroupsResponse struct {
	Results []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Roles []struct {
			RoleName string `json:"roleName"`
		} `json:"roles"`
	} `json:"results"`
}

func (c *atlasHTTPClient) ListOrgs(ctx context.Context) ([]AtlasOrgMembership, error) {
	var raw atlasOrgsResponse
	if err := c.get(ctx, "/api/atlas/v2/orgs", &raw); err != nil {
		return nil, err
	}
	out := make([]AtlasOrgMembership, 0, len(raw.Results))
	for _, r := range raw.Results {
		roles := make([]string, 0, len(r.Roles))
		for _, ro := range r.Roles {
			roles = append(roles, ro.RoleName)
		}
		out = append(out, AtlasOrgMembership{OrgID: r.ID, Roles: roles})
	}
	return out, nil
}

func (c *atlasHTTPClient) ListProjects(ctx context.Context) ([]AtlasProjectMembership, error) {
	var raw atlasGroupsResponse
	if err := c.get(ctx, "/api/atlas/v2/groups", &raw); err != nil {
		return nil, err
	}
	out := make([]AtlasProjectMembership, 0, len(raw.Results))
	for _, r := range raw.Results {
		roles := make([]string, 0, len(r.Roles))
		for _, ro := range r.Roles {
			roles = append(roles, ro.RoleName)
		}
		out = append(out, AtlasProjectMembership{GroupID: r.ID, Name: r.Name, Roles: roles})
	}
	return out, nil
}
