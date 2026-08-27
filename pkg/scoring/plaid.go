package scoring

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

type plaidHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// extractPlaidSecret extracts the Plaid secret from the match.
// Tries named group "token" first, falls back to positional group 0.
func extractPlaidSecret(m *types.Match) (string, bool) {
	if m == nil {
		return "", false
	}
	if v, ok := m.NamedGroups["token"]; ok && len(v) > 0 {
		return string(v), true
	}
	if len(m.Groups) > 0 && len(m.Groups[0]) > 0 {
		return string(m.Groups[0]), true
	}
	return "", false
}

var plaidClientIDRe = regexp.MustCompile(`(?i)(?:plaid[_-]?)?client[_-]?id\s*[:=]\s*["']?([a-z0-9]{24})\b`)

// extractPlaidClientID scans surrounding context for a co-located Plaid client ID.
func extractPlaidClientID(m *types.Match) (string, bool) {
	if m == nil {
		return "", false
	}
	for _, ctx := range [][]byte{m.Snippet.Before, m.Snippet.After} {
		if sub := plaidClientIDRe.FindSubmatch(ctx); len(sub) > 1 {
			return string(sub[1]), true
		}
	}
	return "", false
}

type plaidInstitutionsReq struct {
	ClientID     string   `json:"client_id"`
	Secret       string   `json:"secret"`
	Count        int      `json:"count"`
	Offset       int      `json:"offset"`
	CountryCodes []string `json:"country_codes"`
}

// plaidEnvCheckCondition fires when the Plaid secret + client_id pair is valid
// for a specific environment (production, development, or sandbox).
type plaidEnvCheckCondition struct {
	envURL string // e.g. "https://production.plaid.com/institutions/get"
	client plaidHTTPClient
}

func (c *plaidEnvCheckCondition) markDynamic() {}

func (c *plaidEnvCheckCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	secret, ok := extractPlaidSecret(m)
	if !ok {
		return false, nil
	}
	clientID, ok := extractPlaidClientID(m)
	if !ok {
		return false, nil
	}

	body, err := json.Marshal(plaidInstitutionsReq{
		ClientID:     clientID,
		Secret:       secret,
		Count:        1,
		Offset:       0,
		CountryCodes: []string{"US"},
	})
	if err != nil {
		return false, nil
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.envURL, bytes.NewReader(body))
	if err != nil {
		return false, nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return false, nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil
	}
	return !bytes.Contains(respBody, []byte("INVALID_API_KEYS")), nil
}

func (c *plaidEnvCheckCondition) httpClient() plaidHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// plaidRevokedCondition fires when a client_id is available in the surrounding
// context but the secret is rejected by all three Plaid environments.
type plaidRevokedCondition struct {
	client plaidHTTPClient
}

func (c *plaidRevokedCondition) markDynamic() {}

func (c *plaidRevokedCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	secret, ok := extractPlaidSecret(m)
	if !ok {
		return false, nil
	}
	clientID, ok := extractPlaidClientID(m)
	if !ok {
		return false, nil
	}

	body, err := json.Marshal(plaidInstitutionsReq{
		ClientID:     clientID,
		Secret:       secret,
		Count:        1,
		Offset:       0,
		CountryCodes: []string{"US"},
	})
	if err != nil {
		return false, nil
	}

	for _, env := range []string{
		"https://production.plaid.com/institutions/get",
		"https://development.plaid.com/institutions/get",
		"https://sandbox.plaid.com/institutions/get",
	} {
		req, err := http.NewRequestWithContext(ctx, "POST", env, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient().Do(req)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK && !bytes.Contains(respBody, []byte("INVALID_API_KEYS")) {
			return false, nil
		}
	}
	return true, nil
}

func (c *plaidRevokedCondition) httpClient() plaidHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// plaidSandboxContextCondition fires when the surrounding context contains
// "sandbox" (case-insensitive), suggesting the secret belongs to a sandbox
// environment even when no client_id is available for dynamic verification.
type plaidSandboxContextCondition struct{}

func (c *plaidSandboxContextCondition) Evaluate(_ context.Context, m *types.Match) (bool, error) {
	if m == nil {
		return false, nil
	}
	low := func(b []byte) string { return strings.ToLower(string(b)) }
	return strings.Contains(low(m.Snippet.Before), "sandbox") ||
		strings.Contains(low(m.Snippet.After), "sandbox"), nil
}

// PlaidGoScorer returns the environment-aware Plaid secret scorer.
//
// Targets kingfisher.plaid.2 (Production Secret, base 90) and
// kingfisher.plaid.3 (Sandbox Secret, base 40). Access tokens (plaid.4/5)
// already carry their environment in the prefix and are not scored here.
//
// Dynamic modifiers (require a co-located client_id in surrounding context)
// probe POST /institutions/get against each Plaid environment.
// Static modifiers fall back to keyword detection when no client_id is found.
//
// Product-aware scoring (auth, identity, assets) is deferred — it requires an
// access_token which is not reliably co-located with the secret.
func PlaidGoScorer() *Scorer {
	return &Scorer{
		Name:    "plaid-secret-environment",
		RuleIDs: []string{"kingfisher.plaid.2", "kingfisher.plaid.3"},
		Modifiers: []Modifier{
			// --- Static fallbacks (evaluated first, overridden by dynamic) ---

			// Context contains "sandbox" — likely a sandbox key.
			{
				Name:      "sandbox-context",
				Priority:  90,
				Kind:      ModifierKindSetScore,
				Value:     10,
				Condition: &plaidSandboxContextCondition{},
			},

			// --- Dynamic (evaluated later, override static) ---

			// Confirmed production → highest severity.
			{
				Name:     "production-verified",
				Priority: 30,
				Kind:     ModifierKindSetScore,
				Value:    95,
				Condition: &plaidEnvCheckCondition{
					envURL: "https://production.plaid.com/institutions/get",
				},
			},
			// Confirmed development → moderate severity (real data, limited scale).
			{
				Name:     "development-verified",
				Priority: 25,
				Kind:     ModifierKindSetScore,
				Value:    60,
				Condition: &plaidEnvCheckCondition{
					envURL: "https://development.plaid.com/institutions/get",
				},
			},
			// Confirmed sandbox → minimal severity (entirely fake data).
			{
				Name:     "sandbox-verified",
				Priority: 20,
				Kind:     ModifierKindSetScore,
				Value:    5,
				Condition: &plaidEnvCheckCondition{
					envURL: "https://sandbox.plaid.com/institutions/get",
				},
			},
			// All environments reject → revoked / dead key.
			{
				Name:      "revoked-key",
				Priority:  10,
				Kind:      ModifierKindSetScore,
				Value:     5,
				Condition: &plaidRevokedCondition{},
			},
		},
	}
}
