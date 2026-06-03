package scoring

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/praetorian-inc/titus/pkg/types"
)

// supabaseHTTPClient is an interface for making HTTP requests (allows testing).
type supabaseHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// extractSupabaseToken extracts the management token from positional group 1.
// kingfisher.supabase.1 uses (sbp_...) without a named group.
func extractSupabaseToken(m *types.Match) (string, bool) {
	if m == nil {
		return "", false
	}
	// Try positional group first (the rule uses unnamed capture)
	if len(m.Groups) > 0 && len(m.Groups[0]) > 0 {
		return string(m.Groups[0]), true
	}
	// Fall back to named groups in case the rule is updated
	for _, name := range []string{"token", "1"} {
		if v, ok := m.NamedGroups[name]; ok && len(v) > 0 {
			return string(v), true
		}
	}
	return "", false
}

// supabaseTokenExpiredCondition fires when the token returns 401.
type supabaseTokenExpiredCondition struct {
	client supabaseHTTPClient
}

func (c *supabaseTokenExpiredCondition) markDynamic() {}

func (c *supabaseTokenExpiredCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractSupabaseToken(m)
	if !ok {
		return false, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.supabase.com/v1/organizations", nil)
	if err != nil {
		return false, nil
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return false, nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	return resp.StatusCode == http.StatusUnauthorized, nil
}

func (c *supabaseTokenExpiredCondition) httpClient() supabaseHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// supabaseActiveTokenCondition fires when the token is confirmed active (200).
type supabaseActiveTokenCondition struct {
	client supabaseHTTPClient
}

func (c *supabaseActiveTokenCondition) markDynamic() {}

func (c *supabaseActiveTokenCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractSupabaseToken(m)
	if !ok {
		return false, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.supabase.com/v1/organizations", nil)
	if err != nil {
		return false, nil
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return false, nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	return resp.StatusCode == http.StatusOK, nil
}

func (c *supabaseActiveTokenCondition) httpClient() supabaseHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// supabaseMultiProjectCondition fires when the token has access to >= threshold projects.
type supabaseMultiProjectCondition struct {
	threshold int
	client    supabaseHTTPClient
}

func (c *supabaseMultiProjectCondition) markDynamic() {}

func (c *supabaseMultiProjectCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractSupabaseToken(m)
	if !ok {
		return false, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.supabase.com/v1/projects", nil)
	if err != nil {
		return false, nil
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return false, nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil
	}

	var projects []json.RawMessage
	if err := json.Unmarshal(body, &projects); err != nil {
		return false, nil
	}

	return len(projects) >= c.threshold, nil
}

func (c *supabaseMultiProjectCondition) httpClient() supabaseHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// SupabaseGoScorer returns the Supabase scoring configuration for kingfisher.supabase.1.
func SupabaseGoScorer() *Scorer {
	return &Scorer{
		Name:    "supabase-management-scope",
		RuleIDs: []string{"kingfisher.supabase.1"},
		Modifiers: []Modifier{
			// Priority 100: Token expired → set_score 5
			{
				Name:      "token-expired",
				Priority:  100,
				Kind:      ModifierKindSetScore,
				Value:     5,
				Condition: &supabaseTokenExpiredCondition{},
			},
			// Priority 90: Token confirmed active → delta +5
			{
				Name:      "active-token",
				Priority:  90,
				Kind:      ModifierKindDelta,
				Value:     5,
				Condition: &supabaseActiveTokenCondition{},
			},
			// Priority 70: 5+ projects → delta +5 (broad infrastructure access)
			{
				Name:      "multi-project",
				Priority:  70,
				Kind:      ModifierKindDelta,
				Value:     5,
				Condition: &supabaseMultiProjectCondition{threshold: 5},
			},
		},
	}
}
