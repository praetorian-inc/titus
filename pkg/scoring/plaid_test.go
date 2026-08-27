package scoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fakePlaidClientID = "sd479fjropblyr5b4m2dutha"
	fakePlaidSecret   = "wuxd6sw7ma4lv10xremyhz7ulf9owc"
)

func plaidSecretMatch(ruleID string) *types.Match {
	return &types.Match{
		RuleID: ruleID,
		NamedGroups: map[string][]byte{
			"token": []byte(fakePlaidSecret),
		},
		Snippet: types.Snippet{
			Before: []byte(`PLAID_CLIENT_ID="` + fakePlaidClientID + `"` + "\n"),
			After:  []byte("\n"),
		},
	}
}

func plaidSecretMatchNoClientID(ruleID string) *types.Match {
	return &types.Match{
		RuleID: ruleID,
		NamedGroups: map[string][]byte{
			"token": []byte(fakePlaidSecret),
		},
		Snippet: types.Snippet{
			Before: []byte("some config\n"),
			After:  []byte("\n"),
		},
	}
}

// --- extractPlaidSecret ---

func TestExtractPlaidSecret_NamedGroup(t *testing.T) {
	m := plaidSecretMatch("kingfisher.plaid.2")
	s, ok := extractPlaidSecret(m)
	assert.True(t, ok)
	assert.Equal(t, fakePlaidSecret, s)
}

func TestExtractPlaidSecret_PositionalFallback(t *testing.T) {
	m := &types.Match{
		RuleID:      "kingfisher.plaid.2",
		Groups:      [][]byte{[]byte(fakePlaidSecret)},
		NamedGroups: map[string][]byte{},
	}
	s, ok := extractPlaidSecret(m)
	assert.True(t, ok)
	assert.Equal(t, fakePlaidSecret, s)
}

func TestExtractPlaidSecret_Nil(t *testing.T) {
	_, ok := extractPlaidSecret(nil)
	assert.False(t, ok)
}

func TestExtractPlaidSecret_Empty(t *testing.T) {
	m := &types.Match{
		RuleID:      "kingfisher.plaid.2",
		Groups:      [][]byte{},
		NamedGroups: map[string][]byte{},
	}
	_, ok := extractPlaidSecret(m)
	assert.False(t, ok)
}

// --- extractPlaidClientID ---

func TestExtractPlaidClientID_InBefore(t *testing.T) {
	m := plaidSecretMatch("kingfisher.plaid.2")
	id, ok := extractPlaidClientID(m)
	assert.True(t, ok)
	assert.Equal(t, fakePlaidClientID, id)
}

func TestExtractPlaidClientID_InAfter(t *testing.T) {
	m := &types.Match{
		RuleID:      "kingfisher.plaid.2",
		NamedGroups: map[string][]byte{"token": []byte(fakePlaidSecret)},
		Snippet: types.Snippet{
			Before: []byte("something\n"),
			After:  []byte(`plaid_client_id=` + fakePlaidClientID + "\n"),
		},
	}
	id, ok := extractPlaidClientID(m)
	assert.True(t, ok)
	assert.Equal(t, fakePlaidClientID, id)
}

func TestExtractPlaidClientID_CaseInsensitive(t *testing.T) {
	m := &types.Match{
		RuleID:      "kingfisher.plaid.2",
		NamedGroups: map[string][]byte{"token": []byte(fakePlaidSecret)},
		Snippet: types.Snippet{
			Before: []byte(`CLIENT_ID = "` + fakePlaidClientID + `"` + "\n"),
		},
	}
	id, ok := extractPlaidClientID(m)
	assert.True(t, ok)
	assert.Equal(t, fakePlaidClientID, id)
}

func TestExtractPlaidClientID_NotFound(t *testing.T) {
	m := plaidSecretMatchNoClientID("kingfisher.plaid.2")
	_, ok := extractPlaidClientID(m)
	assert.False(t, ok)
}

func TestExtractPlaidClientID_Nil(t *testing.T) {
	_, ok := extractPlaidClientID(nil)
	assert.False(t, ok)
}

// --- plaidEnvCheckCondition ---

func TestPlaidEnvCheck_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"institutions":[],"total":0}`))
	}))
	defer server.Close()

	c := &plaidEnvCheckCondition{
		envURL: server.URL,
		client: &plaidRedirectingClient{target: server.URL},
	}

	fired, err := c.Evaluate(context.Background(), plaidSecretMatch("kingfisher.plaid.2"))
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestPlaidEnvCheck_InvalidKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error_code":"INVALID_API_KEYS"}`))
	}))
	defer server.Close()

	c := &plaidEnvCheckCondition{
		envURL: server.URL,
		client: &plaidRedirectingClient{target: server.URL},
	}

	fired, err := c.Evaluate(context.Background(), plaidSecretMatch("kingfisher.plaid.2"))
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestPlaidEnvCheck_NoClientID(t *testing.T) {
	c := &plaidEnvCheckCondition{
		envURL: "https://production.plaid.com/institutions/get",
	}
	fired, err := c.Evaluate(context.Background(), plaidSecretMatchNoClientID("kingfisher.plaid.2"))
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestPlaidEnvCheck_NilMatch(t *testing.T) {
	c := &plaidEnvCheckCondition{
		envURL: "https://production.plaid.com/institutions/get",
	}
	fired, err := c.Evaluate(context.Background(), nil)
	assert.NoError(t, err)
	assert.False(t, fired)
}

// --- plaidRevokedCondition ---

func TestPlaidRevoked_AllReject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error_code":"INVALID_API_KEYS"}`))
	}))
	defer server.Close()

	c := &plaidRevokedCondition{
		client: &plaidRedirectingClient{target: server.URL},
	}

	fired, err := c.Evaluate(context.Background(), plaidSecretMatch("kingfisher.plaid.2"))
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestPlaidRevoked_OneAccepts(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"institutions":[],"total":0}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error_code":"INVALID_API_KEYS"}`))
	}))
	defer server.Close()

	c := &plaidRevokedCondition{
		client: &plaidRedirectingClient{target: server.URL},
	}

	fired, err := c.Evaluate(context.Background(), plaidSecretMatch("kingfisher.plaid.2"))
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestPlaidRevoked_NoClientID(t *testing.T) {
	c := &plaidRevokedCondition{}
	fired, err := c.Evaluate(context.Background(), plaidSecretMatchNoClientID("kingfisher.plaid.2"))
	assert.NoError(t, err)
	assert.False(t, fired)
}

// --- plaidSandboxContextCondition ---

func TestPlaidSandboxContext_InBefore(t *testing.T) {
	m := &types.Match{
		RuleID:      "kingfisher.plaid.2",
		NamedGroups: map[string][]byte{"token": []byte(fakePlaidSecret)},
		Snippet: types.Snippet{
			Before: []byte("PLAID_ENV=sandbox\n"),
		},
	}
	c := &plaidSandboxContextCondition{}
	fired, err := c.Evaluate(context.Background(), m)
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestPlaidSandboxContext_InAfter(t *testing.T) {
	m := &types.Match{
		RuleID:      "kingfisher.plaid.2",
		NamedGroups: map[string][]byte{"token": []byte(fakePlaidSecret)},
		Snippet: types.Snippet{
			After: []byte("environment: Sandbox\n"),
		},
	}
	c := &plaidSandboxContextCondition{}
	fired, err := c.Evaluate(context.Background(), m)
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestPlaidSandboxContext_NotPresent(t *testing.T) {
	m := plaidSecretMatch("kingfisher.plaid.2")
	c := &plaidSandboxContextCondition{}
	fired, err := c.Evaluate(context.Background(), m)
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestPlaidSandboxContext_Nil(t *testing.T) {
	c := &plaidSandboxContextCondition{}
	fired, err := c.Evaluate(context.Background(), nil)
	assert.NoError(t, err)
	assert.False(t, fired)
}

// --- PlaidGoScorer structure ---

func TestPlaidGoScorer_Structure(t *testing.T) {
	s := PlaidGoScorer()
	assert.Equal(t, "plaid-secret-environment", s.Name)
	assert.Contains(t, s.RuleIDs, "kingfisher.plaid.2")
	assert.Contains(t, s.RuleIDs, "kingfisher.plaid.3")
	assert.Equal(t, 5, len(s.Modifiers))

	names := make([]string, len(s.Modifiers))
	for i, mod := range s.Modifiers {
		names[i] = mod.Name
	}
	assert.Contains(t, names, "sandbox-context")
	assert.Contains(t, names, "production-verified")
	assert.Contains(t, names, "development-verified")
	assert.Contains(t, names, "sandbox-verified")
	assert.Contains(t, names, "revoked-key")
}

func TestPlaidGoScorer_RuleIDsExist(t *testing.T) {
	s := PlaidGoScorer()
	for _, id := range s.RuleIDs {
		assert.NotEmpty(t, id)
	}
}

func TestPlaidGoScorer_PriorityOrder(t *testing.T) {
	s := PlaidGoScorer()
	byName := map[string]Modifier{}
	for _, mod := range s.Modifiers {
		byName[mod.Name] = mod
	}

	assert.Greater(t, byName["sandbox-context"].Priority, byName["production-verified"].Priority,
		"static should evaluate before dynamic")
	assert.Greater(t, byName["production-verified"].Priority, byName["sandbox-verified"].Priority,
		"production check should evaluate before sandbox")
	assert.Greater(t, byName["sandbox-verified"].Priority, byName["revoked-key"].Priority,
		"env checks should evaluate before revoked")
}

func TestPlaidGoScorer_AllDynamic(t *testing.T) {
	s := PlaidGoScorer()
	for _, mod := range s.Modifiers {
		if mod.Name == "sandbox-context" {
			assert.False(t, mod.IsDynamic(), "sandbox-context should be static")
			continue
		}
		assert.True(t, mod.IsDynamic(), "modifier %s should be dynamic", mod.Name)
	}
}

func TestPlaidGoScorer_MissingToken(t *testing.T) {
	s := PlaidGoScorer()
	m := &types.Match{
		RuleID:      "kingfisher.plaid.2",
		Groups:      [][]byte{},
		NamedGroups: map[string][]byte{},
	}
	for _, mod := range s.Modifiers {
		fired, err := mod.Condition.Evaluate(context.Background(), m)
		assert.NoError(t, err, "modifier %s should not error", mod.Name)
		assert.False(t, fired, "modifier %s should not fire without token", mod.Name)
	}
}

func TestPlaidGoScorer_Scores(t *testing.T) {
	s := PlaidGoScorer()
	byName := map[string]Modifier{}
	for _, mod := range s.Modifiers {
		byName[mod.Name] = mod
	}

	require.Equal(t, ModifierKindSetScore, byName["production-verified"].Kind)
	assert.Equal(t, 95, byName["production-verified"].Value)

	require.Equal(t, ModifierKindSetScore, byName["sandbox-verified"].Kind)
	assert.Equal(t, 5, byName["sandbox-verified"].Value)

	require.Equal(t, ModifierKindSetScore, byName["development-verified"].Kind)
	assert.Equal(t, 60, byName["development-verified"].Value)

	require.Equal(t, ModifierKindSetScore, byName["revoked-key"].Kind)
	assert.Equal(t, 5, byName["revoked-key"].Value)

	require.Equal(t, ModifierKindSetScore, byName["sandbox-context"].Kind)
	assert.Equal(t, 10, byName["sandbox-context"].Value)
}

// plaidRedirectingClient redirects all requests to a test server URL.
type plaidRedirectingClient struct {
	target string
}

func (c *plaidRedirectingClient) Do(req *http.Request) (*http.Response, error) {
	testURL := c.target + req.URL.Path
	if req.URL.RawQuery != "" {
		testURL += "?" + req.URL.RawQuery
	}
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, testURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header
	return http.DefaultClient.Do(newReq)
}
