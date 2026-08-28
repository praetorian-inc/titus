package scoring

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestExtractPlaidClientID_JSONStyle(t *testing.T) {
	m := &types.Match{
		RuleID:      "kingfisher.plaid.2",
		NamedGroups: map[string][]byte{"token": []byte(fakePlaidSecret)},
		Snippet: types.Snippet{
			Before: []byte(`"client_id": "` + fakePlaidClientID + `"` + "\n"),
		},
	}
	id, ok := extractPlaidClientID(m)
	assert.True(t, ok)
	assert.Equal(t, fakePlaidClientID, id)
}

func TestExtractPlaidClientID_InMatching(t *testing.T) {
	m := &types.Match{
		RuleID:      "kingfisher.plaid.2",
		NamedGroups: map[string][]byte{"token": []byte(fakePlaidSecret)},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte(`client_id=` + fakePlaidClientID + ` secret=` + fakePlaidSecret),
			After:    []byte(""),
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

// A transport failure must not read as "revoked" -- but it must not be silent
// either. The condition returns the error so the engine warns and trackError
// counts it in the scan stats; previously every error was swallowed as
// (false, nil), so an unreachable Plaid degraded every finding to its base
// score with no signal that scoring had not actually run.
func TestPlaidRevoked_TransportError(t *testing.T) {
	c := &plaidRevokedCondition{
		client: &plaidFailingClient{},
	}
	fired, err := c.Evaluate(context.Background(), plaidSecretMatch("kingfisher.plaid.2"))
	require.Error(t, err, "an unreachable environment must be reported, not swallowed")
	assert.ErrorIs(t, err, ErrModifierNetwork, "must land in the network-error stats bucket")
	assert.False(t, fired, "transport errors must not be treated as revoked")
}

func TestPlaidRevoked_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`internal error`))
	}))
	defer server.Close()

	c := &plaidRevokedCondition{
		client: &plaidRedirectingClient{target: server.URL},
	}
	fired, err := c.Evaluate(context.Background(), plaidSecretMatch("kingfisher.plaid.2"))
	require.Error(t, err, "a 5xx must be reported, not swallowed")
	assert.ErrorIs(t, err, ErrModifierServerError, "must land in the server-error stats bucket")
	assert.False(t, fired, "5xx errors must not be treated as revoked")
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

func TestPlaidSandboxContext_InMatching(t *testing.T) {
	m := &types.Match{
		RuleID:      "kingfisher.plaid.2",
		NamedGroups: map[string][]byte{"token": []byte(fakePlaidSecret)},
		Snippet: types.Snippet{
			Matching: []byte("PLAID_SANDBOX_SECRET=" + fakePlaidSecret),
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

func TestPlaidGoScorer_ModifierCount(t *testing.T) {
	s := PlaidGoScorer()
	assert.Equal(t, 5, len(s.Modifiers))
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
	assert.Equal(t, 5, byName["sandbox-context"].Value)
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

// plaidFailingClient always returns a transport error.
type plaidFailingClient struct{}

func (c *plaidFailingClient) Do(_ *http.Request) (*http.Response, error) {
	return nil, http.ErrServerClosed
}

// countingPlaidClient records every request the scorer issues.
type countingPlaidClient struct {
	mu       sync.Mutex
	requests []string
	respond  func(url string) (int, string)
}

func (c *countingPlaidClient) Do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.requests = append(c.requests, req.URL.String())
	c.mu.Unlock()
	code, body := c.respond(req.URL.String())
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}

func (c *countingPlaidClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

// plaidScorerWithClient injects a client into every dynamic modifier while
// leaving the shared probe cache from PlaidGoScorer() in place.
func plaidScorerWithClient(c plaidHTTPClient) *Scorer {
	s := PlaidGoScorer()
	for i := range s.Modifiers {
		switch cond := s.Modifiers[i].Condition.(type) {
		case *plaidEnvCheckCondition:
			cond.client = c
		case *plaidRevokedCondition:
			cond.client = c
		}
	}
	return s
}

// Scoring one finding must probe each environment at most ONCE. Before the
// shared cache, revoked-key re-probed all three environments after the
// per-environment modifiers had already done so -- up to six live
// authentication attempts per finding, with production hit twice. Each is a
// real auth attempt in the customer's Plaid audit log.
func TestPlaidScorer_ProbesEachEnvironmentOnce(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid string // environment host that accepts, "" for none
		want  int
	}{
		{"production key", "production.plaid.com", 95},
		{"development key", "development.plaid.com", 60},
		{"sandbox key", "sandbox.plaid.com", 5},
		{"revoked key", "", 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &countingPlaidClient{respond: func(url string) (int, string) {
				if tc.valid != "" && strings.Contains(url, tc.valid) {
					return 200, `{"institutions":[{"institution_id":"ins_1"}]}`
				}
				return 400, `{"error_code":"INVALID_API_KEYS"}`
			}}
			engine := NewEngine([]*Scorer{plaidScorerWithClient(client)}, EngineConfig{
				ScopeEnabled: true,
				Timeout:      5 * time.Second,
				WarnF:        func(string, ...any) {},
			})
			rule := &types.Rule{ID: "kingfisher.plaid.2", BaseScore: 70}
			score := engine.Score(context.Background(),
				&types.Finding{ID: "f", RuleID: "kingfisher.plaid.2"},
				[]*types.Match{plaidSecretMatch("kingfisher.plaid.2")}, rule)

			assert.Equal(t, tc.want, score.Final)
			assert.LessOrEqual(t, client.calls(), len(plaidEnvironments),
				"each environment must be probed at most once per finding")

			seen := map[string]int{}
			client.mu.Lock()
			for _, u := range client.requests {
				seen[u]++
			}
			client.mu.Unlock()
			for u, n := range seen {
				assert.Equalf(t, 1, n, "%s was probed %d times; it must be cached", u, n)
			}
		})
	}
}

// A finding with no co-located client_id cannot be verified dynamically and
// must make no network calls at all.
func TestPlaidScorer_NoClientID_MakesNoRequests(t *testing.T) {
	client := &countingPlaidClient{respond: func(string) (int, string) {
		return 200, `{"institutions":[]}`
	}}
	engine := NewEngine([]*Scorer{plaidScorerWithClient(client)}, EngineConfig{
		ScopeEnabled: true,
		Timeout:      5 * time.Second,
		WarnF:        func(string, ...any) {},
	})
	m := &types.Match{
		RuleID:      "kingfisher.plaid.2",
		NamedGroups: map[string][]byte{"token": []byte("abcdefghij0123456789klmnopqrst")},
	}
	rule := &types.Rule{ID: "kingfisher.plaid.2", BaseScore: 70}
	score := engine.Score(context.Background(),
		&types.Finding{ID: "f", RuleID: "kingfisher.plaid.2"}, []*types.Match{m}, rule)

	assert.Equal(t, 70, score.Final, "no verification possible: base score stands")
	assert.Zero(t, client.calls(), "no client_id means nothing to verify")
}

// An unreachable Plaid must leave the score alone AND be visible: one warning
// and one tracked network error per environment, not silence and not one
// warning per modifier.
func TestPlaidScorer_UnreachableIsVisibleAndBounded(t *testing.T) {
	var warnings []string
	engine := NewEngine([]*Scorer{plaidScorerWithClient(&plaidFailingClient{})}, EngineConfig{
		ScopeEnabled: true,
		Timeout:      5 * time.Second,
		WarnF:        func(f string, a ...any) { warnings = append(warnings, fmt.Sprintf(f, a...)) },
	})
	rule := &types.Rule{ID: "kingfisher.plaid.2", BaseScore: 70}
	score := engine.Score(context.Background(),
		&types.Finding{ID: "f", RuleID: "kingfisher.plaid.2"},
		[]*types.Match{plaidSecretMatch("kingfisher.plaid.2")}, rule)

	assert.Equal(t, 70, score.Final, "an outage must not move the score")
	assert.NotEmpty(t, warnings, "an outage must not be silent")
	assert.LessOrEqual(t, len(warnings), len(plaidEnvironments),
		"one outage must not warn once per modifier")
	assert.Equal(t, len(plaidEnvironments), engine.Stats().NetworkErrors,
		"each unreachable environment must be counted exactly once")
}
