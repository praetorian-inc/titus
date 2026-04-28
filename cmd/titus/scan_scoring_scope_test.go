package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/scoring"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScopeEnabled_DynamicModifier_FiresWhenHeaderPresent verifies the full
// path: HTTP condition evaluates a mock API response and the set_score fires,
// changing the finding's Final score.
func TestScopeEnabled_DynamicModifier_FiresWhenHeaderPresent(t *testing.T) {
	// Mock server returning admin:org in the x-oauth-scopes header.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-oauth-scopes", "repo, admin:org, read:user")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login":"octocat"}`))
	}))
	defer srv.Close()

	// Build a minimal scorer YAML pointing at the mock server.
	const ruleID = "np.github.1"
	scorerYAML := []byte(`
scorers:
  - name: test-github-scope
    rule_ids: [` + ruleID + `]
    modifiers:
      - name: admin-org-scope
        priority: 90
        http:
          method: GET
          url: ` + srv.URL + `
          auth:
            type: bearer
            secret_group: token
        fires_when:
          header_contains:
            name: x-oauth-scopes
            value: "admin:org"
        set_score: 90
`)

	loader := scoring.NewLoader()
	scorers, err := loader.LoadScorers(scorerYAML)
	require.NoError(t, err)

	engine := scoring.NewEngine(scorers, scoring.EngineConfig{
		ScopeEnabled: true,
		Timeout:      5 * time.Second,
	})

	rule := &types.Rule{ID: ruleID, BaseScore: 70}
	finding := &types.Finding{ID: "test-finding", RuleID: ruleID}
	match := &types.Match{
		RuleID:      ruleID,
		NamedGroups: map[string][]byte{"token": []byte("ghp_test_secret")},
	}

	score := engine.Score(context.Background(), finding, []*types.Match{match}, rule)
	require.NotNil(t, score)

	assert.Equal(t, 90, score.Final, "admin:org scope should set_score to 90")
	assert.Equal(t, "critical", score.SuggestedSeverity)
	require.Len(t, score.Applied, 1)
	assert.Equal(t, "admin-org-scope", score.Applied[0].Name)
	assert.Equal(t, "set_score", score.Applied[0].Kind)
}

// TestScopeDisabled_DynamicModifiersSkipped verifies that when ScopeEnabled=false,
// HTTP modifiers do not fire even if the condition would have matched.
func TestScopeDisabled_DynamicModifiersSkipped(t *testing.T) {
	// This server must never be called when scope is disabled.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("x-oauth-scopes", "admin:org")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	const ruleID = "np.github.1"
	scorerYAML := []byte(`
scorers:
  - name: test-github-scope-disabled
    rule_ids: [` + ruleID + `]
    modifiers:
      - name: admin-org-scope
        priority: 90
        http:
          method: GET
          url: ` + srv.URL + `
          auth:
            type: bearer
            secret_group: token
        fires_when:
          header_contains:
            name: x-oauth-scopes
            value: "admin:org"
        set_score: 90
`)

	loader := scoring.NewLoader()
	scorers, err := loader.LoadScorers(scorerYAML)
	require.NoError(t, err)

	// ScopeEnabled=false — HTTP modifiers must be skipped.
	engine := scoring.NewEngine(scorers, scoring.EngineConfig{
		ScopeEnabled: false,
	})

	rule := &types.Rule{ID: ruleID, BaseScore: 70}
	finding := &types.Finding{ID: "test-finding-disabled", RuleID: ruleID}
	match := &types.Match{
		RuleID:      ruleID,
		NamedGroups: map[string][]byte{"token": []byte("ghp_test_secret")},
	}

	score := engine.Score(context.Background(), finding, []*types.Match{match}, rule)
	require.NotNil(t, score)

	assert.Equal(t, rule.BaseScore, score.Final, "scope disabled: no dynamic modifier should fire")
	assert.Equal(t, 0, int(calls.Load()), "scope disabled: no HTTP calls should be made")
	assert.Empty(t, score.Applied, "scope disabled: Applied must be empty")
}
