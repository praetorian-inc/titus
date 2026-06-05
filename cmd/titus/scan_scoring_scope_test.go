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

// stripeTestScorerYAML builds an inline scorer YAML for np.stripe.1 with all
// three modifiers (static restricted-key-prefix + two dynamic charges_enabled
// modifiers). The HTTP modifier URLs point at the provided mock server URL so
// tests make real HTTP calls against an in-process httptest.Server.
func stripeTestScorerYAML(mockURL string) []byte {
	return []byte(`
scorers:
  - name: stripe-key-scope
    rule_ids:
      - np.stripe.1
    modifiers:
      - name: restricted-key-prefix
        priority: 70
        match_group:
          name: key
          matches: '^rk_live_'
        delta: -25
      - name: charges-enabled-live
        priority: 90
        http:
          method: GET
          url: ` + mockURL + `/v1/account
          auth:
            type: bearer
            secret_group: "key"
        fires_when:
          json_path_equals:
            path: ".charges_enabled"
            value: true
        set_score: 95
      - name: charges-disabled
        priority: 80
        http:
          method: GET
          url: ` + mockURL + `/v1/account
          auth:
            type: bearer
            secret_group: "key"
        fires_when:
          json_path_equals:
            path: ".charges_enabled"
            value: false
        set_score: 30
`)
}

// TestStripeScorer_ChargesEnabledLive_SetScore95 verifies that when the Stripe
// API reports charges_enabled=true, the charges-enabled-live modifier fires and
// sets the final score to 95 for an sk_live_ key.
func TestStripeScorer_ChargesEnabledLive_SetScore95(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer sk_live_dhhfUUyfrAace5dBAZ10JrAD" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"charges_enabled": true, "country": "US"}`))
	}))
	defer srv.Close()

	const ruleID = "np.stripe.1"
	loader := scoring.NewLoader()
	scorers, err := loader.LoadScorers(stripeTestScorerYAML(srv.URL))
	require.NoError(t, err)

	engine := scoring.NewEngine(scorers, scoring.EngineConfig{
		ScopeEnabled: true,
		Timeout:      5 * time.Second,
	})

	rule := &types.Rule{ID: ruleID, BaseScore: 90}
	finding := &types.Finding{ID: "stripe-finding-1", RuleID: ruleID}
	match := &types.Match{
		RuleID:      ruleID,
		NamedGroups: map[string][]byte{"key": []byte("sk_live_dhhfUUyfrAace5dBAZ10JrAD")},
	}

	score := engine.Score(context.Background(), finding, []*types.Match{match}, rule)
	require.NotNil(t, score)

	assert.Equal(t, 95, score.Final, "charges_enabled=true should set_score to 95")

	// charges-enabled-live must appear in Applied; charges-disabled must not.
	var appliedNames []string
	for _, a := range score.Applied {
		appliedNames = append(appliedNames, a.Name)
	}
	assert.Contains(t, appliedNames, "charges-enabled-live")
	assert.NotContains(t, appliedNames, "charges-disabled")
}

// TestStripeScorer_ChargesDisabled_SetScore30 verifies that when the Stripe API
// reports charges_enabled=false, the charges-disabled modifier fires and sets
// the final score to 30 for an sk_live_ key.
func TestStripeScorer_ChargesDisabled_SetScore30(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer sk_live_dhhfUUyfrAace5dBAZ10JrAD" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"charges_enabled": false, "country": "US"}`))
	}))
	defer srv.Close()

	const ruleID = "np.stripe.1"
	loader := scoring.NewLoader()
	scorers, err := loader.LoadScorers(stripeTestScorerYAML(srv.URL))
	require.NoError(t, err)

	engine := scoring.NewEngine(scorers, scoring.EngineConfig{
		ScopeEnabled: true,
		Timeout:      5 * time.Second,
	})

	rule := &types.Rule{ID: ruleID, BaseScore: 90}
	finding := &types.Finding{ID: "stripe-finding-2", RuleID: ruleID}
	match := &types.Match{
		RuleID:      ruleID,
		NamedGroups: map[string][]byte{"key": []byte("sk_live_dhhfUUyfrAace5dBAZ10JrAD")},
	}

	score := engine.Score(context.Background(), finding, []*types.Match{match}, rule)
	require.NotNil(t, score)

	assert.Equal(t, 30, score.Final, "charges_enabled=false should set_score to 30")

	var appliedNames []string
	for _, a := range score.Applied {
		appliedNames = append(appliedNames, a.Name)
	}
	assert.Contains(t, appliedNames, "charges-disabled")
}

// TestStripeScorer_RestrictedKey_ChargesEnabled_Score70 verifies scoring for an
// rk_live_ key when charges_enabled=true.
//
// Modifier execution order (priority DESC):
//   1. priority  90: charges-enabled-live   set_score 95 → 95
//   2. priority  80: charges-disabled       does NOT fire (charges_enabled is true)
//   3. priority  70: restricted-key-prefix  delta -25 → 95 - 25 = 70
//
// The restricted key penalty applies on top of the set_score. Final = 70.
func TestStripeScorer_RestrictedKey_ChargesEnabled_Score70(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer rk_live_dhhfuuyfrAace5dbaz10jrad" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"charges_enabled": true}`))
	}))
	defer srv.Close()

	const ruleID = "np.stripe.1"
	loader := scoring.NewLoader()
	scorers, err := loader.LoadScorers(stripeTestScorerYAML(srv.URL))
	require.NoError(t, err)

	engine := scoring.NewEngine(scorers, scoring.EngineConfig{
		ScopeEnabled: true,
		Timeout:      5 * time.Second,
	})

	rule := &types.Rule{ID: ruleID, BaseScore: 90}
	finding := &types.Finding{ID: "stripe-finding-3", RuleID: ruleID}
	match := &types.Match{
		RuleID:      ruleID,
		NamedGroups: map[string][]byte{"key": []byte("rk_live_dhhfuuyfrAace5dbaz10jrad")},
	}

	score := engine.Score(context.Background(), finding, []*types.Match{match}, rule)
	require.NotNil(t, score)

	assert.Equal(t, 70, score.Final, "rk_live_ + charges_enabled=true: set_score 95 then delta -25 = 70")

	require.Len(t, score.Applied, 2)
	assert.Equal(t, "charges-enabled-live", score.Applied[0].Name)
	assert.Equal(t, "restricted-key-prefix", score.Applied[1].Name)
	assert.NotContains(t, func() []string {
		var names []string
		for _, a := range score.Applied {
			names = append(names, a.Name)
		}
		return names
	}(), "charges-disabled")
}

// TestStripeScorer_RestrictedKey_ChargesDisabled_Score5 verifies scoring for an
// rk_live_ key when charges_enabled=false.
//
// Modifier execution order (priority DESC):
//   1. priority  90: charges-enabled-live   does NOT fire
//   2. priority  80: charges-disabled       set_score 30 → 30
//   3. priority  70: restricted-key-prefix  delta -25 → 30 - 25 = 5
//
// Final = 5.
func TestStripeScorer_RestrictedKey_ChargesDisabled_Score5(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer rk_live_dhhfuuyfrAace5dbaz10jrad" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"charges_enabled": false}`))
	}))
	defer srv.Close()

	const ruleID = "np.stripe.1"
	loader := scoring.NewLoader()
	scorers, err := loader.LoadScorers(stripeTestScorerYAML(srv.URL))
	require.NoError(t, err)

	engine := scoring.NewEngine(scorers, scoring.EngineConfig{
		ScopeEnabled: true,
		Timeout:      5 * time.Second,
	})

	rule := &types.Rule{ID: ruleID, BaseScore: 90}
	finding := &types.Finding{ID: "stripe-finding-4", RuleID: ruleID}
	match := &types.Match{
		RuleID:      ruleID,
		NamedGroups: map[string][]byte{"key": []byte("rk_live_dhhfuuyfrAace5dbaz10jrad")},
	}

	score := engine.Score(context.Background(), finding, []*types.Match{match}, rule)
	require.NotNil(t, score)

	assert.Equal(t, 5, score.Final, "rk_live_ + charges_enabled=false: set_score 30 then delta -25 = 5")

	require.Len(t, score.Applied, 2)
	assert.Equal(t, "charges-disabled", score.Applied[0].Name)
	assert.Equal(t, "restricted-key-prefix", score.Applied[1].Name)
	assert.NotContains(t, func() []string {
		var names []string
		for _, a := range score.Applied {
			names = append(names, a.Name)
		}
		return names
	}(), "charges-enabled-live")
}

// TestStripeScorer_ScopeDisabled_DynamicSkipped verifies that with
// ScopeEnabled=false, HTTP modifiers are not executed. Only the static
// restricted-key-prefix modifier can fire (and only for rk_live_ keys).
// An sk_live_ key with scope disabled must return the base score unchanged.
func TestStripeScorer_ScopeDisabled_DynamicSkipped(t *testing.T) {
	// The mock server must not be called when scope is disabled.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"charges_enabled": true}`))
	}))
	defer srv.Close()

	const ruleID = "np.stripe.1"
	loader := scoring.NewLoader()
	scorers, err := loader.LoadScorers(stripeTestScorerYAML(srv.URL))
	require.NoError(t, err)

	engine := scoring.NewEngine(scorers, scoring.EngineConfig{
		ScopeEnabled: false,
	})

	rule := &types.Rule{ID: ruleID, BaseScore: 90}
	finding := &types.Finding{ID: "stripe-finding-5", RuleID: ruleID}
	match := &types.Match{
		RuleID:      ruleID,
		NamedGroups: map[string][]byte{"key": []byte("sk_live_dhhfUUyfrAace5dBAZ10JrAD")},
	}

	score := engine.Score(context.Background(), finding, []*types.Match{match}, rule)
	require.NotNil(t, score)

	assert.Equal(t, 90, score.Final, "scope disabled: sk_live_ should return base score unchanged")
	assert.Equal(t, 0, int(calls.Load()), "scope disabled: no HTTP calls should be made")
	assert.Empty(t, score.Applied, "scope disabled: no modifiers should fire for sk_live_")
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
