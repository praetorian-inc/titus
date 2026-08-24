package main

import (
	"context"
	"encoding/json"
	"fmt"
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

// ----------------------------------------------------------------
// SendGrid scope scorer (LAB-3371)
//
// Mirrors pkg/scoring/scorers/sendgrid.yaml with the API host swapped for an
// in-process httptest.Server. Priorities matter here: higher priority is
// evaluated FIRST, and a later set_score replaces an earlier running score, so
// billing-access (30) deliberately lands after narrow-scope-set (40) and
// revoked-key (10) lands last of all.
// ----------------------------------------------------------------

const sendgridTestKey = "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"

func sendgridTestScorerYAML(mockURL string) []byte {
	return []byte(`
scorers:
  - name: sendgrid-key-scope
    rule_ids:
      - np.sendgrid.1
    modifiers:
      - name: full-access-key
        priority: 90
        http: &sg
          method: GET
          url: ` + mockURL + `/v3/scopes
          auth:
            type: bearer
            secret_group: "token"
        fires_when:
          json_array_length_gte:
            path: ".scopes"
            value: 100
        set_score: 85
      - name: domain-auth-access
        priority: 70
        http: *sg
        fires_when:
          response_body_contains: '"whitelabel.read"'
        delta: 20
      - name: subuser-management
        priority: 60
        http: *sg
        fires_when:
          response_body_contains: '"subusers.create"'
        delta: 15
      - name: contact-pii-access
        priority: 50
        http: *sg
        fires_when:
          response_body_contains: '"marketing.read"'
        delta: 15
      - name: narrow-scope-set
        priority: 40
        http: *sg
        fires_when:
          negative: true
          json_array_length_gte:
            path: ".scopes"
            value: 25
        delta: -20
      - name: billing-access
        priority: 30
        http: *sg
        fires_when:
          response_body_contains: '"billing.read"'
        set_score: 85
      - name: revoked-key
        priority: 10
        http: *sg
        fires_when:
          status_code: 401
        set_score: 5
`)
}

// sendgridScopesServer serves a /v3/scopes payload for the given scope list,
// rejecting any request that does not carry the expected bearer token.
func sendgridScopesServer(t *testing.T, scopes []string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+sendgridTestKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status != http.StatusOK {
			_, _ = w.Write([]byte(`{"errors":[{"message":"authorization required"}]}`))
			return
		}
		body, err := json.Marshal(map[string][]string{"scopes": scopes})
		require.NoError(t, err)
		_, _ = w.Write(body)
	}))
}

func scoreSendGridKey(t *testing.T, srv *httptest.Server) *types.Score {
	t.Helper()
	const ruleID = "np.sendgrid.1"
	scorers, err := scoring.NewLoader().LoadScorers(sendgridTestScorerYAML(srv.URL))
	require.NoError(t, err)

	engine := scoring.NewEngine(scorers, scoring.EngineConfig{
		ScopeEnabled: true,
		Timeout:      5 * time.Second,
	})
	rule := &types.Rule{ID: ruleID, BaseScore: 65}
	finding := &types.Finding{ID: "sendgrid-finding-1", RuleID: ruleID}
	match := &types.Match{
		RuleID:      ruleID,
		NamedGroups: map[string][]byte{"token": []byte(sendgridTestKey)},
	}
	score := engine.Score(context.Background(), finding, []*types.Match{match}, rule)
	require.NotNil(t, score)
	return score
}

func appliedNames(score *types.Score) []string {
	var names []string
	for _, a := range score.Applied {
		names = append(names, a.Name)
	}
	return names
}

// genericScopes returns n harmless scope names that match none of the
// sensitive-scope substrings the scorer looks for.
func genericScopes(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("templates.read.%d", i))
	}
	return out
}

// A Full Access key returns the whole scope catalogue; breadth alone puts it at 85.
func TestSendGridScorer_FullAccessKey_SetScore85(t *testing.T) {
	srv := sendgridScopesServer(t, append(genericScopes(120), "mail.send"), http.StatusOK)
	defer srv.Close()

	score := scoreSendGridKey(t, srv)
	assert.Equal(t, 85, score.Final)
	assert.Contains(t, appliedNames(score), "full-access-key")
	assert.NotContains(t, appliedNames(score), "narrow-scope-set")
}

// A restricted key with only mail.send is scored DOWN from the 65 base. This is
// the case the DSL could not express before the negative: flag.
func TestSendGridScorer_MailSendOnly_ScoredDown(t *testing.T) {
	srv := sendgridScopesServer(t, []string{"mail.send"}, http.StatusOK)
	defer srv.Close()

	score := scoreSendGridKey(t, srv)
	assert.Equal(t, 45, score.Final, "65 base - 20 for a narrow scope set")
	assert.Contains(t, appliedNames(score), "narrow-scope-set")
	assert.NotContains(t, appliedNames(score), "full-access-key")
}

// A billing key is narrow but high value. billing-access is evaluated after
// narrow-scope-set precisely so its set_score overrides that downgrade.
func TestSendGridScorer_BillingKey_OverridesNarrowDowngrade(t *testing.T) {
	srv := sendgridScopesServer(t, []string{"billing.read", "billing.update"}, http.StatusOK)
	defer srv.Close()

	score := scoreSendGridKey(t, srv)
	assert.Equal(t, 85, score.Final, "billing set_score must win over the narrow-scope delta")
	assert.Contains(t, appliedNames(score), "billing-access")
	assert.Contains(t, appliedNames(score), "narrow-scope-set")
}

// Sensitive-scope deltas compose with the narrow-scope downgrade.
func TestSendGridScorer_NarrowKeyWithDomainAuth_NetsToBase(t *testing.T) {
	srv := sendgridScopesServer(t, []string{"mail.send", "whitelabel.read"}, http.StatusOK)
	defer srv.Close()

	score := scoreSendGridKey(t, srv)
	assert.Equal(t, 65, score.Final, "65 base + 20 domain auth - 20 narrow scope")
	assert.Contains(t, appliedNames(score), "domain-auth-access")
	assert.Contains(t, appliedNames(score), "narrow-scope-set")
}

// A revoked key is worthless regardless of what it once could do. revoked-key
// is the lowest priority so its set_score lands last and wins outright.
func TestSendGridScorer_RevokedKey_SetScore5(t *testing.T) {
	srv := sendgridScopesServer(t, nil, http.StatusUnauthorized)
	defer srv.Close()

	score := scoreSendGridKey(t, srv)
	assert.Equal(t, 5, score.Final)
	assert.Contains(t, appliedNames(score), "revoked-key")
	// The negated array-length check must not fire on an error body: jsonGet
	// errors on the missing .scopes path rather than returning false.
	assert.NotContains(t, appliedNames(score), "narrow-scope-set")
}

// Email Marketing access exposes contact lists (PII). The documented scope is
// marketing.read; marketing.contacts.read does not exist.
func TestSendGridScorer_MarketingAccess_AddsPIIDelta(t *testing.T) {
	srv := sendgridScopesServer(t, []string{"mail.send", "marketing.read"}, http.StatusOK)
	defer srv.Close()

	score := scoreSendGridKey(t, srv)
	assert.Contains(t, appliedNames(score), "contact-pii-access")
	assert.Equal(t, 60, score.Final, "65 base + 15 marketing PII - 20 narrow scope")
}
