package scoring_test

// Tests that verify each dynamic scorer YAML condition against
// realistic API response fixtures based on official API documentation.
// These tests do NOT make real network calls.
//
// GitHub API docs: https://docs.github.com/en/rest/users/users
// Slack API docs: https://api.slack.com/methods/auth.test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/praetorian-inc/titus/pkg/scoring"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadFixture reads a JSON fixture file from testdata/.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err, "fixture %s must exist", name)
	return data
}

// mockAPIServer returns a test server that serves the given fixture body
// with the given status code and optional headers.
func mockAPIServer(t *testing.T, status int, body []byte, headers map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
}

// scoreWithYAML builds a scorer from inline YAML and calls Score with the
// given named groups. ScopeEnabled is set to true so dynamic modifiers run.
func scoreWithYAML(t *testing.T, scorerYAML string, ruleID string, baseScore int, namedGroups map[string][]byte) *types.Score {
	t.Helper()
	loader := scoring.NewLoader()
	scorers, err := loader.LoadScorers([]byte(scorerYAML))
	require.NoError(t, err)
	engine := scoring.NewEngine(scorers, scoring.EngineConfig{ScopeEnabled: true, Timeout: 5e9})
	rule := &types.Rule{ID: ruleID, BaseScore: baseScore}
	finding := &types.Finding{ID: "test", RuleID: ruleID}
	match := &types.Match{RuleID: ruleID, NamedGroups: namedGroups}
	return engine.Score(context.Background(), finding, []*types.Match{match}, rule)
}

// =============================================================================
// GitHub scorer fixture tests
// =============================================================================

func TestGitHubScorer_AdminOrgScope_FiringConditions(t *testing.T) {
	// admin:org in x-oauth-scopes header → modifier fires → set_score: 90
	srv := mockAPIServer(t, 200, loadFixture(t, "github_user_enterprise.json"),
		map[string]string{"x-oauth-scopes": "admin:org, repo, read:user"})
	defer srv.Close()

	yaml := `
scorers:
  - name: test-scorer
    rule_ids: [np.github.1]
    modifiers:
      - name: admin-org-scope
        priority: 90
        http:
          method: GET
          url: ` + srv.URL + `
          auth: {type: bearer, secret_group: token}
        fires_when:
          header_contains:
            name: x-oauth-scopes
            value: "admin:org"
        set_score: 90
`
	score := scoreWithYAML(t, yaml, "np.github.1", 70, map[string][]byte{"token": []byte("ghp_test")})

	assert.Equal(t, 90, score.Final, "admin:org scope should set_score to 90")
	require.Len(t, score.Applied, 1)
	assert.Equal(t, "admin-org-scope", score.Applied[0].Name)
}

func TestGitHubScorer_AdminOrgScope_DoesNotFireWithoutScope(t *testing.T) {
	// read-only scopes → modifier must not fire
	srv := mockAPIServer(t, 200, loadFixture(t, "github_user.json"),
		map[string]string{"x-oauth-scopes": "read:user, repo"})
	defer srv.Close()

	yaml := `
scorers:
  - name: test-scorer
    rule_ids: [np.github.1]
    modifiers:
      - name: admin-org-scope
        priority: 90
        http:
          method: GET
          url: ` + srv.URL + `
          auth: {type: bearer, secret_group: token}
        fires_when:
          header_contains:
            name: x-oauth-scopes
            value: "admin:org"
        set_score: 90
`
	score := scoreWithYAML(t, yaml, "np.github.1", 70, map[string][]byte{"token": []byte("ghp_test")})

	assert.Equal(t, 70, score.Final, "without admin:org scope, score should stay at base")
	assert.Empty(t, score.Applied)
}

func TestGitHubScorer_EnterprisePlan_FiresForEnterpriseUser(t *testing.T) {
	srv := mockAPIServer(t, 200, loadFixture(t, "github_user_enterprise.json"), nil)
	defer srv.Close()

	yaml := `
scorers:
  - name: test-scorer
    rule_ids: [np.github.1]
    modifiers:
      - name: enterprise-plan
        priority: 80
        http:
          method: GET
          url: ` + srv.URL + `
          auth: {type: bearer, secret_group: token}
        fires_when:
          json_path_equals:
            path: ".plan.name"
            value: enterprise
        delta: 15
`
	score := scoreWithYAML(t, yaml, "np.github.1", 70, map[string][]byte{"token": []byte("ghp_test")})

	assert.Equal(t, 85, score.Final, "enterprise plan should add +15")
}

func TestGitHubScorer_EnterprisePlan_DoesNotFireForFreeUser(t *testing.T) {
	srv := mockAPIServer(t, 200, loadFixture(t, "github_user.json"), nil)
	defer srv.Close()

	yaml := `
scorers:
  - name: test-scorer
    rule_ids: [np.github.1]
    modifiers:
      - name: enterprise-plan
        priority: 80
        http:
          method: GET
          url: ` + srv.URL + `
          auth: {type: bearer, secret_group: token}
        fires_when:
          json_path_equals:
            path: ".plan.name"
            value: enterprise
        delta: 15
`
	score := scoreWithYAML(t, yaml, "np.github.1", 70, map[string][]byte{"token": []byte("ghp_test")})

	assert.Equal(t, 70, score.Final, "free plan should not fire")
}

func TestGitHubScorer_MultiOrg_FiresForManyOrgs(t *testing.T) {
	srv := mockAPIServer(t, 200, loadFixture(t, "github_orgs_many.json"), nil)
	defer srv.Close()

	yaml := `
scorers:
  - name: test-scorer
    rule_ids: [np.github.1]
    modifiers:
      - name: multi-org-member
        priority: 50
        http:
          method: GET
          url: ` + srv.URL + `
          auth: {type: bearer, secret_group: token}
        fires_when:
          json_array_length_gte:
            path: "."
            value: 3
        delta: 10
`
	score := scoreWithYAML(t, yaml, "np.github.1", 70, map[string][]byte{"token": []byte("ghp_test")})

	assert.Equal(t, 80, score.Final, "5 orgs >= 3 should add +10")
}

// =============================================================================
// Slack scorer fixture tests
// =============================================================================

func TestSlackScorer_ValidToken_FiresOnSuccess(t *testing.T) {
	// auth.test returns {"ok": true} → token is valid → modifier fires.
	// Note: json_path_equals compares using fmt.Sprintf("%v") which converts
	// JSON boolean true → "true", matching YAML value: true → "true". This is
	// intentional and documented behavior.
	srv := mockAPIServer(t, 200, loadFixture(t, "slack_auth_test_valid.json"), nil)
	defer srv.Close()

	yaml := `
scorers:
  - name: test-scorer
    rule_ids: [np.slack.2]
    modifiers:
      - name: valid-active-token
        priority: 90
        http:
          method: POST
          url: ` + srv.URL + `
          auth: {type: bearer, secret_group: token}
        fires_when:
          json_path_equals:
            path: ".ok"
            value: true
        delta: 10
`
	score := scoreWithYAML(t, yaml, "np.slack.2", 60, map[string][]byte{"token": []byte("xoxb-test")})

	assert.Equal(t, 70, score.Final, "valid token should add +10")
}

func TestSlackScorer_ValidToken_DoesNotFireOnInvalidToken(t *testing.T) {
	// auth.test returns {"ok": false} → revoked token → modifier must not fire.
	// Slack returns HTTP 200 even for invalid tokens; only ok:false indicates failure.
	srv := mockAPIServer(t, 200, loadFixture(t, "slack_auth_test_invalid.json"), nil)
	defer srv.Close()

	yaml := `
scorers:
  - name: test-scorer
    rule_ids: [np.slack.2]
    modifiers:
      - name: valid-active-token
        priority: 90
        http:
          method: POST
          url: ` + srv.URL + `
          auth: {type: bearer, secret_group: token}
        fires_when:
          json_path_equals:
            path: ".ok"
            value: true
        delta: 10
`
	score := scoreWithYAML(t, yaml, "np.slack.2", 60, map[string][]byte{"token": []byte("xoxb-invalid")})

	assert.Equal(t, 60, score.Final, "revoked token (ok:false) should not fire")
}

func TestSlackScorer_EnterpriseGrid_FiresWhenEnterpriseIDPresent(t *testing.T) {
	// enterprise_id is non-empty → Enterprise Grid workspace → modifier fires.
	// auth.test includes enterprise_id as a top-level string field; it is only
	// present (non-empty) for Enterprise Grid workspaces.
	srv := mockAPIServer(t, 200, loadFixture(t, "slack_auth_test_enterprise.json"), nil)
	defer srv.Close()

	yaml := `
scorers:
  - name: test-scorer
    rule_ids: [np.slack.2]
    modifiers:
      - name: enterprise-grid
        priority: 70
        http:
          method: POST
          url: ` + srv.URL + `
          auth: {type: bearer, secret_group: token}
        fires_when:
          json_path_matches:
            path: ".enterprise_id"
            regex: "^E[A-Z0-9]+"
        delta: 15
`
	score := scoreWithYAML(t, yaml, "np.slack.2", 60, map[string][]byte{"token": []byte("xoxb-test")})

	assert.Equal(t, 75, score.Final, "Enterprise Grid (enterprise_id ^E) should add +15")
}

func TestSlackScorer_EnterpriseGrid_DoesNotFireForStandardWorkspace(t *testing.T) {
	// Standard workspace has no enterprise_id field → modifier must not fire.
	srv := mockAPIServer(t, 200, loadFixture(t, "slack_auth_test_valid.json"), nil)
	defer srv.Close()

	yaml := `
scorers:
  - name: test-scorer
    rule_ids: [np.slack.2]
    modifiers:
      - name: enterprise-grid
        priority: 70
        http:
          method: POST
          url: ` + srv.URL + `
          auth: {type: bearer, secret_group: token}
        fires_when:
          json_path_matches:
            path: ".enterprise_id"
            regex: "^E[A-Z0-9]+"
        delta: 15
`
	score := scoreWithYAML(t, yaml, "np.slack.2", 60, map[string][]byte{"token": []byte("xoxb-test")})

	assert.Equal(t, 60, score.Final, "standard workspace (no enterprise_id) should not fire")
}
