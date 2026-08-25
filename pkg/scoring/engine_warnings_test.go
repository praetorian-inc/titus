package scoring

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scoreWithWarnings runs one finding through a scorer built from yamlSrc and
// returns the score plus every warning the engine emitted.
func scoreWithWarnings(t *testing.T, yamlSrc string, ruleID string) (*types.Score, []string) {
	t.Helper()
	scorers, err := NewLoader().LoadScorers([]byte(yamlSrc))
	require.NoError(t, err)

	var warnings []string
	engine := NewEngine(scorers, EngineConfig{
		ScopeEnabled: true,
		Timeout:      5 * time.Second,
		WarnF:        func(f string, a ...any) { warnings = append(warnings, fmt.Sprintf(f, a...)) },
	})
	rule := &types.Rule{ID: ruleID, BaseScore: 65}
	finding := &types.Finding{ID: "f1", RuleID: ruleID}
	match := &types.Match{RuleID: ruleID, NamedGroups: map[string][]byte{"token": []byte("secret")}}
	return engine.Score(context.Background(), finding, []*types.Match{match}, rule), warnings
}

// A revoked credential is the common case in a scan, not an anomaly. The
// modifiers that inspect the response body cannot find their fields in a 401
// error body and error, which previously produced a warning each -- scaling
// with every dead key found.
func TestEngine_NotApplicableOnErrorResponse_DoesNotWarn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"message":"authorization required"}]}`))
	}))
	defer srv.Close()

	score, warnings := scoreWithWarnings(t, `
scorers:
  - name: probe
    rule_ids: [np.sendgrid.1]
    modifiers:
      - name: breadth
        priority: 90
        http: &h
          method: GET
          url: `+srv.URL+`/v3/scopes
          auth: {type: bearer, secret_group: "token"}
        fires_when:
          json_array_length_gte: {path: ".scopes", value: 100}
        delta: 30
      - name: narrow
        priority: 40
        http: *h
        fires_when:
          negative: true
          json_array_length_gte: {path: ".scopes", value: 25}
        delta: -20
      - name: revoked
        priority: 10
        http: *h
        fires_when:
          status_code: 401
        set_score: 5
`, "np.sendgrid.1")

	assert.Equal(t, 5, score.Final, "the revoked verdict must still apply")
	assert.Empty(t, warnings, "a condition that cannot apply to an error response is routine, not warnworthy")
}

// The demotion must NOT be unconditional. A condition that cannot find its
// field in a healthy 200 response is probably a typo in the scorer, and losing
// that signal would trade log noise for a silent-misconfiguration hole.
func TestEngine_NotApplicableOnSuccessResponse_StillWarns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"scopes":["mail.send"]}`))
	}))
	defer srv.Close()

	_, warnings := scoreWithWarnings(t, `
scorers:
  - name: probe
    rule_ids: [np.sendgrid.1]
    modifiers:
      - name: typo-path
        priority: 90
        http:
          method: GET
          url: `+srv.URL+`/v3/scopes
          auth: {type: bearer, secret_group: "token"}
        fires_when:
          json_array_length_gte: {path: ".scoeps", value: 5}
        delta: 10
`, "np.sendgrid.1")

	require.Len(t, warnings, 1, "a bad path against a healthy response must still be reported")
	assert.Contains(t, warnings[0], "typo-path")
}
