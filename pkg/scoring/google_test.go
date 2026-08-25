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

// The shipped Google scorer's dynamic modifiers must actually be able to issue
// their request. They could not: auth.type "none" was unsupported, so both
// modifiers errored before sending anything and the scorer silently did nothing
// from the day it shipped. Nothing caught it because the dynamic path was never
// exercised against the built-in file.
func TestBuiltinGoogleScorer_DynamicModifiersCanIssueTheirRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"models":[{"name":"models/gemini-1.5-pro"}]}`))
	}))
	defer srv.Close()

	s := builtinScorerFor(t, "np.google.5")

	var dynamic int
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		if !ok {
			continue
		}
		dynamic++
		// Point the real modifier at the stub, leaving auth untouched.
		probe := &httpCondition{
			method:    cond.method,
			url:       srv.URL + "/v1/models?key={{key}}",
			headers:   cond.headers,
			body:      cond.body,
			auth:      cond.auth,
			firesWhen: cond.firesWhen,
		}
		m := &types.Match{NamedGroups: map[string][]byte{"key": []byte("AIzaSyEXAMPLE")}}
		_, err := probe.Evaluate(context.Background(), m)
		require.NoErrorf(t, err, "modifier %q could not issue its request", s.Modifiers[dynamic-1].Name)
	}
	require.Positive(t, dynamic, "expected the Google scorer to have dynamic modifiers")
}

// type: none still needs secret_group. evaluateWithCache builds the cache key
// from NamedGroups[auth.SecretGroup]; without it secretBytes is nil and every
// finding sharing this URL template collides on one cache entry, so the second
// key silently receives the first key's response. It looks redundant next to
// type: none -- it is not.
func TestBuiltinGoogleScorer_KeepsSecretGroupForCacheKeying(t *testing.T) {
	s := builtinScorerFor(t, "np.google.5")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		if !ok {
			continue
		}
		assert.NotEmptyf(t, cond.auth.SecretGroup,
			"modifier %q must keep secret_group so cache keys stay per-secret", m.Name)
	}
}
