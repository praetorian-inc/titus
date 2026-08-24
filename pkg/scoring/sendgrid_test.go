package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// builtinScorerFor returns the built-in scorer covering ruleID.
func builtinScorerFor(t *testing.T, ruleID string) *Scorer {
	t.Helper()
	scorers, err := NewLoader().LoadBuiltinScorers()
	require.NoError(t, err)
	for _, s := range scorers {
		if s.canScore(ruleID) {
			return s
		}
	}
	t.Fatalf("no built-in scorer covers rule %q", ruleID)
	return nil
}

// The shipped scorer must exist and be registered for the SendGrid rule. The
// cmd/titus scope tests build their own YAML, so without this the production
// file could be missing entirely and those tests would still pass.
func TestBuiltinSendGridScorer_IsRegisteredForRule(t *testing.T) {
	s := builtinScorerFor(t, "np.sendgrid.1")
	assert.Equal(t, "sendgrid-key-scope", s.Name)

	got := make(map[string]Modifier, len(s.Modifiers))
	for _, m := range s.Modifiers {
		got[m.Name] = m
	}
	for _, name := range []string{
		"full-access-key", "domain-auth-access", "subuser-management",
		"contact-pii-access", "narrow-scope-set", "billing-access", "revoked-key",
	} {
		assert.Contains(t, got, name)
	}
}

// Every modifier must hit the real scopes endpoint with the rule's token group.
// The engine caches on (method, url, secret), so identical URLs also mean one
// network call per finding rather than seven.
func TestBuiltinSendGridScorer_AllModifiersShareOneAuthedRequest(t *testing.T) {
	s := builtinScorerFor(t, "np.sendgrid.1")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		assert.Equal(t, "https://api.sendgrid.com/v3/scopes", cond.url, "modifier %q", m.Name)
		assert.Equal(t, "GET", cond.method, "modifier %q", m.Name)
		assert.Equal(t, "bearer", cond.auth.Type, "modifier %q", m.Name)
		assert.Equal(t, "token", cond.auth.SecretGroup, "modifier %q", m.Name)
	}
}

// Ordering is load-bearing, not cosmetic. Higher priority is evaluated first and
// a later set_score replaces the running score, so billing-access must come
// AFTER narrow-scope-set to override its downgrade, and revoked-key must be last
// of all so a dead key scores 5 no matter what scopes it once held.
func TestBuiltinSendGridScorer_SetScoreOrderingInvariants(t *testing.T) {
	s := builtinScorerFor(t, "np.sendgrid.1")
	prio := make(map[string]int, len(s.Modifiers))
	for _, m := range s.Modifiers {
		prio[m.Name] = m.Priority
	}

	assert.Less(t, prio["billing-access"], prio["narrow-scope-set"],
		"billing-access must evaluate after narrow-scope-set to override its delta")

	for name, p := range prio {
		if name == "revoked-key" {
			continue
		}
		assert.Less(t, prio["revoked-key"], p,
			"revoked-key must evaluate last; %q has lower or equal priority", name)
	}
}
