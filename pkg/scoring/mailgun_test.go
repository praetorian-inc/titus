package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinMailgunScorer_IsRegisteredForRule(t *testing.T) {
	s := builtinScorerFor(t, "np.mailgun.1")
	assert.Equal(t, "mailgun-key-scope", s.Name)

	got := make(map[string]Modifier, len(s.Modifiers))
	for _, m := range s.Modifiers {
		got[m.Name] = m
	}
	for _, name := range []string{
		"has-production-domain", "multiple-domains",
		"sandbox-only", "revoked-key",
	} {
		assert.Contains(t, got, name)
	}
}

func TestBuiltinMailgunScorer_AllModifiersShareOneAuthedRequest(t *testing.T) {
	s := builtinScorerFor(t, "np.mailgun.1")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		assert.Equal(t, "https://api.mailgun.net/v3/domains", cond.url, "modifier %q", m.Name)
		assert.Equal(t, "GET", cond.method, "modifier %q", m.Name)
		assert.Equal(t, "basic", cond.auth.Type, "modifier %q", m.Name)
		assert.Equal(t, "api", cond.auth.Username, "modifier %q", m.Name)
		assert.Equal(t, "token", cond.auth.SecretGroup, "modifier %q", m.Name)
	}
}

func TestBuiltinMailgunScorer_RevokedKeyIsLowestPriority(t *testing.T) {
	s := builtinScorerFor(t, "np.mailgun.1")
	prio := make(map[string]int, len(s.Modifiers))
	for _, m := range s.Modifiers {
		prio[m.Name] = m.Priority
	}

	for name, p := range prio {
		if name == "revoked-key" {
			continue
		}
		assert.Less(t, prio["revoked-key"], p,
			"revoked-key must evaluate last; %q has lower or equal priority", name)
	}
}

func TestBuiltinMailgunScorer_OnlyRevokedUsesSetScore(t *testing.T) {
	s := builtinScorerFor(t, "np.mailgun.1")
	for _, m := range s.Modifiers {
		if m.Kind == ModifierKindSetScore {
			assert.Equal(t, "revoked-key", m.Name,
				"only revoked-key should use set_score")
		}
	}
}

func TestBuiltinMailgunScorer_SandboxOnlyIsNegated(t *testing.T) {
	s := builtinScorerFor(t, "np.mailgun.1")
	for _, m := range s.Modifiers {
		if m.Name != "sandbox-only" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.True(t, ok)
		_, ok = cond.firesWhen.(*negatedLeaf)
		assert.True(t, ok, "sandbox-only should use negative: true")
		return
	}
	t.Fatal("sandbox-only modifier not found")
}

func TestBuiltinMailgunScorer_MultipleDomainsAccountsForSandbox(t *testing.T) {
	s := builtinScorerFor(t, "np.mailgun.1")
	for _, m := range s.Modifiers {
		if m.Name != "multiple-domains" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.True(t, ok)
		leaf, ok := cond.firesWhen.(*jsonArrayLengthGteLeaf)
		require.True(t, ok, "multiple-domains should use json_array_length_gte")
		assert.Equal(t, 3, leaf.Value,
			"threshold must be 3 (not 2) because Mailgun auto-provisions a sandbox domain")
		return
	}
	t.Fatal("multiple-domains modifier not found")
}

func TestBuiltinMailgunScorer_RevokedKeyCovers403(t *testing.T) {
	s := builtinScorerFor(t, "np.mailgun.1")
	for _, m := range s.Modifiers {
		if m.Name != "revoked-key" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.True(t, ok)
		leaf, ok := cond.firesWhen.(*statusCodeInLeaf)
		require.True(t, ok, "revoked-key should use status_code_in")
		assert.Contains(t, leaf.Codes, 401)
		assert.Contains(t, leaf.Codes, 403)
		return
	}
	t.Fatal("revoked-key modifier not found")
}

func TestBuiltinMailgunScorer_ModifierCount(t *testing.T) {
	s := builtinScorerFor(t, "np.mailgun.1")
	assert.Len(t, s.Modifiers, 4)
}
