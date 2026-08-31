package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinAnthropicScorer_IsRegisteredForRule(t *testing.T) {
	s := builtinScorerFor(t, "np.anthropic.1")
	assert.Equal(t, "anthropic-key-scope", s.Name)

	got := make(map[string]Modifier, len(s.Modifiers))
	for _, m := range s.Modifiers {
		got[m.Name] = m
	}
	for _, name := range []string{
		"has-opus-access", "no-opus-access", "revoked-key",
	} {
		assert.Contains(t, got, name)
	}
}

func TestBuiltinAnthropicScorer_AllModifiersShareOneAuthedRequest(t *testing.T) {
	s := builtinScorerFor(t, "np.anthropic.1")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		assert.Equal(t, "https://api.anthropic.com/v1/models", cond.url, "modifier %q", m.Name)
		assert.Equal(t, "GET", cond.method, "modifier %q", m.Name)
		assert.Equal(t, "header", cond.auth.Type, "modifier %q", m.Name)
		assert.Equal(t, "x-api-key", cond.auth.HeaderName, "modifier %q", m.Name)
		assert.Equal(t, "token", cond.auth.SecretGroup, "modifier %q", m.Name)
	}
}

func TestBuiltinAnthropicScorer_AnthropicVersionHeader(t *testing.T) {
	s := builtinScorerFor(t, "np.anthropic.1")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		found := false
		for _, h := range cond.headers {
			if h.Name == "anthropic-version" {
				assert.Equal(t, "2023-06-01", h.Value)
				found = true
			}
		}
		assert.Truef(t, found, "modifier %q missing anthropic-version header", m.Name)
	}
}

func TestBuiltinAnthropicScorer_RevokedKeyIsLowestPriority(t *testing.T) {
	s := builtinScorerFor(t, "np.anthropic.1")
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

func TestBuiltinAnthropicScorer_OnlyRevokedUsesSetScore(t *testing.T) {
	s := builtinScorerFor(t, "np.anthropic.1")
	for _, m := range s.Modifiers {
		if m.Kind == ModifierKindSetScore {
			assert.Equal(t, "revoked-key", m.Name,
				"only revoked-key should use set_score")
		}
	}
}

func TestBuiltinAnthropicScorer_NoOpusIsNegated(t *testing.T) {
	s := builtinScorerFor(t, "np.anthropic.1")
	for _, m := range s.Modifiers {
		if m.Name != "no-opus-access" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.True(t, ok)
		_, ok = cond.firesWhen.(*negatedLeaf)
		assert.True(t, ok, "no-opus-access should use negative: true")
		return
	}
	t.Fatal("no-opus-access modifier not found")
}

func TestBuiltinAnthropicScorer_RevokedKeyCovers403(t *testing.T) {
	s := builtinScorerFor(t, "np.anthropic.1")
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

func TestBuiltinAnthropicScorer_ModifierCount(t *testing.T) {
	s := builtinScorerFor(t, "np.anthropic.1")
	assert.Len(t, s.Modifiers, 3)
}
