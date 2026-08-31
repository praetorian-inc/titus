package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinNgrokScorer_IsRegisteredForRule(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.ngrok.1")
	assert.Equal(t, "ngrok-key-scope", s.Name)

	got := make(map[string]Modifier, len(s.Modifiers))
	for _, m := range s.Modifiers {
		got[m.Name] = m
	}
	for _, name := range []string{
		"has-active-endpoints", "no-active-endpoints", "revoked-key",
	} {
		assert.Contains(t, got, name)
	}
}

func TestBuiltinNgrokScorer_AllModifiersShareOneAuthedRequest(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.ngrok.1")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		assert.Equal(t, "https://api.ngrok.com/endpoints", cond.url, "modifier %q", m.Name)
		assert.Equal(t, "GET", cond.method, "modifier %q", m.Name)
		assert.Equal(t, "bearer", cond.auth.Type, "modifier %q", m.Name)
		assert.Equal(t, "token", cond.auth.SecretGroup, "modifier %q", m.Name)
	}
}

func TestBuiltinNgrokScorer_NgrokVersionHeader(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.ngrok.1")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		found := false
		for _, h := range cond.headers {
			if h.Name == "ngrok-version" {
				assert.Equal(t, "2", h.Value)
				found = true
			}
		}
		assert.Truef(t, found, "modifier %q missing ngrok-version header", m.Name)
	}
}

func TestBuiltinNgrokScorer_RevokedKeyIsLowestPriority(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.ngrok.1")
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

func TestBuiltinNgrokScorer_OnlyRevokedUsesSetScore(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.ngrok.1")
	found := false
	for _, m := range s.Modifiers {
		if m.Kind == ModifierKindSetScore {
			found = true
			assert.Equal(t, "revoked-key", m.Name,
				"only revoked-key should use set_score")
		}
	}
	assert.True(t, found, "revoked-key should use set_score")
}

func TestBuiltinNgrokScorer_NoActiveEndpointsIsNegated(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.ngrok.1")
	for _, m := range s.Modifiers {
		if m.Name != "no-active-endpoints" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.True(t, ok)
		_, ok = cond.firesWhen.(*negatedLeaf)
		assert.True(t, ok, "no-active-endpoints should use negative: true")
		return
	}
	t.Fatal("no-active-endpoints modifier not found")
}

func TestBuiltinNgrokScorer_RevokedKeyCovers403(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.ngrok.1")
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

func TestBuiltinNgrokScorer_ModifierCount(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.ngrok.1")
	assert.Len(t, s.Modifiers, 3)
}
