package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinElevenLabsScorer_IsRegisteredForRule(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.elevenlabs.1")
	assert.Equal(t, "elevenlabs-key-scope", s.Name)

	got := make(map[string]Modifier, len(s.Modifiers))
	for _, m := range s.Modifiers {
		got[m.Name] = m
	}
	for _, name := range []string{
		"paid-tier", "free-tier", "revoked-key",
	} {
		assert.Contains(t, got, name)
	}
}

func TestBuiltinElevenLabsScorer_AllModifiersShareOneAuthedRequest(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.elevenlabs.1")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		assert.Equal(t, "https://api.elevenlabs.io/v1/user/subscription", cond.url, "modifier %q", m.Name)
		assert.Equal(t, "GET", cond.method, "modifier %q", m.Name)
		assert.Equal(t, "header", cond.auth.Type, "modifier %q", m.Name)
		assert.Equal(t, "xi-api-key", cond.auth.HeaderName, "modifier %q", m.Name)
		assert.Equal(t, "token", cond.auth.SecretGroup, "modifier %q", m.Name)
	}
}

func TestBuiltinElevenLabsScorer_RevokedKeyIsLowestPriority(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.elevenlabs.1")
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

func TestBuiltinElevenLabsScorer_OnlyRevokedUsesSetScore(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.elevenlabs.1")
	for _, m := range s.Modifiers {
		if m.Kind == ModifierKindSetScore {
			assert.Equal(t, "revoked-key", m.Name,
				"only revoked-key should use set_score")
		}
	}
}

func TestBuiltinElevenLabsScorer_PaidTierIsNegated(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.elevenlabs.1")
	for _, m := range s.Modifiers {
		if m.Name != "paid-tier" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.True(t, ok)
		_, ok = cond.firesWhen.(*negatedLeaf)
		assert.True(t, ok, "paid-tier should use negative: true")
		return
	}
	t.Fatal("paid-tier modifier not found")
}

func TestBuiltinElevenLabsScorer_FreeTierChecksTierField(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.elevenlabs.1")
	for _, m := range s.Modifiers {
		if m.Name != "free-tier" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.True(t, ok)
		leaf, ok := cond.firesWhen.(*jsonPathEqualsLeaf)
		require.True(t, ok, "free-tier should use json_path_equals")
		assert.Equal(t, ".tier", leaf.Path)
		assert.Equal(t, "free", leaf.Value)
		return
	}
	t.Fatal("free-tier modifier not found")
}

func TestBuiltinElevenLabsScorer_RevokedKeyIs401Only(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.elevenlabs.1")
	for _, m := range s.Modifiers {
		if m.Name != "revoked-key" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.True(t, ok)
		leaf, ok := cond.firesWhen.(*statusCodeLeaf)
		require.True(t, ok, "revoked-key should use status_code (not status_code_in)")
		assert.Equal(t, 401, leaf.Code)
		return
	}
	t.Fatal("revoked-key modifier not found")
}

func TestBuiltinElevenLabsScorer_ModifierCount(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.elevenlabs.1")
	assert.Len(t, s.Modifiers, 3)
}
