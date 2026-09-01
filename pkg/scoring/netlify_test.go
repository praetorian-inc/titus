package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinNetlifyScorer_IsRegisteredForRule(t *testing.T) {
	for _, ruleID := range []string{"kingfisher.netlify.1", "kingfisher.netlify.2"} {
		s := builtinScorerFor(t, ruleID)
		assert.Equal(t, "netlify-key-scope", s.Name)

		got := make(map[string]Modifier, len(s.Modifiers))
		for _, m := range s.Modifiers {
			got[m.Name] = m
		}
		for _, name := range []string{
			"has-sites", "no-sites", "revoked-key",
		} {
			assert.Contains(t, got, name, "rule %s", ruleID)
		}
	}
}

func TestBuiltinNetlifyScorer_AllModifiersShareOneAuthedRequest(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.netlify.1")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		assert.Equal(t, "https://api.netlify.com/api/v1/sites", cond.url, "modifier %q", m.Name)
		assert.Equal(t, "GET", cond.method, "modifier %q", m.Name)
		assert.Equal(t, "bearer", cond.auth.Type, "modifier %q", m.Name)
		assert.Equal(t, "token", cond.auth.SecretGroup, "modifier %q", m.Name)
	}
}

func TestBuiltinNetlifyScorer_RevokedKeyIsLowestPriority(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.netlify.1")
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

func TestBuiltinNetlifyScorer_OnlyRevokedUsesSetScore(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.netlify.1")
	for _, m := range s.Modifiers {
		if m.Kind == ModifierKindSetScore {
			assert.Equal(t, "revoked-key", m.Name,
				"only revoked-key should use set_score")
		}
	}
}

func TestBuiltinNetlifyScorer_NoSitesIsNegated(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.netlify.1")
	for _, m := range s.Modifiers {
		if m.Name != "no-sites" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.True(t, ok)
		_, ok = cond.firesWhen.(*negatedLeaf)
		assert.True(t, ok, "no-sites should use negative: true")
		return
	}
	t.Fatal("no-sites modifier not found")
}

func TestBuiltinNetlifyScorer_HasSitesChecksRootArray(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.netlify.1")
	for _, m := range s.Modifiers {
		if m.Name != "has-sites" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.True(t, ok)
		leaf, ok := cond.firesWhen.(*jsonArrayLengthGteLeaf)
		require.True(t, ok, "has-sites should use json_array_length_gte")
		assert.Equal(t, ".", leaf.Path)
		assert.Equal(t, 1, leaf.Value)
		return
	}
	t.Fatal("has-sites modifier not found")
}

func TestBuiltinNetlifyScorer_RevokedKeyCovers403(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.netlify.1")
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

func TestBuiltinNetlifyScorer_ModifierCount(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.netlify.1")
	assert.Len(t, s.Modifiers, 3)
}
