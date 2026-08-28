package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinAsanaScorer_IsRegisteredForRule(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.asana.3")
	assert.Equal(t, "asana-token-scope", s.Name)
}

func TestBuiltinAsanaScorer_DoesNotCoverClientIDOrSecret(t *testing.T) {
	scorers, err := NewLoader().LoadBuiltinScorers()
	require.NoError(t, err)
	for _, s := range scorers {
		for _, id := range []string{"kingfisher.asana.1", "kingfisher.asana.2"} {
			if s.canScore(id) {
				t.Fatalf("%s should not be scored — client IDs and secrets cannot authenticate as bearer tokens", id)
			}
		}
	}
}

func TestBuiltinAsanaScorer_AllModifiersShareOneAuthedRequest(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.asana.3")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		assert.Equal(t, "https://app.asana.com/api/1.0/users/me", cond.url, "modifier %q", m.Name)
		assert.Equal(t, "GET", cond.method, "modifier %q", m.Name)
		assert.Equal(t, "bearer", cond.auth.Type, "modifier %q", m.Name)
		assert.Equal(t, "token", cond.auth.SecretGroup, "modifier %q", m.Name)
	}
}

func TestBuiltinAsanaScorer_RevokedKeyIsLowestPriority(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.asana.3")
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

func TestBuiltinAsanaScorer_OnlyRevokedUsesSetScore(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.asana.3")
	for _, m := range s.Modifiers {
		if m.Kind == ModifierKindSetScore {
			assert.Equal(t, "revoked-key", m.Name,
				"only revoked-key should use set_score")
		}
	}
}

func TestBuiltinAsanaScorer_WorkspaceModifiersCheckCorrectPath(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.asana.3")
	for _, m := range s.Modifiers {
		if m.Name != "multiple-workspaces" && m.Name != "single-workspace-only" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)

		var leaf *jsonArrayLengthGteLeaf
		if neg, isNeg := cond.firesWhen.(*negatedLeaf); isNeg {
			leaf, ok = neg.inner.(*jsonArrayLengthGteLeaf)
		} else {
			leaf, ok = cond.firesWhen.(*jsonArrayLengthGteLeaf)
		}
		require.Truef(t, ok, "modifier %q should use json_array_length_gte", m.Name)
		assert.Equal(t, ".data.workspaces", leaf.Path, "modifier %q json path", m.Name)
		assert.Equal(t, 2, leaf.Value, "modifier %q threshold", m.Name)
	}
}

func TestBuiltinAsanaScorer_SingleWorkspaceIsNegated(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.asana.3")
	for _, m := range s.Modifiers {
		if m.Name != "single-workspace-only" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		_, isNegated := cond.firesWhen.(*negatedLeaf)
		assert.Truef(t, isNegated, "single-workspace-only must use negative: true (negatedLeaf wrapper)")
	}
}

func TestBuiltinAsanaScorer_ModifierCount(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.asana.3")
	assert.Len(t, s.Modifiers, 3)
}
