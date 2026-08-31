package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinOpenAIScorer_IsRegisteredForRule(t *testing.T) {
	s := builtinScorerFor(t, "np.openai.1")
	assert.Equal(t, "openai-key-scope", s.Name)

	got := make(map[string]Modifier, len(s.Modifiers))
	for _, m := range s.Modifiers {
		got[m.Name] = m
	}
	for _, name := range []string{
		"broad-model-access", "limited-model-access", "revoked-key",
	} {
		assert.Contains(t, got, name)
	}
}

func TestBuiltinOpenAIScorer_AllModifiersShareOneAuthedRequest(t *testing.T) {
	s := builtinScorerFor(t, "np.openai.1")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		assert.Equal(t, "https://api.openai.com/v1/models", cond.url, "modifier %q", m.Name)
		assert.Equal(t, "GET", cond.method, "modifier %q", m.Name)
		assert.Equal(t, "bearer", cond.auth.Type, "modifier %q", m.Name)
		assert.Equal(t, "key", cond.auth.SecretGroup, "modifier %q", m.Name)
	}
}

func TestBuiltinOpenAIScorer_RevokedKeyIsLowestPriority(t *testing.T) {
	s := builtinScorerFor(t, "np.openai.1")
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

func TestBuiltinOpenAIScorer_OnlyRevokedUsesSetScore(t *testing.T) {
	s := builtinScorerFor(t, "np.openai.1")
	for _, m := range s.Modifiers {
		if m.Kind == ModifierKindSetScore {
			assert.Equal(t, "revoked-key", m.Name,
				"only revoked-key should use set_score")
		}
	}
}

func TestBuiltinOpenAIScorer_ModelAccessModifiersCheckCorrectPath(t *testing.T) {
	s := builtinScorerFor(t, "np.openai.1")
	for _, m := range s.Modifiers {
		if m.Name != "broad-model-access" && m.Name != "limited-model-access" {
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
		assert.Equal(t, ".data", leaf.Path, "modifier %q json path", m.Name)
		assert.Equal(t, 10, leaf.Value, "modifier %q threshold", m.Name)
	}
}

func TestBuiltinOpenAIScorer_LimitedModelAccessIsNegated(t *testing.T) {
	s := builtinScorerFor(t, "np.openai.1")
	for _, m := range s.Modifiers {
		if m.Name != "limited-model-access" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.True(t, ok)
		_, ok = cond.firesWhen.(*negatedLeaf)
		assert.True(t, ok, "limited-model-access should use negative: true")
		return
	}
	t.Fatal("limited-model-access modifier not found")
}

func TestBuiltinOpenAIScorer_RevokedKeyCovers403(t *testing.T) {
	s := builtinScorerFor(t, "np.openai.1")
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

func TestBuiltinOpenAIScorer_ModifierCount(t *testing.T) {
	s := builtinScorerFor(t, "np.openai.1")
	assert.Len(t, s.Modifiers, 3)
}
