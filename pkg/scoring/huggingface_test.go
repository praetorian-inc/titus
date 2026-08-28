package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinHuggingFaceScorer_IsRegisteredForRule(t *testing.T) {
	s := builtinScorerFor(t, "np.huggingface.1")
	assert.Equal(t, "huggingface-token-scope", s.Name)

	got := make(map[string]Modifier, len(s.Modifiers))
	for _, m := range s.Modifiers {
		got[m.Name] = m
	}
	for _, name := range []string{
		"write-access", "read-only-access", "fine-grained-token",
		"org-member", "revoked-key",
	} {
		assert.Contains(t, got, name)
	}
}

func TestBuiltinHuggingFaceScorer_AllModifiersShareOneAuthedRequest(t *testing.T) {
	s := builtinScorerFor(t, "np.huggingface.1")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		assert.Equal(t, "https://huggingface.co/api/whoami-v2", cond.url, "modifier %q", m.Name)
		assert.Equal(t, "GET", cond.method, "modifier %q", m.Name)
		assert.Equal(t, "bearer", cond.auth.Type, "modifier %q", m.Name)
		assert.Equal(t, "token", cond.auth.SecretGroup, "modifier %q", m.Name)
	}
}

func TestBuiltinHuggingFaceScorer_RevokedKeyIsLowestPriority(t *testing.T) {
	s := builtinScorerFor(t, "np.huggingface.1")
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

func TestBuiltinHuggingFaceScorer_OnlyRevokedUsesSetScore(t *testing.T) {
	s := builtinScorerFor(t, "np.huggingface.1")
	for _, m := range s.Modifiers {
		if m.Kind == ModifierKindSetScore {
			assert.Equal(t, "revoked-key", m.Name,
				"only revoked-key should use set_score")
		}
	}
}

func TestBuiltinHuggingFaceScorer_RoleModifiersCheckCorrectPaths(t *testing.T) {
	s := builtinScorerFor(t, "np.huggingface.1")

	want := map[string]struct {
		path  string
		value string
	}{
		"write-access":      {".auth.accessToken.role", "write"},
		"read-only-access":  {".auth.accessToken.role", "read"},
		"fine-grained-token": {".auth.accessToken.role", "fineGrained"},
	}

	for _, m := range s.Modifiers {
		exp, ok := want[m.Name]
		if !ok {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		leaf, ok := cond.firesWhen.(*jsonPathEqualsLeaf)
		require.Truef(t, ok, "modifier %q should use json_path_equals", m.Name)
		assert.Equal(t, exp.path, leaf.Path, "modifier %q json path", m.Name)
		assert.Equal(t, exp.value, leaf.Value, "modifier %q expected value", m.Name)
	}
}

func TestBuiltinHuggingFaceScorer_OrgMemberChecksOrgsArray(t *testing.T) {
	s := builtinScorerFor(t, "np.huggingface.1")
	for _, m := range s.Modifiers {
		if m.Name != "org-member" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.True(t, ok)
		leaf, ok := cond.firesWhen.(*jsonArrayLengthGteLeaf)
		require.True(t, ok, "org-member should use json_array_length_gte")
		assert.Equal(t, ".orgs", leaf.Path)
		assert.Equal(t, 1, leaf.Value)
		return
	}
	t.Fatal("org-member modifier not found")
}

func TestBuiltinHuggingFaceScorer_ModifierCount(t *testing.T) {
	s := builtinScorerFor(t, "np.huggingface.1")
	assert.Len(t, s.Modifiers, 5)
}
