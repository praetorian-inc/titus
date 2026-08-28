package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinNotionScorer_IsRegisteredForRules(t *testing.T) {
	for _, ruleID := range []string{"kingfisher.notion.1", "kingfisher.notion.2"} {
		s := builtinScorerFor(t, ruleID)
		assert.Equal(t, "notion-token-scope", s.Name)
	}
}

func TestBuiltinNotionScorer_ModifierNames(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.notion.1")
	got := make(map[string]Modifier, len(s.Modifiers))
	for _, m := range s.Modifiers {
		got[m.Name] = m
	}
	for _, name := range []string{
		"workspace-integration", "user-scoped-token", "revoked-key",
	} {
		assert.Contains(t, got, name)
	}
}

func TestBuiltinNotionScorer_AllModifiersShareOneAuthedRequest(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.notion.1")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		assert.Equal(t, "https://api.notion.com/v1/users/me", cond.url, "modifier %q", m.Name)
		assert.Equal(t, "GET", cond.method, "modifier %q", m.Name)
		assert.Equal(t, "bearer", cond.auth.Type, "modifier %q", m.Name)
		assert.Equal(t, "token", cond.auth.SecretGroup, "modifier %q", m.Name)
	}
}

func TestBuiltinNotionScorer_NotionVersionHeader(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.notion.1")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		found := false
		for _, h := range cond.headers {
			if h.Name == "Notion-Version" {
				assert.Equal(t, "2022-06-28", h.Value)
				found = true
			}
		}
		assert.Truef(t, found, "modifier %q missing Notion-Version header", m.Name)
	}
}

func TestBuiltinNotionScorer_RevokedKeyIsLowestPriority(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.notion.1")
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

func TestBuiltinNotionScorer_OwnerTypeChecks(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.notion.1")
	want := map[string]string{
		"workspace-integration": "workspace",
		"user-scoped-token":     "user",
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
		assert.Equal(t, ".bot.owner.type", leaf.Path, "modifier %q json path", m.Name)
		assert.Equal(t, exp, leaf.Value, "modifier %q expected value", m.Name)
	}
}

func TestBuiltinNotionScorer_OnlyRevokedUsesSetScore(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.notion.1")
	for _, m := range s.Modifiers {
		if m.Kind == ModifierKindSetScore {
			assert.Equal(t, "revoked-key", m.Name,
				"only revoked-key should use set_score")
		}
	}
}

func TestBuiltinNotionScorer_DoesNotCoverRefreshToken(t *testing.T) {
	scorers, err := NewLoader().LoadBuiltinScorers()
	require.NoError(t, err)
	for _, s := range scorers {
		if s.canScore("kingfisher.notion.3") {
			t.Fatal("kingfisher.notion.3 (refresh token) should not be scored — it cannot be probed directly")
		}
	}
}

func TestBuiltinNotionScorer_ModifierCount(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.notion.1")
	assert.Len(t, s.Modifiers, 3)
}
