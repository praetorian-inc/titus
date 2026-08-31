package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinMailchimpScorer_IsRegisteredForRule(t *testing.T) {
	s := builtinScorerFor(t, "np.mailchimp.1")
	assert.Equal(t, "mailchimp-key-scope", s.Name)

	got := make(map[string]Modifier, len(s.Modifiers))
	for _, m := range s.Modifiers {
		got[m.Name] = m
	}
	for _, name := range []string{
		"free-plan", "significant-subscribers",
		"no-subscribers", "revoked-key",
	} {
		assert.Contains(t, got, name)
	}
}

func TestBuiltinMailchimpScorer_AllModifiersUseDCTemplateURL(t *testing.T) {
	s := builtinScorerFor(t, "np.mailchimp.1")
	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		assert.Equal(t, "https://{{dc}}.api.mailchimp.com/3.0/", cond.url, "modifier %q", m.Name)
		assert.Equal(t, "GET", cond.method, "modifier %q", m.Name)
		assert.Equal(t, "basic", cond.auth.Type, "modifier %q", m.Name)
		assert.Equal(t, "token", cond.auth.SecretGroup, "modifier %q", m.Name)
	}
}

func TestBuiltinMailchimpScorer_RevokedKeyIsLowestPriority(t *testing.T) {
	s := builtinScorerFor(t, "np.mailchimp.1")
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

func TestBuiltinMailchimpScorer_OnlyRevokedUsesSetScore(t *testing.T) {
	s := builtinScorerFor(t, "np.mailchimp.1")
	for _, m := range s.Modifiers {
		if m.Kind == ModifierKindSetScore {
			assert.Equal(t, "revoked-key", m.Name,
				"only revoked-key should use set_score")
		}
	}
}

func TestBuiltinMailchimpScorer_FreePlanChecksCorrectValue(t *testing.T) {
	s := builtinScorerFor(t, "np.mailchimp.1")
	for _, m := range s.Modifiers {
		if m.Name != "free-plan" {
			continue
		}
		cond, ok := m.Condition.(*httpCondition)
		require.True(t, ok)
		leaf, ok := cond.firesWhen.(*jsonPathEqualsLeaf)
		require.True(t, ok, "free-plan should use json_path_equals")
		assert.Equal(t, ".pricing_plan_type", leaf.Path)
		assert.Equal(t, "forever_free", leaf.Value)
		return
	}
	t.Fatal("free-plan modifier not found")
}

func TestBuiltinMailchimpScorer_SubscriberModifiersCheckCorrectPath(t *testing.T) {
	s := builtinScorerFor(t, "np.mailchimp.1")
	seen := map[string]bool{}
	for _, m := range s.Modifiers {
		switch m.Name {
		case "significant-subscribers":
			cond, ok := m.Condition.(*httpCondition)
			require.True(t, ok)
			leaf, ok := cond.firesWhen.(*jsonPathMatchesLeaf)
			require.True(t, ok, "significant-subscribers should use json_path_matches")
			assert.Equal(t, ".total_subscribers", leaf.Path)
			seen[m.Name] = true
		case "no-subscribers":
			cond, ok := m.Condition.(*httpCondition)
			require.True(t, ok)
			leaf, ok := cond.firesWhen.(*jsonPathEqualsLeaf)
			require.True(t, ok, "no-subscribers should use json_path_equals")
			assert.Equal(t, ".total_subscribers", leaf.Path)
			seen[m.Name] = true
		}
	}
	assert.True(t, seen["significant-subscribers"], "significant-subscribers not found")
	assert.True(t, seen["no-subscribers"], "no-subscribers not found")
}

func TestBuiltinMailchimpScorer_RevokedKeyCovers403(t *testing.T) {
	s := builtinScorerFor(t, "np.mailchimp.1")
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

func TestBuiltinMailchimpScorer_ModifierCount(t *testing.T) {
	s := builtinScorerFor(t, "np.mailchimp.1")
	assert.Len(t, s.Modifiers, 4)
}
