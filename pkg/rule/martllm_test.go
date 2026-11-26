package rule

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// martllmFakeKey is a clearly synthetic MartLLM key: the real "ull_" prefix
// followed by 43 base62 characters that are obviously not a credential.
const martllmFakeKey = "ull_EXAMPLEkeyDoNotUse4mZ9vT2kL8nR3pW6xY1bC5dQ7"

func loadMartLLMRule(t *testing.T) *types.Rule {
	t.Helper()
	rules, err := NewLoader().LoadBuiltinRules()
	require.NoError(t, err)

	for _, r := range rules {
		if r.ID == "kingfisher.martllm.1" {
			return r
		}
	}
	t.Fatal("kingfisher.martllm.1 is missing from the built-in rule set")
	return nil
}

func TestMartLLMRule_Metadata(t *testing.T) {
	r := loadMartLLMRule(t)

	assert.Equal(t, "MartLLM API Key", r.Name)
	assert.Equal(t, 65, r.BaseScore)
	assert.Contains(t, r.Categories, "api")
	assert.Contains(t, r.Categories, "secret")
	assert.InDelta(t, 3.5, r.MinEntropy, 0.0001)
	assert.Contains(t, r.References, "https://martllm.com/docs/quickstart")
}

func TestMartLLMRule_DetectsKeyShapes(t *testing.T) {
	require.Len(t, martllmFakeKey, 47, "ull_ + 43 base62 characters")

	m, err := matcher.NewPortableRegexp([]*types.Rule{loadMartLLMRule(t)}, 0, nil)
	require.NoError(t, err)

	cases := []struct {
		name   string
		input  string
		expect bool
	}{
		{"bare key", martllmFakeKey, true},
		{"bearer header", "Authorization: Bearer " + martllmFakeKey, true},
		{"env assignment", "MARTLLM_API_KEY=" + martllmFakeKey, true},
		{"quoted config", `api_key = "` + martllmFakeKey + `"`, true},
		{"prefix only", "MARTLLM_API_KEY=ull_", false},
		{"body one short", "MARTLLM_API_KEY=" + martllmFakeKey[:len(martllmFakeKey)-1], false},
		{"body one long", "MARTLLM_API_KEY=" + martllmFakeKey + "a", false},
		{"unrelated token", "ghp_0000111122223333444455556666777788889999", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.input))
			require.NoError(t, err)

			if !tc.expect {
				assert.Empty(t, matches, "unexpected match for %q", tc.input)
				return
			}
			require.NotEmpty(t, matches, "expected a match for %q", tc.input)
			require.NotEmpty(t, matches[0].NamedGroups)
			assert.Equal(t, martllmFakeKey, string(matches[0].NamedGroups["key"]),
				"the named group must capture exactly the key, with no surrounding text")
		})
	}
}

func TestMartLLMRule_IncludedInDefaultRuleset(t *testing.T) {
	rulesets, err := NewLoader().LoadBuiltinRulesets()
	require.NoError(t, err)

	var def *types.Ruleset
	for _, rs := range rulesets {
		if rs.ID == "default" {
			def = rs
			break
		}
	}
	require.NotNil(t, def, "default ruleset must exist")
	assert.Contains(t, def.RuleIDs, "kingfisher.martllm.1")
}
