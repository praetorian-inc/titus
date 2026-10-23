package rule

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// orcaFakeKey is a clearly synthetic OrcaRouter key: the real "sk-orca-"
// prefix followed by a body that is obviously not a credential.
const orcaFakeKey = "sk-orca-TEST-ONLY-000011112222333344445555"

func loadOrcaRouterRule(t *testing.T) *types.Rule {
	t.Helper()
	rules, err := NewLoader().LoadBuiltinRules()
	require.NoError(t, err)

	for _, r := range rules {
		if r.ID == "kingfisher.orcarouter.1" {
			return r
		}
	}
	t.Fatal("kingfisher.orcarouter.1 is missing from the built-in rule set")
	return nil
}

func TestOrcaRouterRule_Metadata(t *testing.T) {
	r := loadOrcaRouterRule(t)

	assert.Equal(t, "OrcaRouter Cyber Inference API Key", r.Name)
	assert.Equal(t, 70, r.BaseScore)
	assert.Contains(t, r.Categories, "api")
	assert.Contains(t, r.Categories, "secret")
	assert.InDelta(t, 3.5, r.MinEntropy, 0.0001)

	// The rule documents the provider it validates against.
	assert.Contains(t, r.References, "https://www.orcarouter.ai/cyber")
	assert.Contains(t, r.References, "https://www.orcarouter.ai/models?tier=cyber")
}

func TestOrcaRouterRule_DetectsKeyShapes(t *testing.T) {
	m, err := matcher.NewPortableRegexp([]*types.Rule{loadOrcaRouterRule(t)}, 0, nil)
	require.NoError(t, err)

	cases := []struct {
		name   string
		input  string
		expect bool
	}{
		{"bare key", orcaFakeKey, true},
		{"bearer header", "Authorization: Bearer " + orcaFakeKey, true},
		{"env assignment", "ORCAROUTER_API_KEY=" + orcaFakeKey, true},
		{"quoted config", `api_key = "` + orcaFakeKey + `"`, true},
		{"prefix only", "ORCAROUTER_API_KEY=sk-orca-", false},
		{"body below minimum length", "ORCAROUTER_API_KEY=sk-orca-short", false},
		{"placeholder", "ORCAROUTER_API_KEY=sk-orca-REPLACE_WITH_YOUR_KEY", false},
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
			assert.Equal(t, orcaFakeKey, string(matches[0].NamedGroups["key"]),
				"the named group must capture exactly the key, with no surrounding text")
		})
	}
}

func TestOrcaRouterRule_IncludedInDefaultRuleset(t *testing.T) {
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
	assert.Contains(t, def.RuleIDs, "kingfisher.orcarouter.1",
		"OrcaRouter keys should be detected by the default (high-precision) ruleset")
}
