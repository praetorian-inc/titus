package rule

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetoolWorkflowKey(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)
	rulesets, err := loader.LoadBuiltinRulesets()
	require.NoError(t, err)
	defaults := FindRuleset(rulesets, "default")
	require.NotNil(t, defaults)

	var retool *types.Rule
	for _, r := range ApplyRuleset(rules, defaults) {
		if r.ID == "np.retool.1" {
			retool = r
			break
		}
	}
	require.NotNil(t, retool, "Retool keys must be detected by the default ruleset")
	m, err := matcher.NewPortableRegexp([]*types.Rule{retool}, 0, nil)
	require.NoError(t, err)
	defer m.Close()

	for _, example := range retool.Examples {
		t.Run(example, func(t *testing.T) {
			matches, err := m.Match([]byte(example))
			require.NoError(t, err)
			require.Len(t, matches, 1)
			require.Len(t, matches[0].Groups, 1)
			assert.Equal(t, "retool_wk_0123456789abcdef0123456789abcdef", string(matches[0].Groups[0]))
		})
	}
	for _, example := range retool.NegativeExamples {
		t.Run(example, func(t *testing.T) {
			matches, err := m.Match([]byte(example))
			require.NoError(t, err)
			assert.Empty(t, matches)
		})
	}
}
