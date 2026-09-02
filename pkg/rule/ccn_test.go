package rule

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ccnMatchesInput(t *testing.T, rule *types.Rule, input string) bool {
	t.Helper()
	m, err := matcher.New(matcher.Config{
		Rules:        []*types.Rule{rule},
		ContextLines: 0,
	})
	require.NoError(t, err)
	matches, err := m.Match([]byte(input))
	require.NoError(t, err)
	return len(matches) > 0
}

func loadCCNRule(t *testing.T, id string) *types.Rule {
	t.Helper()
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)
	r := findRule(rules, id)
	require.NotNil(t, r, "rule %s not found", id)
	return r
}

func TestCCN_VisaCreditCard(t *testing.T) {
	rule := loadCCNRule(t, "np.ccn.1")
	assert.Equal(t, "Credit Card Number (Visa)", rule.Name)
	assert.True(t, rule.Noisy)
	assert.Equal(t, 25, rule.BaseScore)

	assert.True(t, ccnMatchesInput(t, rule, `card_number = "4532015112830366"`))
	assert.True(t, ccnMatchesInput(t, rule, `visa: 4916-3385-0728-9460`))

	assert.False(t, ccnMatchesInput(t, rule, `test_card = "4111111111111111"`))
	assert.False(t, ccnMatchesInput(t, rule, `test_card = "4111-1111-1111-1111"`))
	assert.False(t, ccnMatchesInput(t, rule, `test_card = "4242424242424242"`))
	assert.False(t, ccnMatchesInput(t, rule, `test_card = "4242-4242-4242-4242"`))
}

func TestCCN_MastercardCreditCard(t *testing.T) {
	rule := loadCCNRule(t, "np.ccn.2")
	assert.True(t, rule.Noisy)

	assert.True(t, ccnMatchesInput(t, rule, `mc_card = "5425233430109903"`))
	assert.False(t, ccnMatchesInput(t, rule, `test_card = "5555555555554444"`))
}

func TestCCN_AmexCreditCard(t *testing.T) {
	rule := loadCCNRule(t, "np.ccn.3")
	assert.True(t, rule.Noisy)

	assert.True(t, ccnMatchesInput(t, rule, `amex = "378734493671000"`))
	assert.False(t, ccnMatchesInput(t, rule, `test_amex = "378282246310005"`))
}

func TestCCN_DiscoverCreditCard(t *testing.T) {
	rule := loadCCNRule(t, "np.ccn.4")
	assert.True(t, rule.Noisy)

	assert.True(t, ccnMatchesInput(t, rule, `discover = "6011514433546201"`))
	assert.False(t, ccnMatchesInput(t, rule, `test_discover = "6011111111111117"`))
}

func TestCCN_AllRulesInDefaultRuleset(t *testing.T) {
	loader := NewLoader()
	rulesets, err := loader.LoadBuiltinRulesets()
	require.NoError(t, err)

	var defaultRS *types.Ruleset
	for _, rs := range rulesets {
		if rs.ID == "default" {
			defaultRS = rs
			break
		}
	}
	require.NotNil(t, defaultRS, "default ruleset should exist")

	ccnIDs := []string{
		"np.ccn.1", "np.ccn.2", "np.ccn.3", "np.ccn.4",
	}

	ruleIDSet := make(map[string]bool, len(defaultRS.RuleIDs))
	for _, id := range defaultRS.RuleIDs {
		ruleIDSet[id] = true
	}

	for _, id := range ccnIDs {
		assert.True(t, ruleIDSet[id], "CCN rule %s should be in default ruleset", id)
	}
}

func TestCCN_AllRulesAreNoisy(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	for _, r := range rules {
		if len(r.ID) > 7 && r.ID[:7] == "np.ccn." {
			assert.True(t, r.Noisy, "CCN rule %s should be marked noisy", r.ID)
		}
	}
}
