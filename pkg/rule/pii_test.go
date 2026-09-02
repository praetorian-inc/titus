package rule

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func piiMatchesInput(t *testing.T, rule *types.Rule, input string) bool {
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

func loadPIIRule(t *testing.T, id string) *types.Rule {
	t.Helper()
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)
	r := findRule(rules, id)
	require.NotNil(t, r, "rule %s not found", id)
	return r
}

func TestPII_VisaCreditCard(t *testing.T) {
	rule := loadPIIRule(t, "np.pii.cc.1")
	assert.Equal(t, "Credit Card Number (Visa)", rule.Name)
	assert.True(t, rule.Noisy)
	assert.Equal(t, 25, rule.BaseScore)

	assert.True(t, piiMatchesInput(t, rule, `card_number = "4532015112830366"`))
	assert.True(t, piiMatchesInput(t, rule, `visa: 4916-3385-0728-9460`))

	assert.False(t, piiMatchesInput(t, rule, `test_card = "4111111111111111"`))
	assert.False(t, piiMatchesInput(t, rule, `test_card = "4111-1111-1111-1111"`))
	assert.False(t, piiMatchesInput(t, rule, `test_card = "4242424242424242"`))
	assert.False(t, piiMatchesInput(t, rule, `test_card = "4242-4242-4242-4242"`))
}

func TestPII_MastercardCreditCard(t *testing.T) {
	rule := loadPIIRule(t, "np.pii.cc.2")
	assert.True(t, rule.Noisy)

	assert.True(t, piiMatchesInput(t, rule, `mc_card = "5425233430109903"`))
	assert.False(t, piiMatchesInput(t, rule, `test_card = "5555555555554444"`))
}

func TestPII_AmexCreditCard(t *testing.T) {
	rule := loadPIIRule(t, "np.pii.cc.3")
	assert.True(t, rule.Noisy)

	assert.True(t, piiMatchesInput(t, rule, `amex = "378734493671000"`))
	assert.False(t, piiMatchesInput(t, rule, `test_amex = "378282246310005"`))
}

func TestPII_DiscoverCreditCard(t *testing.T) {
	rule := loadPIIRule(t, "np.pii.cc.4")
	assert.True(t, rule.Noisy)

	assert.True(t, piiMatchesInput(t, rule, `discover = "6011514433546201"`))
	assert.False(t, piiMatchesInput(t, rule, `test_discover = "6011111111111117"`))
}

func TestPII_SSN(t *testing.T) {
	rule := loadPIIRule(t, "np.pii.ssn.1")
	assert.Equal(t, 30, rule.BaseScore)
	assert.True(t, rule.Noisy)

	assert.True(t, piiMatchesInput(t, rule, `ssn = "267-43-9185"`))
	assert.True(t, piiMatchesInput(t, rule, `social_security: 431 98 2134`))

	assert.False(t, piiMatchesInput(t, rule, `ssn = "123-45-6789"`))
	assert.False(t, piiMatchesInput(t, rule, `ssn = "000-12-3456"`))
	assert.False(t, piiMatchesInput(t, rule, `ssn = "666-12-3456"`))
	assert.False(t, piiMatchesInput(t, rule, `ssn = "900-12-3456"`))
	assert.False(t, piiMatchesInput(t, rule, `ssn = "123-00-3456"`))
	assert.False(t, piiMatchesInput(t, rule, `ssn = "123-45-0000"`))
	assert.False(t, piiMatchesInput(t, rule, `ssn = "111-11-1111"`))
}

func TestPII_AllRulesInDefaultRuleset(t *testing.T) {
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

	piiIDs := []string{
		"np.pii.cc.1", "np.pii.cc.2", "np.pii.cc.3", "np.pii.cc.4",
		"np.pii.ssn.1",
	}

	ruleIDSet := make(map[string]bool, len(defaultRS.RuleIDs))
	for _, id := range defaultRS.RuleIDs {
		ruleIDSet[id] = true
	}

	for _, id := range piiIDs {
		assert.True(t, ruleIDSet[id], "PII rule %s should be in default ruleset", id)
	}
}

func TestPII_AllRulesAreNoisy(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	for _, r := range rules {
		if len(r.ID) > 7 && r.ID[:7] == "np.pii." {
			assert.True(t, r.Noisy, "PII rule %s should be marked noisy", r.ID)
		}
	}
}
