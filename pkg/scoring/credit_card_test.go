package scoring

import (
	"context"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		name   string
		digits string
		valid  bool
	}{
		{"visa valid", "4532015112830366", true},
		{"visa test 4111", "4111111111111111", true},
		{"mastercard valid", "5425233430109903", true},
		{"amex valid", "378734493671000", true},
		{"discover valid", "6011514433546201", true},
		{"random digits", "1234567890123456", false},
		{"all zeros", "0000000000000000", true},
		{"short", "123456", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, luhnCheck([]byte(tt.digits)))
		})
	}
}

func TestStripCardSeparators(t *testing.T) {
	assert.Equal(t, []byte("4111111111111111"), stripCardSeparators([]byte("4111-1111-1111-1111")))
	assert.Equal(t, []byte("4111111111111111"), stripCardSeparators([]byte("4111 1111 1111 1111")))
	assert.Equal(t, []byte("4532015112830366"), stripCardSeparators([]byte("4532015112830366")))
}

func TestCCFailsLuhnCondition_ValidCard(t *testing.T) {
	cond := &ccFailsLuhnCondition{}
	m := &types.Match{
		NamedGroups: map[string][]byte{"card": []byte("4532015112830366")},
	}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.False(t, fired, "valid card should not fire fails-luhn")
}

func TestCCFailsLuhnCondition_ValidCardFormatted(t *testing.T) {
	cond := &ccFailsLuhnCondition{}
	m := &types.Match{
		NamedGroups: map[string][]byte{"card": []byte("4532-0151-1283-0366")},
	}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.False(t, fired, "valid formatted card should not fire fails-luhn")
}

func TestCCFailsLuhnCondition_InvalidCard(t *testing.T) {
	cond := &ccFailsLuhnCondition{}
	m := &types.Match{
		NamedGroups: map[string][]byte{"card": []byte("1234567890123456")},
	}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.True(t, fired, "invalid card should fire fails-luhn")
}

func TestCCFailsLuhnCondition_InvalidCardFormatted(t *testing.T) {
	cond := &ccFailsLuhnCondition{}
	m := &types.Match{
		NamedGroups: map[string][]byte{"card": []byte("1234-5678-9012-3456")},
	}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.True(t, fired, "invalid formatted card should fire fails-luhn")
}

func TestCCFailsLuhnCondition_NilMatch(t *testing.T) {
	cond := &ccFailsLuhnCondition{}
	fired, err := cond.Evaluate(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestCCFailsLuhnCondition_MissingGroup(t *testing.T) {
	cond := &ccFailsLuhnCondition{}
	m := &types.Match{
		NamedGroups: map[string][]byte{"token": []byte("something")},
	}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestCreditCardGoScorer_Structure(t *testing.T) {
	s := CreditCardGoScorer()
	assert.Equal(t, "ccn-luhn", s.Name)
	assert.Equal(t, []string{"np.ccn.1", "np.ccn.2", "np.ccn.3", "np.ccn.4"}, s.RuleIDs)
	require.Len(t, s.Modifiers, 1)
	assert.Equal(t, "fails-luhn", s.Modifiers[0].Name)
	assert.Equal(t, ModifierKindSetScore, s.Modifiers[0].Kind)
	assert.Equal(t, 0, s.Modifiers[0].Value)
	assert.False(t, s.Modifiers[0].IsDynamic())
}

func TestCreditCardGoScorer_Integration_ValidCard(t *testing.T) {
	scorers := []*Scorer{CreditCardGoScorer()}
	engine := NewEngine(scorers, EngineConfig{ScopeEnabled: false, Timeout: 5e9})
	rule := &types.Rule{ID: "np.ccn.1", BaseScore: 25}
	finding := &types.Finding{ID: "test", RuleID: "np.ccn.1"}
	match := &types.Match{
		RuleID:      "np.ccn.1",
		NamedGroups: map[string][]byte{"card": []byte("4532015112830366")},
	}
	score := engine.Score(context.Background(), finding, []*types.Match{match}, rule)
	assert.Equal(t, 25, score.Final, "valid Luhn card keeps base score")
}

func TestCreditCardGoScorer_Integration_InvalidCard(t *testing.T) {
	scorers := []*Scorer{CreditCardGoScorer()}
	engine := NewEngine(scorers, EngineConfig{ScopeEnabled: false, Timeout: 5e9})
	rule := &types.Rule{ID: "np.ccn.1", BaseScore: 25}
	finding := &types.Finding{ID: "test", RuleID: "np.ccn.1"}
	match := &types.Match{
		RuleID:      "np.ccn.1",
		NamedGroups: map[string][]byte{"card": []byte("1234567890123456")},
	}
	score := engine.Score(context.Background(), finding, []*types.Match{match}, rule)
	assert.Equal(t, 0, score.Final, "invalid Luhn card zeros score")
}
