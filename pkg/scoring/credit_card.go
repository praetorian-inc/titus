package scoring

import (
	"context"

	"github.com/praetorian-inc/titus/pkg/types"
)

// luhnCheck returns true if digits passes the Luhn algorithm (ISO/IEC 7812-1).
func luhnCheck(digits []byte) bool {
	if len(digits) < 13 {
		return false
	}
	var sum int
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// stripCardSeparators removes hyphens and spaces from the captured card group.
func stripCardSeparators(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	for _, b := range raw {
		if b != '-' && b != ' ' {
			out = append(out, b)
		}
	}
	return out
}

// ccFailsLuhnCondition fires when the captured card number does NOT pass
// the Luhn checksum — meaning it is not a valid credit card number.
type ccFailsLuhnCondition struct{}

func (c *ccFailsLuhnCondition) Evaluate(_ context.Context, m *types.Match) (bool, error) {
	if m == nil {
		return false, nil
	}
	raw, ok := m.NamedGroups["card"]
	if !ok || len(raw) == 0 {
		return false, nil
	}
	digits := stripCardSeparators(raw)
	return !luhnCheck(digits), nil
}

// CreditCardGoScorer returns the credit card number (CCN) scoring configuration.
// It zeros the score for captured numbers that fail the Luhn checksum,
// eliminating false positives from non-card digit sequences.
func CreditCardGoScorer() *Scorer {
	return &Scorer{
		Name:    "ccn-luhn",
		RuleIDs: []string{"np.ccn.1", "np.ccn.2", "np.ccn.3", "np.ccn.4"},
		Modifiers: []Modifier{
			{
				Name:      "fails-luhn",
				Priority:  100,
				Kind:      ModifierKindSetScore,
				Value:     0,
				Condition: &ccFailsLuhnCondition{},
			},
		},
	}
}
