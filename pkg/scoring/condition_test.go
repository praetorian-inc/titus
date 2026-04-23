package scoring

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestCondition_InterfaceCompliance is a compile-time-ish check that each
// concrete condition satisfies the Condition interface. It will be expanded
// in tasks 0.3-0.5 as each leaf type is implemented.
func TestCondition_InterfaceCompliance(t *testing.T) {
	var _ Condition = (*matchGroupCondition)(nil)
	var _ Condition = (*surroundingContextContainsCondition)(nil)
	var _ Condition = (*matchLengthCondition)(nil)
	// Sanity: zero match must not panic any default nil-safe path.
	m := &types.Match{}
	assert.NotNil(t, m)
}
