package scoring

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

// Confirms the basic Scorer/Modifier types exist with the expected shape.
func TestScorer_BasicShape(t *testing.T) {
	m := Modifier{
		Name:      "test",
		Priority:  50,
		Kind:      ModifierKindDelta,
		Value:     10,
		Condition: &matchLengthCondition{Op: matchLengthOpGT, Value: 0},
	}
	s := &Scorer{Name: "test-scorer", RuleIDs: []string{"np.test.1"}, Modifiers: []Modifier{m}}
	assert.Equal(t, "test-scorer", s.Name)
	assert.True(t, s.canScore("np.test.1"))
	assert.False(t, s.canScore("np.other.1"))

	// Match is unused here but the types must line up.
	_ = &types.Match{}
}
