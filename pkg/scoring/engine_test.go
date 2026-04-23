package scoring

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

// Confirms the basic Scorer/Modifier types exist with the expected shape.
// This test also acts as a compile-time guard for engine_test.go imports.
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

func TestEngine_NoScorerRegistered_ReturnsBaseOnly(t *testing.T) {
	engine := NewEngine(nil)
	rule := &types.Rule{ID: "np.test.1", BaseScore: 50}
	finding := &types.Finding{ID: "f1", RuleID: rule.ID}
	match := &types.Match{RuleID: rule.ID}

	score := engine.Score(finding, []*types.Match{match}, rule)

	assert.Equal(t, 50, score.Final)
	assert.Equal(t, 50, score.Base)
	assert.Equal(t, "medium", score.SuggestedSeverity)
	assert.Empty(t, score.Applied)
}

func TestEngine_NoMatchingScorer_ReturnsBaseOnly(t *testing.T) {
	scorer := &Scorer{
		Name:    "other-scorer",
		RuleIDs: []string{"np.other.1"},
		Modifiers: []Modifier{{
			Name: "unused", Kind: ModifierKindDelta, Value: 100,
			Condition: &matchLengthCondition{Op: matchLengthOpGT, Value: 0},
		}},
	}
	engine := NewEngine([]*Scorer{scorer})
	rule := &types.Rule{ID: "np.test.1", BaseScore: 30}
	finding := &types.Finding{ID: "f1", RuleID: rule.ID}

	score := engine.Score(finding, []*types.Match{{}}, rule)

	assert.Equal(t, 30, score.Final)
	assert.Empty(t, score.Applied)
}
