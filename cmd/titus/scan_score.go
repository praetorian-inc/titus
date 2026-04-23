package main

import (
	"github.com/praetorian-inc/titus/pkg/types"
)

// synthesizeBaseScore creates a Score from a rule's BaseScore with no modifiers
// applied. This is the Milestone 1 scoring — the modifier engine lands in M2+.
func synthesizeBaseScore(rule *types.Rule) *types.Score {
	return &types.Score{
		Final:             rule.BaseScore,
		Base:              rule.BaseScore,
		SuggestedSeverity: types.SeverityForScore(rule.BaseScore),
		Applied:           []types.ScoreModifier{},
	}
}
