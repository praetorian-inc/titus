package main

import (
	"context"
	"testing"

	"github.com/praetorian-inc/titus/pkg/scoring"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildScoringEngine_BaseScoreOnly verifies that for rules with no
// matching scorer, the engine returns the rule's BaseScore unmodified with
// an empty Applied slice (matching the M1 synthesizeBaseScore behavior).
func TestBuildScoringEngine_BaseScoreOnly(t *testing.T) {
	engine, err := buildScoringEngine()
	require.NoError(t, err)
	require.NotNil(t, engine)

	cases := []struct {
		name string
		rule *types.Rule
		want *types.Score
	}{
		{
			name: "critical tier — no scorer for this rule",
			rule: &types.Rule{ID: "np.unscored.1", BaseScore: 85},
			want: &types.Score{Final: 85, Base: 85, SuggestedSeverity: "critical", Applied: []types.ScoreModifier{}},
		},
		{
			name: "low tier",
			rule: &types.Rule{ID: "np.linkedin.1", BaseScore: 25},
			want: &types.Score{Final: 25, Base: 25, SuggestedSeverity: "low", Applied: []types.ScoreModifier{}},
		},
		{
			name: "zero base score (unscored rule, legacy)",
			rule: &types.Rule{ID: "np.old.1", BaseScore: 0},
			want: &types.Score{Final: 0, Base: 0, SuggestedSeverity: "info", Applied: []types.ScoreModifier{}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Pass a match with no named groups — no modifier will fire.
			match := &types.Match{RuleID: c.rule.ID, NamedGroups: map[string][]byte{}}
			got := engine.Score(context.Background(), &types.Finding{RuleID: c.rule.ID}, []*types.Match{match}, c.rule)
			assert.Equal(t, c.want.Final, got.Final)
			assert.Equal(t, c.want.Base, got.Base)
			assert.Equal(t, c.want.SuggestedSeverity, got.SuggestedSeverity)
			require.NotNil(t, got.Applied, "Applied must be non-nil (empty slice) for stable JSON")
		})
	}
}


// TestBuildScoringEngine_WithScopeEnabled verifies the engine builds without
// error when --score-scope is enabled.
func TestBuildScoringEngine_WithScopeEnabled(t *testing.T) {
	// Save/restore global flag state
	origScope := scanScopeEnabled
	origTimeout := scanScoreTimeout
	origBudget := scanScoreBudget
	defer func() {
		scanScopeEnabled = origScope
		scanScoreTimeout = origTimeout
		scanScoreBudget = origBudget
	}()
	scanScopeEnabled = true

	eng, err := buildScoringEngine()
	require.NoError(t, err)
	require.NotNil(t, eng)
	// Engine is opaque; just verify it builds without error when scope is enabled.
}

// stubScoringEngine implements scoringEngineInterface for use in unit tests
// that need to inject a controlled engine without loading real scorers.
type stubScoringEngine struct {
	score *types.Score
	stats scoring.HTTPModifierStats
}

func (s *stubScoringEngine) Score(_ context.Context, _ *types.Finding, _ []*types.Match, _ *types.Rule) *types.Score {
	return s.score
}

func (s *stubScoringEngine) Stats() scoring.HTTPModifierStats {
	return s.stats
}
