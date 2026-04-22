package main

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSynthesizeScore_FromRuleBaseScore is a table-driven test for the pure function
// that will live alongside runScan. It's tested here because the integration path
// (runScan end-to-end) requires scaffolding; the pure function captures the logic.
func TestSynthesizeScore_FromRuleBaseScore(t *testing.T) {
	cases := []struct {
		name string
		rule *types.Rule
		want *types.Score
	}{
		{
			name: "critical tier",
			rule: &types.Rule{ID: "np.aws.1", BaseScore: 85},
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
			got := synthesizeBaseScore(c.rule)
			assert.Equal(t, c.want.Final, got.Final)
			assert.Equal(t, c.want.Base, got.Base)
			assert.Equal(t, c.want.SuggestedSeverity, got.SuggestedSeverity)
			require.NotNil(t, got.Applied, "Applied must be non-nil (empty slice) for stable JSON")
		})
	}
}
