package store

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_AddFinding_PreservesScore(t *testing.T) {
	s := NewMemory()
	finding := &types.Finding{
		ID:     "abc",
		RuleID: "np.aws.1",
		Score: &types.Score{
			Final: 85, Base: 60, SuggestedSeverity: "critical",
			Applied: []types.ScoreModifier{},
		},
	}
	require.NoError(t, s.AddFinding(finding))
	findings, err := s.GetFindings()
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.NotNil(t, findings[0].Score, "Score not preserved through memory store")
	assert.Equal(t, 85, findings[0].Score.Final)
}
