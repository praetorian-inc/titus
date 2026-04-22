package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/titus/pkg/sarif"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOutputSARIF_IncludesScoreProperties verifies that AddResultWithScore
// propagates score data into SARIF properties correctly.
func TestOutputSARIF_IncludesScoreProperties(t *testing.T) {
	match := &types.Match{
		RuleID:   "np.aws.1",
		RuleName: "AWS API Key",
		Location: types.Location{
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 1, Column: 1},
				End:   types.SourcePoint{Line: 1, Column: 20},
			},
		},
	}

	score := &types.Score{
		Final:             85,
		Base:              85,
		SuggestedSeverity: "critical",
		Applied:           []types.ScoreModifier{},
	}

	report := sarif.NewReport()
	report.AddResultWithScore(match, "testdata/fake.txt", score)

	data, err := report.ToJSON()
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &parsed))

	runs := parsed["runs"].([]interface{})
	results := runs[0].(map[string]interface{})["results"].([]interface{})
	require.Len(t, results, 1)

	r := results[0].(map[string]interface{})
	assert.Equal(t, "error", r["level"], "score 85 should map to level 'error'")

	props, ok := r["properties"].(map[string]interface{})
	require.True(t, ok, "properties should be present")
	assert.Equal(t, "8.5", props["security-severity"])

	titusScore := props["titus_score"]
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	require.NoError(t, enc.Encode(titusScore))
	assert.Contains(t, buf.String(), `"Final":85`, "titus_score should include Final score")
}
