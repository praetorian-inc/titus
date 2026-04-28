package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeverityForScore(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "info"}, {10, "info"}, {19, "info"}, {20, "info"},
		{21, "low"}, {30, "low"}, {39, "low"}, {40, "low"},
		{41, "medium"}, {50, "medium"}, {59, "medium"}, {60, "medium"},
		{61, "high"}, {70, "high"}, {79, "high"}, {80, "high"},
		{81, "critical"}, {90, "critical"}, {100, "critical"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, SeverityForScore(c.score), "SeverityForScore(%d)", c.score)
	}
}

func TestSeverityForScore_OutOfRange(t *testing.T) {
	assert.Equal(t, "info", SeverityForScore(-5), "SeverityForScore(-5) should clamp to info")
	assert.Equal(t, "critical", SeverityForScore(150), "SeverityForScore(150) should clamp to critical")
}

func TestScore_JSONSerialization(t *testing.T) {
	s := &Score{
		Final:             85,
		Base:              60,
		SuggestedSeverity: "critical",
		Applied: []ScoreModifier{
			{Name: "iam-admin", Scorer: "aws", Kind: "set_score", Value: 95, Priority: 50},
		},
	}
	data, err := json.Marshal(s)
	require.NoError(t, err)

	want := `{"Final":85,"Base":60,"SuggestedSeverity":"critical","Applied":[{"Name":"iam-admin","Scorer":"aws","Kind":"set_score","Value":95,"Priority":50}]}`
	assert.Equal(t, want, string(data))
}

func TestScore_EmptyAppliedSerializesAsEmptyArray(t *testing.T) {
	s := &Score{Final: 50, Base: 50, SuggestedSeverity: "medium", Applied: []ScoreModifier{}}
	data, err := json.Marshal(s)
	require.NoError(t, err)

	// Must contain "Applied":[] not "Applied":null
	assert.Contains(t, string(data), `"Applied":[]`)
}
