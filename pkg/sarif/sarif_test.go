package sarif

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewReport(t *testing.T) {
	report := NewReport()

	assert.Equal(t, SchemaURI, report.Schema)
	assert.Equal(t, Version, report.Version)
	assert.NotNil(t, report.Runs)
	assert.Len(t, report.Runs, 1)
	assert.Equal(t, ToolName, report.Runs[0].Tool.Driver.Name)
	assert.Equal(t, ToolVersion, report.Runs[0].Tool.Driver.Version)
}

func TestAddRule(t *testing.T) {
	report := NewReport()

	rule := &types.Rule{
		ID:          "np.aws.1",
		Name:        "AWS API Key",
		Description: "Detects AWS API keys",
		References:  []string{"https://docs.aws.amazon.com"},
	}

	report.AddRule(rule)

	assert.Len(t, report.Runs[0].Tool.Driver.Rules, 1)
	sarifRule := report.Runs[0].Tool.Driver.Rules[0]
	assert.Equal(t, "np.aws.1", sarifRule.ID)
	assert.Equal(t, "AWS API Key", sarifRule.Name)
	assert.Equal(t, "Detects AWS API keys", sarifRule.ShortDescription.Text)
}

func TestAddResult(t *testing.T) {
	report := NewReport()

	rule := &types.Rule{
		ID:   "np.aws.1",
		Name: "AWS API Key",
	}
	report.AddRule(rule)

	match := &types.Match{
		RuleID:   "np.aws.1",
		RuleName: "AWS API Key",
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 100, End: 120},
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 10, Column: 5},
				End:   types.SourcePoint{Line: 10, Column: 25},
			},
		},
		Snippet: types.Snippet{
			Matching: []byte("AKIATESTFAKEKEY12345"),
		},
	}

	filePath := "/path/to/secrets.txt"
	report.AddResult(match, filePath)

	assert.Len(t, report.Runs[0].Results, 1)
	result := report.Runs[0].Results[0]
	assert.Equal(t, "np.aws.1", result.RuleID)
	assert.Equal(t, "warning", result.Level)
	assert.Len(t, result.Locations, 1)

	location := result.Locations[0]
	assert.Equal(t, "file:///path/to/secrets.txt", location.PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, 10, location.PhysicalLocation.Region.StartLine)
	assert.Equal(t, 5, location.PhysicalLocation.Region.StartColumn)
	assert.Equal(t, 10, location.PhysicalLocation.Region.EndLine)
	assert.Equal(t, 25, location.PhysicalLocation.Region.EndColumn)
}

func TestToJSON(t *testing.T) {
	report := NewReport()

	rule := &types.Rule{
		ID:          "np.aws.1",
		Name:        "AWS API Key",
		Description: "Detects AWS API keys",
	}
	report.AddRule(rule)

	match := &types.Match{
		RuleID:   "np.aws.1",
		RuleName: "AWS API Key",
		Location: types.Location{
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 10, Column: 5},
				End:   types.SourcePoint{Line: 10, Column: 25},
			},
		},
		Snippet: types.Snippet{
			Matching: []byte("AKIATESTFAKEKEY12345"),
		},
	}
	report.AddResult(match, "/test/file.txt")

	jsonBytes, err := report.ToJSON()
	require.NoError(t, err)

	// Verify it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal(jsonBytes, &parsed)
	require.NoError(t, err)

	// Check schema is present
	assert.Contains(t, parsed, "$schema")
	assert.Equal(t, SchemaURI, parsed["$schema"])

	// Check version
	assert.Equal(t, Version, parsed["version"])
}

func TestMultipleResults(t *testing.T) {
	report := NewReport()

	awsRule := &types.Rule{ID: "np.aws.1", Name: "AWS API Key"}
	githubRule := &types.Rule{ID: "np.github.1", Name: "GitHub PAT"}

	report.AddRule(awsRule)
	report.AddRule(githubRule)

	match1 := &types.Match{
		RuleID: "np.aws.1",
		Location: types.Location{
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 10, Column: 1},
				End:   types.SourcePoint{Line: 10, Column: 20},
			},
		},
	}
	match2 := &types.Match{
		RuleID: "np.github.1",
		Location: types.Location{
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 20, Column: 1},
				End:   types.SourcePoint{Line: 20, Column: 40},
			},
		},
	}

	report.AddResult(match1, "/file1.txt")
	report.AddResult(match2, "/file2.txt")

	assert.Len(t, report.Runs[0].Tool.Driver.Rules, 2)
	assert.Len(t, report.Runs[0].Results, 2)
}

func TestRelativePathConversion(t *testing.T) {
	report := NewReport()

	rule := &types.Rule{ID: "test", Name: "Test"}
	report.AddRule(rule)

	match := &types.Match{
		RuleID: "test",
		Location: types.Location{
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 1, Column: 1},
				End:   types.SourcePoint{Line: 1, Column: 10},
			},
		},
	}

	// Test absolute path
	report.AddResult(match, "/absolute/path/file.txt")
	assert.Equal(t, "file:///absolute/path/file.txt", report.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)

	// Test relative path
	report.AddResult(match, "relative/path/file.txt")
	assert.Equal(t, "relative/path/file.txt", report.Runs[0].Results[1].Locations[0].PhysicalLocation.ArtifactLocation.URI)
}

func TestAddResult_WithScore_EmitsPropertiesAndLevel(t *testing.T) {
	r := NewReport()
	match := &types.Match{
		RuleID:   "np.aws.1",
		RuleName: "AWS API Key",
		Location: types.Location{
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 10, Column: 5},
				End:   types.SourcePoint{Line: 10, Column: 25},
			},
		},
		Snippet: types.Snippet{Matching: []byte("AKIAIOSFODNN7EXAMPLE")},
	}
	score := &types.Score{
		Final:             85,
		Base:              60,
		SuggestedSeverity: "critical",
		Applied:           []types.ScoreModifier{},
	}
	r.AddResultWithScore(match, "/path/to/file.txt", score)

	require.Len(t, r.Runs[0].Results, 1)
	res := r.Runs[0].Results[0]

	// score 85 → level "error"
	assert.Equal(t, "error", res.Level, "Level should be 'error' for score 85")
	require.NotNil(t, res.Properties, "Properties should not be nil")
	assert.Equal(t, "8.5", res.Properties.SecuritySeverity)
	require.NotNil(t, res.Properties.TitusScore, "TitusScore should not be nil")
	assert.Equal(t, 85, res.Properties.TitusScore.Final)
}

func TestLevelForScore(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "none"}, {19, "none"},
		{20, "note"}, {39, "note"},
		{40, "warning"}, {59, "warning"},
		{60, "error"}, {99, "error"}, {100, "error"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, LevelForScore(c.score), "LevelForScore(%d)", c.score)
	}
}

func TestSnippetInRegion(t *testing.T) {
	report := NewReport()

	rule := &types.Rule{ID: "test", Name: "Test"}
	report.AddRule(rule)

	match := &types.Match{
		RuleID: "test",
		Location: types.Location{
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 5, Column: 10},
				End:   types.SourcePoint{Line: 5, Column: 30},
			},
		},
		Snippet: types.Snippet{
			Before:   []byte("prefix: "),
			Matching: []byte("SECRET_VALUE_HERE"),
			After:    []byte(" suffix"),
		},
	}

	report.AddResult(match, "/test.txt")

	region := report.Runs[0].Results[0].Locations[0].PhysicalLocation.Region
	assert.NotNil(t, region.Snippet)
	assert.Equal(t, "SECRET_VALUE_HERE", region.Snippet.Text)
}
