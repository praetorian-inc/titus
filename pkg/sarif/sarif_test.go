package sarif

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func occurrenceMatch() *types.Match {
	return &types.Match{
		RuleID:   "np.aws.1",
		RuleName: "AWS API Key",
		Location: types.Location{
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 3, Column: 7},
				End:   types.SourcePoint{Line: 3, Column: 27},
			},
		},
		Snippet: types.Snippet{Matching: []byte("AKIAIOSFODNN7EXAMPLE")},
	}
}

// C-SARIF-1: N locations of a match give N results, each naming its
// repository and commit, each with a distinct location fingerprint (SEC-17).
func TestAddResultForOccurrence_OneResultPerLocation(t *testing.T) {
	date := time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)
	occs := []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CommitDate: date, HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/web", Path: "config.yml", Commit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CommitDate: date, HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/api", Path: "deploy/config.yml", Commit: "cccccccccccccccccccccccccccccccccccccccc", CommitDate: date, HostRecorded: true},
	}
	r := NewReport()
	match := occurrenceMatch()
	for _, o := range occs {
		r.AddResultForOccurrence(match, o, nil)
	}

	results := r.Runs[0].Results
	require.Len(t, results, 3)
	var uris []string
	fingerprints := map[string]bool{}
	for i, res := range results {
		require.Len(t, res.Locations, 1)
		uris = append(uris, res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		assert.Equal(t, 3, res.Locations[0].PhysicalLocation.Region.StartLine)
		require.NotNil(t, res.Properties)
		assert.Equal(t, occs[i].Repository, res.Properties.Repository)
		assert.Equal(t, occs[i].Commit, res.Properties.Commit)
		assert.Equal(t, "2024-05-01T12:00:00Z", res.Properties.CommitDate)
		require.NotNil(t, res.Properties.HostRecorded)
		assert.True(t, *res.Properties.HostRecorded)
		fp := res.PartialFingerprints[LocationFingerprintKey]
		require.NotEmpty(t, fp)
		fingerprints[fp] = true
	}
	assert.Equal(t, []string{"config.yml", "config.yml", "deploy/config.yml"}, uris)
	assert.Len(t, fingerprints, 3, "each location needs a distinct fingerprint so GitHub does not dedupe")
}

func TestAddResultForOccurrence_JSONShape(t *testing.T) {
	r := NewReport()
	score := &types.Score{Final: 85, Applied: []types.ScoreModifier{}}
	r.AddResultForOccurrence(occurrenceMatch(), types.Occurrence{
		Kind: "git", Repository: "github.com/acme/api", Path: "config.yml",
		AbsolutePath: "/src/api/config.yml", WorkingTree: true, HostRecorded: false,
	}, score)
	data, err := r.ToJSON()
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))
	res := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	assert.Equal(t, "error", res["level"])
	props := res["properties"].(map[string]any)
	assert.Equal(t, "8.5", props["security-severity"])
	assert.Equal(t, "github.com/acme/api", props["repository"])
	assert.Equal(t, "/src/api/config.yml", props["absolute_path"])
	assert.Equal(t, false, props["host_recorded"])
	assert.Equal(t, true, props["working_tree"])
	assert.NotContains(t, props, "commit", "absent commit is omitted")
	assert.NotContains(t, props, "commit_date", "absent date is omitted")
	fps := res["partialFingerprints"].(map[string]any)
	assert.NotEmpty(t, fps[LocationFingerprintKey])
}

func TestAddResultForOccurrence_NonGitOmitsHostRecorded(t *testing.T) {
	r := NewReport()
	r.AddResultForOccurrence(occurrenceMatch(), types.Occurrence{Kind: "file", Path: "/tmp/x.env", HostRecorded: true}, nil)
	res := r.Runs[0].Results[0]
	assert.Equal(t, "file:///tmp/x.env", res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, "warning", res.Level)
	require.NotNil(t, res.Properties)
	assert.Nil(t, res.Properties.HostRecorded)
	assert.Empty(t, res.Properties.Repository)
}

func TestAddResultForOccurrence_FingerprintStable(t *testing.T) {
	o := types.Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", Commit: "abc", HostRecorded: true}
	a, b := NewReport(), NewReport()
	a.AddResultForOccurrence(occurrenceMatch(), o, nil)
	b.AddResultForOccurrence(occurrenceMatch(), o, nil)
	assert.Equal(t, a.Runs[0].Results[0].PartialFingerprints, b.Runs[0].Results[0].PartialFingerprints)
}

// SEC-18: message.text is shown by SARIF viewers, so it is sanitized.
func TestAddResult_MessageSanitized(t *testing.T) {
	m := occurrenceMatch()
	m.RuleName = "evil\x1b[31m\u202e"
	r := NewReport()
	r.AddResult(m, "a.txt")
	r.AddResultWithScore(m, "a.txt", nil)
	r.AddResultForOccurrence(m, types.Occurrence{Kind: "file", Path: "a.txt"}, nil)
	for _, res := range r.Runs[0].Results {
		assert.Equal(t, `evil\x1b[31m\u{202e}`, res.Message.Text)
	}
}

// SEC-18: artifact URIs are RFC 3986-valid.
func TestFormatFileURI_RFC3986(t *testing.T) {
	tests := []struct{ in, want string }{
		{"dir/a b#c?.yml", "dir/a%20b%23c%3F.yml"},
		{"a\nb.yml", "a%0Ab.yml"},
		{"x\x1b[31m.yml", "x%1B%5B31m.yml"},
		{"café.yml", "caf%C3%A9.yml"},
		{"a:b.yml", "a%3Ab.yml"},
		{"relative/path/file.txt", "relative/path/file.txt"},
		{"/home/u/x y", "file:///home/u/x%20y"},
		{"/absolute/path/file.txt", "file:///absolute/path/file.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatFileURI(tt.in)
			assert.Equal(t, tt.want, got)
			assertValidURI(t, tt.in, got)
		})
	}
}

func assertValidURI(t *testing.T, in, got string) {
	t.Helper()
	u, err := url.Parse(got)
	require.NoError(t, err)
	assert.Equal(t, got, u.String())
	for i := 0; i < len(got); i++ {
		c := got[i]
		if c == '%' {
			require.Less(t, i+2, len(got), "truncated escape in %q", got)
			continue
		}
		assert.True(t, isURIChar(c), "byte %q not allowed in URI %q", c, got)
	}
	if strings.HasPrefix(got, "file://") {
		assert.Equal(t, "file", u.Scheme)
		assert.Equal(t, filepath.ToSlash(in), u.Path)
		return
	}
	assert.Empty(t, u.Scheme, "relative path must stay a relative reference")
	back, err := url.PathUnescape(got)
	require.NoError(t, err)
	assert.Equal(t, filepath.ToSlash(in), back)
}

func isURIChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("-._~:/?#[]@!$&'()*+,;=", c) >= 0
}

func FuzzFormatFileURI(f *testing.F) {
	for _, s := range []string{"dir/a b#c?.yml", "a\nb.yml", "café.yml", "/home/u/x y", "caf\xe9.yml", "a:b", "//x", "%41", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		if strings.ContainsRune(in, '\\') && filepath.Separator == '\\' {
			t.Skip("backslash is a separator on Windows")
		}
		assertValidURI(t, in, formatFileURI(in))
	})
}
