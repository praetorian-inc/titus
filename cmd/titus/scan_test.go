package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/sarif"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func TestScanCommand_Exists(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)
	assert.Equal(t, "scan", cmd.Name())
}

func TestScanCommand_DefaultOutputIsDatastore(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("output")
	require.NotNil(t, flag, "--output flag should exist")
	assert.Equal(t, "titus.ds", flag.DefValue,
		"default --output should be titus.ds datastore directory")
}

func TestScanCommand_DockerFlag(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("docker")
	require.NotNil(t, flag, "--docker flag should exist")
	assert.Equal(t, "false", flag.DefValue)
}

func TestScanCommand_OutputFlagMentionsAuto(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)
	flag := cmd.Flags().Lookup("output")
	require.NotNil(t, flag)
	assert.Contains(t, flag.Usage, ":auto:")
}

func TestGitHubScanCmd_OutputFlagMentionsAuto(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"github", "scan"})
	require.NoError(t, err)
	flag := cmd.Flags().Lookup("output")
	require.NotNil(t, flag)
	assert.Contains(t, flag.Usage, ":auto:")
}

func TestCreateEnumerator_GitReturnsCombined(t *testing.T) {
	// createEnumerator with useGit=true must return a *enum.CombinedEnumerator
	// so that both git history and the working tree are scanned.
	target := t.TempDir()

	e, err := createEnumerator(target, true)
	require.NoError(t, err)

	_, ok := e.(*enum.CombinedEnumerator)
	assert.True(t, ok, "createEnumerator(useGit=true) should return *enum.CombinedEnumerator, got %T", e)
}

func TestCreateEnumerator_NoGitReturnsFilesystem(t *testing.T) {
	target := t.TempDir()

	e, err := createEnumerator(target, false)
	require.NoError(t, err)

	_, ok := e.(*enum.FilesystemEnumerator)
	assert.True(t, ok, "createEnumerator(useGit=false) should return *enum.FilesystemEnumerator, got %T", e)
}

func TestCreateDockerEnumerator_ReturnsDockerImageEnumerator(t *testing.T) {
	e, err := createDockerEnumerator("example/app:latest")
	require.NoError(t, err)

	dockerEnum, ok := e.(*enum.DockerImageEnumerator)
	require.True(t, ok, "createDockerEnumerator should return *enum.DockerImageEnumerator, got %T", e)
	assert.Equal(t, "example/app:latest", dockerEnum.Image)
}

func TestCreateEnumerator_InvalidTarget(t *testing.T) {
	// createEnumerator does not validate the target path; runScan does.
	// The filesystem enumerator it returns walks the target as its root,
	// so a missing path yields no blobs and a warning naming that path.
	const target = "/nonexistent/path/xyz"
	e, err := createEnumerator(target, false)
	require.NoError(t, err)
	fsEnum, ok := e.(*enum.FilesystemEnumerator)
	require.True(t, ok, "createEnumerator(useGit=false) should return *enum.FilesystemEnumerator, got %T", e)

	var blobs int
	var enumErr error
	stderr := captureStderr(t, func() {
		enumErr = fsEnum.Enumerate(context.Background(), func([]byte, types.BlobID, types.Provenance) error {
			blobs++
			return nil
		})
	})
	require.NoError(t, enumErr)
	assert.Zero(t, blobs, "a missing root has no files")
	assert.Contains(t, stderr, target, "the walk starts at the target path")
}

func TestLoadRules_DefaultRuleset(t *testing.T) {
	rules, err := loadRules("", "", "", "default", false)
	require.NoError(t, err)
	ruleIDs := make(map[string]bool)
	for _, r := range rules {
		ruleIDs[r.ID] = true
	}
	assert.False(t, ruleIDs["np.aws.1"], "np.aws.1 (identifier) should not be in default ruleset")
	assert.False(t, ruleIDs["np.aws.3"], "np.aws.3 (identifier) should not be in default ruleset")
	assert.True(t, ruleIDs["np.aws.2"], "np.aws.2 (secret) should be in default ruleset")
}

func TestLoadRules_AllRuleset(t *testing.T) {
	rules, err := loadRules("", "", "", "all", false)
	require.NoError(t, err)
	ruleIDs := make(map[string]bool)
	for _, r := range rules {
		ruleIDs[r.ID] = true
	}
	assert.True(t, ruleIDs["np.aws.1"], "np.aws.1 should be present with ruleset=all")
	assert.True(t, ruleIDs["np.aws.3"], "np.aws.3 should be present with ruleset=all")
}

func TestLoadRules_UnknownRuleset(t *testing.T) {
	_, err := loadRules("", "", "", "bogus", false)
	assert.Error(t, err, "expected error for unknown ruleset")
}

func TestLoadRules_RulesetThenIncludeExclude(t *testing.T) {
	rules, err := loadRules("", "np\\.aws\\.", "", "default", false)
	require.NoError(t, err)
	ruleIDs := make(map[string]bool)
	for _, r := range rules {
		ruleIDs[r.ID] = true
		assert.Contains(t, r.ID, "np.aws", "expected only aws rules after include filter")
	}
	assert.False(t, ruleIDs["np.aws.1"], "np.aws.1 should not appear — not in default ruleset")
}

func TestLoadRules_AssetsRuleset(t *testing.T) {
	rules, err := loadRules("", "", "", "np.assets", false)
	require.NoError(t, err)
	ruleIDs := make(map[string]bool)
	for _, r := range rules {
		ruleIDs[r.ID] = true
	}
	assert.True(t, ruleIDs["np.aws.1"], "np.aws.1 should be in np.assets ruleset")
	assert.False(t, ruleIDs["np.aws.2"], "np.aws.2 (secret) should not be in np.assets ruleset")
}

func TestScanCommand_IgnoreFlag(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("ignore")
	require.NotNil(t, flag, "--ignore flag should exist")
	assert.Equal(t, "", flag.DefValue, "default --ignore should be empty (uses embedded defaults)")
}

func TestResolveAutoOutput(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)
	cwdBase := filepath.Base(cwd)

	tests := []struct {
		name     string
		target   string
		expected string
	}{
		{
			name:     "github url",
			target:   "https://github.com/org/repo",
			expected: "repo.ds",
		},
		{
			name:     "github url with .git suffix",
			target:   "https://github.com/org/repo.git",
			expected: "repo.ds",
		},
		{
			name:     "gitlab url with .git suffix",
			target:   "gitlab.com/ns/project.git",
			expected: "project.ds",
		},
		{
			name:     "absolute path",
			target:   "/home/user/myproject",
			expected: "myproject.ds",
		},
		{
			name:     "dot path",
			target:   ".",
			expected: cwdBase + ".ds",
		},
		{
			name:     "file path",
			target:   "/tmp/secrets.env",
			expected: "secrets.env.ds",
		},
		{
			name:     "path with trailing slash",
			target:   "/home/user/myproject/",
			expected: "myproject.ds",
		},
		{
			name:     "github url with .git suffix and trailing slash",
			target:   "https://github.com/org/repo.git/",
			expected: "repo.ds",
		},
		{
			name:     "github url without scheme",
			target:   "github.com/org/repo",
			expected: "repo.ds",
		},
		{
			name:     "github enterprise url falls back to path",
			target:   "https://github.corp.com/org/repo",
			expected: "repo.ds",
		},
		{
			name:     "relative path",
			target:   "myproject",
			expected: "myproject.ds",
		},
		{
			name:     "docker image url",
			target:   "docker://registry.example.com/team/app:1.2.3",
			expected: "registry.example.com_team_app_1.2.3.ds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveAutoOutput(tt.target)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestDockerAutoOutputName(t *testing.T) {
	assert.Equal(t, "alpine_latest.ds", dockerAutoOutputName("alpine:latest"))
	assert.Equal(t, "registry.example.com_team_app_1.2.3.ds", dockerAutoOutputName("docker://registry.example.com/team/app:1.2.3"))
	assert.Equal(t, "registry.example.com_team_app.ds", dockerAutoOutputName("registry.example.com/team/app@sha256:abc123"))
}

func init() {
	// Ensure the package-level flag vars have sane defaults for unit tests
	// (they are normally set by cobra flag parsing).
	if extractMaxSize == "" {
		extractMaxSize = "10MB"
	}
	if extractMaxTotal == "" {
		extractMaxTotal = "100MB"
	}
	if extractMaxDepth == 0 {
		extractMaxDepth = 5
	}
}

func TestLoadCustomRulesPath_SingleFileSingleRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "one.yml")
	writeRulesYAML(t, path, []ruleStub{{ID: "np.test.path.solo", BaseScore: 50}})

	loader := newRuleLoader(t)
	rules, err := loadCustomRulesPath(loader, path)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "np.test.path.solo", rules[0].ID)
}

func TestLoadCustomRulesPath_SingleFileMultiRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.yml")
	writeRulesYAML(t, path, []ruleStub{
		{ID: "np.test.path.multi.1", BaseScore: 50},
		{ID: "np.test.path.multi.2", BaseScore: 60},
		{ID: "np.test.path.multi.3", BaseScore: 70},
	})

	loader := newRuleLoader(t)
	rules, err := loadCustomRulesPath(loader, path)
	require.NoError(t, err)
	require.Len(t, rules, 3)
	ids := ruleIDs(rules)
	assert.ElementsMatch(t, []string{
		"np.test.path.multi.1",
		"np.test.path.multi.2",
		"np.test.path.multi.3",
	}, ids)
}

func TestLoadCustomRulesPath_DirectoryMixedExtensions(t *testing.T) {
	dir := t.TempDir()
	writeRulesYAML(t, filepath.Join(dir, "a.yml"), []ruleStub{{ID: "np.test.dir.a", BaseScore: 50}})
	writeRulesYAML(t, filepath.Join(dir, "b.yaml"), []ruleStub{
		{ID: "np.test.dir.b1", BaseScore: 50},
		{ID: "np.test.dir.b2", BaseScore: 60},
	})
	writeRulesYAML(t, filepath.Join(dir, "C.YAML"), []ruleStub{{ID: "np.test.dir.c", BaseScore: 50}})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("ignore me"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.md"), []byte("# ignore"), 0o644))

	loader := newRuleLoader(t)
	rules, err := loadCustomRulesPath(loader, dir)
	require.NoError(t, err)
	ids := ruleIDs(rules)
	assert.ElementsMatch(t, []string{
		"np.test.dir.a",
		"np.test.dir.b1",
		"np.test.dir.b2",
		"np.test.dir.c",
	}, ids)
}

func TestLoadCustomRulesPath_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	loader := newRuleLoader(t)
	_, err := loadCustomRulesPath(loader, dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no .yml or .yaml files found")
}

func TestLoadCustomRulesPath_NestedSubdirectory(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "sub", "deeper")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	writeRulesYAML(t, filepath.Join(dir, "top.yml"), []ruleStub{{ID: "np.test.nested.top", BaseScore: 50}})
	writeRulesYAML(t, filepath.Join(nested, "deep.yaml"), []ruleStub{{ID: "np.test.nested.deep", BaseScore: 50}})

	loader := newRuleLoader(t)
	rules, err := loadCustomRulesPath(loader, dir)
	require.NoError(t, err)
	ids := ruleIDs(rules)
	assert.ElementsMatch(t, []string{
		"np.test.nested.top",
		"np.test.nested.deep",
	}, ids)
}

func TestLoadCustomRulesPath_MissingPath(t *testing.T) {
	loader := newRuleLoader(t)
	_, err := loadCustomRulesPath(loader, filepath.Join(t.TempDir(), "does-not-exist"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stat ")
}

// ruleStub describes a synthetic rule used in tests for loadCustomRulesPath.
type ruleStub struct {
	ID        string
	BaseScore int
}

// writeRulesYAML serializes the given rule stubs as a YAML rules file at path.
// Patterns are synthetic placeholders; no real secret material is used.
func writeRulesYAML(t *testing.T, path string, rules []ruleStub) {
	t.Helper()
	var b strings.Builder
	b.WriteString("rules:\n")
	for i, r := range rules {
		fmt.Fprintf(&b, "  - name: Synthetic Rule %d\n", i+1)
		fmt.Fprintf(&b, "    id: %s\n", r.ID)
		fmt.Fprintf(&b, "    pattern: synthetic_%d_[A-Za-z0-9]{8}\n", i+1)
		fmt.Fprintf(&b, "    description: synthetic test rule\n")
		fmt.Fprintf(&b, "    base_score: %d\n", r.BaseScore)
	}
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o644))
}

// newRuleLoader returns a fresh rule.Loader for tests.
func newRuleLoader(t *testing.T) *rule.Loader {
	t.Helper()
	return rule.NewLoader()
}

// ruleIDs extracts rule IDs from a slice of *types.Rule for set-based assertions.
func ruleIDs(rules []*types.Rule) []string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}

// TestLoadRules_CustomPathMergedWithBuiltins verifies that supplying a custom
// rules file via --rules appends the custom rule to (not replaces) the builtin
// ruleset. Both the custom rule ID and at least one known builtin must be
// present in the returned slice.
func TestLoadRules_CustomPathMergedWithBuiltins(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "custom-*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(`rules:
  - name: Custom Merge Test Rule
    id: custom.test.merge.1
    pattern: "(?P<token>CUSTOMMRG[A-Z0-9]{8})"
    description: synthetic rule for merge test
    base_score: 50
`)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	rules, err := loadRules(f.Name(), "", "", "default", false)
	require.NoError(t, err)

	// Custom rule must be present
	var foundCustom bool
	var foundBuiltin bool
	for _, r := range rules {
		if r.ID == "custom.test.merge.1" {
			foundCustom = true
		}
		// np.aws.2 is a known builtin secret rule present in all rulesets
		if r.ID == "np.aws.2" {
			foundBuiltin = true
		}
	}
	if !foundCustom {
		t.Error("custom rule 'custom.test.merge.1' not present in merged rule set")
	}
	if !foundBuiltin {
		t.Error("builtin rule 'np.aws.2' should still be present after merging custom rules")
	}
}

// TestLoadRules_CustomRuleMissingBaseScore_Rejected verifies that a custom rule
// file missing the required base_score field causes loadRules to return an error
// at load time rather than silently producing an unscored (score=0) finding.
func TestLoadRules_CustomRuleMissingBaseScore_Rejected(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "invalid-*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(`rules:
  - name: Missing Base Score
    id: custom.no.score.1
    pattern: "(?P<token>TOKEN[A-Z0-9]{8})"
    description: rule without base_score
`)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	_, err = loadRules(f.Name(), "", "", "default", false)
	if err == nil {
		t.Error("expected error for custom rule missing base_score, got nil")
	}
}

// ---------------------------------------------------------------------------
// ENG-9178: every location of a matched blob in scan output
// ---------------------------------------------------------------------------

const (
	locTestRuleID = "test.locations.1"
	locTestSecret = "token: synthetic_1_AbCd1234\n"
)

// scanJSONMatchForTest is the subset of one `titus scan --format json` element that
// the location tests read.
type scanJSONMatchForTest struct {
	RuleID    string
	Locations []jsonLocation `json:"locations"`
}

// scanForTest runs `titus scan <target>` through runScan with only the
// synthetic location rule enabled and returns stdout. Every scan global it
// sets is restored when the test ends.
func scanForTest(t *testing.T, target, output, format string, git bool) []byte {
	t.Helper()
	rulesFile := filepath.Join(t.TempDir(), "rules.yml")
	writeRulesYAML(t, rulesFile, []ruleStub{{ID: locTestRuleID, BaseScore: 50}})

	origRules, origInclude, origExclude := scanRulesPath, scanRulesInclude, scanRulesExclude
	origRuleset, origOutput, origFormat, origGit := scanRuleset, scanOutputPath, scanOutputFormat, scanGit
	origIgnore, origAccess := scanIgnoreFile, scanAccessibility
	t.Cleanup(func() {
		scanRulesPath, scanRulesInclude, scanRulesExclude = origRules, origInclude, origExclude
		scanRuleset, scanOutputPath, scanOutputFormat, scanGit = origRuleset, origOutput, origFormat, origGit
		scanIgnoreFile, scanAccessibility = origIgnore, origAccess
	})
	scanRulesPath = rulesFile
	scanRulesInclude = `^test\.locations\.`
	scanRulesExclude = ""
	scanRuleset = "default"
	scanOutputPath = output
	scanOutputFormat = format
	scanGit = git
	scanIgnoreFile = ""
	scanAccessibility = "private"

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetContext(context.Background())
	require.NoError(t, runScan(cmd, []string{target}))
	return out.Bytes()
}

// scanJSONMatches decodes `titus scan --format json` stdout.
func scanJSONMatches(t *testing.T, out []byte) []scanJSONMatchForTest {
	t.Helper()
	var got []scanJSONMatchForTest
	require.NoError(t, json.Unmarshal(out, &got), "scan stdout must be a JSON array: %s", out)
	return got
}

func writeFileForTest(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// gitForTest runs git in dir with a fixed identity and fixed dates, isolated
// from the user's git config, so identical trees give identical commits.
func gitForTest(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Titus Test", "GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=Titus Test", "GIT_COMMITTER_EMAIL=test@example.invalid",
		"GIT_AUTHOR_DATE=2024-01-02T03:04:05Z", "GIT_COMMITTER_DATE=2024-01-02T03:04:05Z",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
}

// gitRepoForTest creates a repository in dir with one commit holding files.
func gitRepoForTest(t *testing.T, dir, origin string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		writeFileForTest(t, filepath.Join(dir, name), content)
	}
	gitForTest(t, dir, "init", "-q", "-b", "main")
	if origin != "" {
		gitForTest(t, dir, "remote", "add", "origin", origin)
	}
	gitForTest(t, dir, "add", "-A")
	gitForTest(t, dir, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "initial")
}

func locationPaths(locs []jsonLocation) []string {
	paths := make([]string, len(locs))
	for i, l := range locs {
		paths[i] = l.Path
	}
	return paths
}

func strPtr(s string) *string { return &s }

// tempDatastore returns a fresh --output path outside every scanned tree.
// The tests use a datastore, as `titus scan` does by default, rather than
// :memory:, because only the datastore deduplicates the matches of a blob
// seen at several locations.
func tempDatastore(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "out.ds")
}

// TestOutputMatches_AddsLocationsKeepsMatchFields covers C-SCANJSON-1 at the
// encoder: every existing match field is unchanged and the locations key
// lists every location of the blob.
func TestOutputMatches_AddsLocationsKeepsMatchFields(t *testing.T) {
	s := store.NewMemory()
	blobID := types.ComputeBlobID([]byte(locTestSecret))
	require.NoError(t, s.AddOccurrences(blobID, []types.Occurrence{
		{Kind: "file", Path: "a/config.yml", AbsolutePath: "/x/a/config.yml", HostRecorded: true},
		{Kind: "file", Path: "b/config.yml", AbsolutePath: "/x/b/config.yml", HostRecorded: true},
	}))
	match := &types.Match{
		BlobID: blobID, StructuralID: "sid", FindingID: "fid", RuleID: locTestRuleID, RuleName: "Synthetic Rule 1",
		Location: types.Location{Source: types.SourceSpan{
			Start: types.SourcePoint{Line: 1, Column: 8}, End: types.SourcePoint{Line: 1, Column: 28},
		}},
		Groups:  [][]byte{[]byte("synthetic_1_AbCd1234")},
		Snippet: types.Snippet{Matching: []byte("synthetic_1_AbCd1234")},
	}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	require.NoError(t, outputMatches(cmd, s, []*types.Match{match}))

	var got []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Len(t, got, 1)

	var locs []jsonLocation
	require.NoError(t, json.Unmarshal(got[0]["locations"], &locs))
	assert.Equal(t, []string{"a/config.yml", "b/config.yml"}, locationPaths(locs))
	assert.Equal(t, strPtr("/x/a/config.yml"), locs[0].AbsolutePath)
	assert.Nil(t, locs[0].Repository)
	assert.Equal(t, 1, locs[0].Range.Start.Line)
	assert.Equal(t, 8, locs[0].Range.Start.Column)

	// Compare decoded values, so the encoder's indentation does not count.
	var gotFields []map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &gotFields))
	delete(gotFields[0], "locations")
	raw, err := json.Marshal(match)
	require.NoError(t, err)
	var want map[string]any
	require.NoError(t, json.Unmarshal(raw, &want))
	assert.Equal(t, want, gotFields[0], "existing match fields must be unchanged")
}

// TestOutputMatches_NoLocationIsEmptyArray: a blob with no recorded location
// still gets a locations key, as [] rather than null.
func TestOutputMatches_NoLocationIsEmptyArray(t *testing.T) {
	s := store.NewMemory()
	match := &types.Match{BlobID: types.ComputeBlobID([]byte("x")), RuleID: locTestRuleID}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	require.NoError(t, outputMatches(cmd, s, []*types.Match{match}))

	var got []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Len(t, got, 1)
	assert.JSONEq(t, `[]`, string(got[0]["locations"]))
}

// sarifDocForTest is the subset of a SARIF log the location tests read.
type sarifDocForTest struct {
	Runs []struct {
		Results []struct {
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			Properties struct {
				Repository string `json:"repository"`
			} `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

// TestOutputSARIF_AttachesStoredFindingScore covers what scan's SARIF route
// adds over writeSARIF (C-SARIF-1 itself is TestWriteSARIF_OneResultPerLocation):
// it writes to the command's output and scores each location's result from
// the finding stored for its rule and groups. A match with no stored finding
// gets no score.
func TestOutputSARIF_AttachesStoredFindingScore(t *testing.T) {
	s := store.NewMemory()
	rules := []*types.Rule{{ID: locTestRuleID, Name: "Synthetic Rule 1", StructuralID: "rsid"}}
	groups := [][]byte{[]byte("g")}
	scored := &types.Match{BlobID: types.ComputeBlobID([]byte(locTestSecret)), RuleID: locTestRuleID, Groups: groups}
	unscored := &types.Match{BlobID: types.ComputeBlobID([]byte("other")), RuleID: locTestRuleID, Groups: [][]byte{[]byte("h")}}
	require.NoError(t, s.AddFinding(&types.Finding{
		ID: types.ComputeFindingID("rsid", groups), RuleID: locTestRuleID, Groups: groups,
		Score: &types.Score{Final: 85, Applied: []types.ScoreModifier{}},
	}))
	require.NoError(t, s.AddOccurrences(scored.BlobID, []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", Commit: "aaaa", HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/web", Path: "config.yml", Commit: "bbbb", HostRecorded: true},
	}))
	require.NoError(t, s.AddOccurrences(unscored.BlobID, []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "other.yml", Commit: "cccc", HostRecorded: true},
	}))

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	require.NoError(t, outputSARIF(cmd, s, rules, []*types.Match{scored, unscored}))

	var rep sarif.Report
	require.NoError(t, json.Unmarshal(out.Bytes(), &rep), "SARIF goes to the command's output")
	require.Len(t, rep.Runs, 1)
	severity := map[string]string{}
	levels := map[string]string{}
	for _, r := range rep.Runs[0].Results {
		require.NotNil(t, r.Properties)
		key := r.Properties.Repository + " " + r.Locations[0].PhysicalLocation.ArtifactLocation.URI
		severity[key] = r.Properties.SecuritySeverity
		levels[key] = r.Level
	}
	assert.Equal(t, map[string]string{
		"github.com/acme/api config.yml": "8.5",
		"github.com/acme/web config.yml": "8.5",
		"github.com/acme/api other.yml":  "",
	}, severity)
	assert.Equal(t, map[string]string{
		"github.com/acme/api config.yml": "error",
		"github.com/acme/web config.yml": "error",
		"github.com/acme/api other.yml":  "warning",
	}, levels)
}

// TestSARIFOccurrence_SourceSeparatesResults: two extended locations that
// differ only by source get distinct location fingerprints and each result
// names its source.
func TestSARIFOccurrence_SourceSeparatesResults(t *testing.T) {
	match := &types.Match{BlobID: types.ComputeBlobID([]byte(locTestSecret)), RuleID: locTestRuleID}
	report := sarif.NewReport()
	report.AddResultForOccurrence(match, types.Occurrence{Kind: "extended", Source: "confluence", Path: "page/1"}, nil)
	report.AddResultForOccurrence(match, types.Occurrence{Kind: "extended", Source: "jira", Path: "page/1"}, nil)

	results := report.Runs[0].Results
	require.Len(t, results, 2)
	assert.NotEqual(t,
		results[0].PartialFingerprints[sarif.LocationFingerprintKey],
		results[1].PartialFingerprints[sarif.LocationFingerprintKey])

	raw, err := report.ToJSON()
	require.NoError(t, err)
	var doc struct {
		Runs []struct {
			Results []struct {
				Properties map[string]any `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	assert.Equal(t, "confluence", doc.Runs[0].Results[0].Properties["source"])
	assert.Equal(t, "jira", doc.Runs[0].Results[1].Properties["source"])

	report = sarif.NewReport()
	report.AddResultForOccurrence(match, types.Occurrence{Kind: "file", Path: "a.yml"}, nil)
	raw, err = report.ToJSON()
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"source"`, "source is omitted when empty")
}

// TestScanE2E_JSONListsEveryLocation covers C-SCANJSON-1 end to end:
// `titus scan . --format json` over two identical files gives one match whose
// locations name both files.
func TestScanE2E_JSONListsEveryLocation(t *testing.T) {
	dir := t.TempDir()
	writeFileForTest(t, filepath.Join(dir, "a", "config.yml"), locTestSecret)
	writeFileForTest(t, filepath.Join(dir, "b", "config.yml"), locTestSecret)
	t.Chdir(dir)

	got := scanJSONMatches(t, scanForTest(t, ".", tempDatastore(t), "json", false))
	require.Len(t, got, 1)
	assert.Equal(t, locTestRuleID, got[0].RuleID)
	assert.Equal(t, []string{"a/config.yml", "b/config.yml"}, locationPaths(got[0].Locations))
}

// TestScanE2E_SARIFOneResultPerFile: scan's SARIF route reports each
// identical file as its own result.
func TestScanE2E_SARIFOneResultPerFile(t *testing.T) {
	dir := t.TempDir()
	writeFileForTest(t, filepath.Join(dir, "a", "config.yml"), locTestSecret)
	writeFileForTest(t, filepath.Join(dir, "b", "config.yml"), locTestSecret)
	t.Chdir(dir)

	var doc sarifDocForTest
	require.NoError(t, json.Unmarshal(scanForTest(t, ".", tempDatastore(t), "sarif", false), &doc))
	require.Len(t, doc.Runs, 1)
	var uris []string
	for _, r := range doc.Runs[0].Results {
		require.Len(t, r.Locations, 1)
		uris = append(uris, r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	assert.Equal(t, []string{"a/config.yml", "b/config.yml"}, uris)
}

// TestScanE2E_PlainFolderLocation covers C-NOREMOTE-2: `titus scan e/f` over
// a plain folder gives repository null and the path as typed.
func TestScanE2E_PlainFolderLocation(t *testing.T) {
	dir := t.TempDir()
	writeFileForTest(t, filepath.Join(dir, "e", "f", "g", "h", "config.yml"), locTestSecret)
	t.Chdir(dir)
	cwd, err := os.Getwd()
	require.NoError(t, err)

	got := scanJSONMatches(t, scanForTest(t, "e/f", tempDatastore(t), "json", false))
	require.Len(t, got, 1)
	require.Len(t, got[0].Locations, 1)
	loc := got[0].Locations[0]
	assert.Nil(t, loc.Repository)
	assert.Equal(t, "e/f/g/h/config.yml", loc.Path)
	assert.Equal(t, strPtr(filepath.Join(cwd, "e", "f", "g", "h", "config.yml")), loc.AbsolutePath)
	assert.Nil(t, loc.Commit)
	assert.True(t, loc.HostRecorded)
}

// TestScanE2E_TwoFoldersOneDatastore covers C-FOLDERS-1: identical
// config.yml in two folders, each scanned with `titus scan .` into one
// datastore, gives two locations separated by their absolute paths.
func TestScanE2E_TwoFoldersOneDatastore(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared.ds")
	one, two := filepath.Join(root, "one"), filepath.Join(root, "two")
	writeFileForTest(t, filepath.Join(one, "config.yml"), locTestSecret)
	writeFileForTest(t, filepath.Join(two, "config.yml"), locTestSecret)

	t.Chdir(one)
	cwdOne, err := os.Getwd()
	require.NoError(t, err)
	scanForTest(t, ".", shared, "json", false)

	t.Chdir(two)
	cwdTwo, err := os.Getwd()
	require.NoError(t, err)
	got := scanJSONMatches(t, scanForTest(t, ".", shared, "json", false))

	require.Len(t, got, 1)
	require.Len(t, got[0].Locations, 2)
	for i, wantAbs := range []string{filepath.Join(cwdOne, "config.yml"), filepath.Join(cwdTwo, "config.yml")} {
		assert.Equal(t, "config.yml", got[0].Locations[i].Path)
		assert.Equal(t, strPtr(wantAbs), got[0].Locations[i].AbsolutePath)
	}
}

// TestScanE2E_TwoGitFoldersOneDatastore covers C-FOLDERS-2: identical
// remote-less repositories (identical commits) scanned with --git into one
// datastore give two locations. Only the repository's absolute root
// separates them.
func TestScanE2E_TwoGitFoldersOneDatastore(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared.ds")
	for _, name := range []string{"one", "two"} {
		gitRepoForTest(t, filepath.Join(root, name), "", map[string]string{"config.yml": locTestSecret})
	}

	t.Chdir(filepath.Join(root, "one"))
	cwdOne, err := os.Getwd()
	require.NoError(t, err)
	scanForTest(t, ".", shared, "json", true)
	t.Chdir(filepath.Join(root, "two"))
	cwdTwo, err := os.Getwd()
	require.NoError(t, err)
	got := scanJSONMatches(t, scanForTest(t, ".", shared, "json", true))

	require.Len(t, got, 1)
	require.Len(t, got[0].Locations, 2)
	for i, wantAbs := range []string{filepath.Join(cwdOne, "config.yml"), filepath.Join(cwdTwo, "config.yml")} {
		loc := got[0].Locations[i]
		assert.Equal(t, strPtr("."), loc.Repository, "a remote-less repository keeps the root as typed")
		assert.Equal(t, "config.yml", loc.Path)
		assert.NotNil(t, loc.Commit)
		assert.Equal(t, strPtr(wantAbs), loc.AbsolutePath, "only the absolute path separates the two folders")
	}
}

// TestScanE2E_OnlyMatchedBlobsWriteLocationRows: the write hook stores
// location rows for blobs with at least one match and for no other blob.
func TestScanE2E_OnlyMatchedBlobsWriteLocationRows(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	writeFileForTest(t, filepath.Join(src, "config.yml"), locTestSecret)
	writeFileForTest(t, filepath.Join(src, "clean.txt"), "nothing to see here\n")
	writeFileForTest(t, filepath.Join(src, "other.txt"), "still nothing\n")
	output := filepath.Join(dir, "out.ds")

	scanForTest(t, src, output, "json", false)

	db, err := sql.Open("sqlite", filepath.Join(output, "datastore.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	var blobs, rows int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM blobs`).Scan(&blobs))
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM blob_locations`).Scan(&rows))
	assert.Equal(t, 3, blobs, "every scanned blob is stored")
	assert.Equal(t, 1, rows, "only the matched blob gets a location row")

	var path, abs string
	require.NoError(t, db.QueryRow(`SELECT path, absolute_path FROM blob_locations`).Scan(&path, &abs))
	assert.Equal(t, filepath.Join(src, "config.yml"), path)
	assert.Equal(t, filepath.Join(src, "config.yml"), abs)
}

// TestScanE2E_OriginRemoteMergesWithAPI covers C-CLONEMERGE-1: a local
// --git scan whose origin is git@github.com:acme/api.git and a GitHub API scan
// of acme/api name one repository, and config.yml has one location.
func TestScanE2E_OriginRemoteMergesWithAPI(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared.ds")
	api := filepath.Join(root, "api")
	content := "name: api\n" + locTestSecret
	gitRepoForTest(t, api, "git@github.com:acme/api.git", map[string]string{"config.yml": content})
	t.Chdir(root)
	scanForTest(t, "./api", shared, "json", true)

	// Stand-in for `titus github acme/api`: the API enumerator records a
	// commitless occurrence of the same repository and path.
	s, err := store.New(store.Config{Path: filepath.Join(shared, "datastore.db")})
	require.NoError(t, err)
	require.NoError(t, s.AddOccurrences(types.ComputeBlobID([]byte(content)), []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", HostRecorded: true},
	}))
	require.NoError(t, s.Close())

	got := scanJSONMatches(t, scanForTest(t, "./api", shared, "json", true))
	require.Len(t, got, 1)
	repos := map[string]bool{}
	configLocs := 0
	for _, l := range got[0].Locations {
		require.NotNil(t, l.Repository)
		repos[*l.Repository] = true
		if l.Path == "config.yml" {
			configLocs++
		}
	}
	assert.Equal(t, map[string]bool{"github.com/acme/api": true}, repos)
	assert.Equal(t, 1, configLocs)
}

// TestScanE2E_OriginURLNormalized covers C-NORMALIZE-1: three spellings of
// the same origin all record repository github.com/acme/api.
func TestScanE2E_OriginURLNormalized(t *testing.T) {
	for _, origin := range []string{
		"git@github.com:acme/api.git",
		"https://user:tok@GitHub.com/acme/api.git",
		"ssh://git@github.com:22/acme/api",
	} {
		t.Run(origin, func(t *testing.T) {
			repo := filepath.Join(t.TempDir(), "api")
			gitRepoForTest(t, repo, origin, map[string]string{"config.yml": locTestSecret})
			got := scanJSONMatches(t, scanForTest(t, repo, tempDatastore(t), "json", true))
			require.Len(t, got, 1)
			require.NotEmpty(t, got[0].Locations)
			for _, l := range got[0].Locations {
				assert.Equal(t, strPtr("github.com/acme/api"), l.Repository)
			}
		})
	}
}

// TestScanE2E_NoRemoteRepositoryAsTyped covers C-NOREMOTE-1: `titus scan e/f
// --git` with no remote names the repository e/f and the path g/h/config.yml.
func TestScanE2E_NoRemoteRepositoryAsTyped(t *testing.T) {
	dir := t.TempDir()
	gitRepoForTest(t, filepath.Join(dir, "e", "f"), "", map[string]string{"g/h/config.yml": locTestSecret})
	t.Chdir(dir)
	cwd, err := os.Getwd()
	require.NoError(t, err)

	got := scanJSONMatches(t, scanForTest(t, "e/f", tempDatastore(t), "json", true))
	require.Len(t, got, 1)
	committed := 0
	for _, l := range got[0].Locations {
		if l.Commit == nil {
			continue
		}
		committed++
		assert.Equal(t, strPtr("e/f"), l.Repository)
		assert.Equal(t, "g/h/config.yml", l.Path)
		assert.Equal(t, strPtr(filepath.Join(cwd, "e", "f", "g", "h", "config.yml")), l.AbsolutePath)
	}
	assert.Equal(t, 1, committed)
}

// TestScanE2E_UntrackedCopyIsWorkingTreeLocation covers C-WORKTREE-1: after
// `titus scan acme-api --git`, an untracked backup/config.yml with the same
// bytes as the committed config.yml is its own location with no commit, and
// the human report labels it "working tree". If the combined enumerator
// skipped the already-seen blob, the report would show only the commit line.
func TestScanE2E_UntrackedCopyIsWorkingTreeLocation(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "acme-api")
	gitRepoForTest(t, repo, "", map[string]string{"config.yml": locTestSecret})
	writeFileForTest(t, filepath.Join(repo, "backup", "config.yml"), locTestSecret)
	rev, err := exec.Command("git", "-C", repo, "rev-parse", "--short=7", "HEAD").Output()
	require.NoError(t, err)
	commitA := strings.TrimSpace(string(rev))
	t.Chdir(root)
	ds := tempDatastore(t)

	got := scanJSONMatches(t, scanForTest(t, "acme-api", ds, "json", true))
	require.Len(t, got, 1)
	commits := map[string]bool{}
	for _, l := range got[0].Locations {
		commits[l.Path] = l.Commit != nil
	}
	assert.Equal(t, map[string]bool{"config.yml": true, "backup/config.yml": false}, commits,
		"the untracked copy is a location with no commit")

	s, err := store.New(store.Config{Path: filepath.Join(ds, "datastore.db")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	findings, err := s.GetFindings()
	require.NoError(t, err)
	matches, err := s.GetAllMatches()
	require.NoError(t, err)
	builtins, err := rule.NewLoader().LoadBuiltinRules()
	require.NoError(t, err)
	ruleMap := map[string]*types.Rule{}
	for _, r := range builtins {
		ruleMap[r.ID] = r
	}

	assert.Equal(t, []string{
		"    acme-api  backup/config.yml:1  working tree",
		"    acme-api  config.yml:1  " + commitA + "  2024-01-02",
	}, humanLocationLines(renderHuman(t, s, findings, matches, ruleMap)))
}

// retryingMatcherFake makes every blob time out on the parallel pass: it
// returns no matches, reports the blob as queued for retry, and returns the
// real matches only from DrainTimedOut, as a matcher does after a timeout.
type retryingMatcherFake struct {
	matcher.Matcher
	mu      sync.Mutex
	pending map[types.BlobID][]byte
}

func (f *retryingMatcherFake) MatchWithBlobID(content []byte, blobID types.BlobID) ([]*types.Match, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending[blobID] = content
	return nil, nil
}

func (f *retryingMatcherFake) HasPendingRetry(blobID types.BlobID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.pending[blobID]
	return ok
}

func (f *retryingMatcherFake) DrainTimedOut() ([]*types.Match, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*types.Match
	for blobID, content := range f.pending {
		matches, err := f.Matcher.MatchWithBlobID(content, blobID)
		if err != nil {
			return nil, err
		}
		out = append(out, matches...)
	}
	f.pending = nil
	return out, nil
}

// useRetryingMatcher makes runScan use retryingMatcherFake for this test.
func useRetryingMatcher(t *testing.T) {
	t.Helper()
	orig := newMatcher
	t.Cleanup(func() { newMatcher = orig })
	newMatcher = func(cfg matcher.Config) (matcher.Matcher, error) {
		inner, err := orig(cfg)
		if err != nil {
			return nil, err
		}
		return &retryingMatcherFake{Matcher: inner, pending: map[types.BlobID][]byte{}}, nil
	}
}

// TestScanE2E_RetriedMatchListsEveryLocation: a blob at 2 paths whose match
// arrives only from the timeout-retry pass still shows both recorded
// locations, with absolute paths, in the scan JSON and one SARIF result each.
// Without the location rows, the JSON falls back to legacy provenance rows,
// which have no absolute_path and host_recorded false.
func TestScanE2E_RetriedMatchListsEveryLocation(t *testing.T) {
	dir := t.TempDir()
	writeFileForTest(t, filepath.Join(dir, "a", "config.yml"), locTestSecret)
	writeFileForTest(t, filepath.Join(dir, "b", "config.yml"), locTestSecret)
	t.Chdir(dir)
	cwd, err := os.Getwd()
	require.NoError(t, err)
	useRetryingMatcher(t)
	ds := tempDatastore(t)

	got := scanJSONMatches(t, scanForTest(t, ".", ds, "json", false))
	require.Len(t, got, 1)
	assert.Equal(t, locTestRuleID, got[0].RuleID)
	require.Len(t, got[0].Locations, 2)
	for i, want := range []string{"a/config.yml", "b/config.yml"} {
		loc := got[0].Locations[i]
		assert.Equal(t, want, loc.Path)
		assert.Equal(t, strPtr(filepath.Join(cwd, want)), loc.AbsolutePath)
		assert.True(t, loc.HostRecorded)
	}

	var doc sarifDocForTest
	require.NoError(t, json.Unmarshal(scanForTest(t, ".", tempDatastore(t), "sarif", false), &doc))
	require.Len(t, doc.Runs, 1)
	var uris []string
	for _, r := range doc.Runs[0].Results {
		require.Len(t, r.Locations, 1)
		uris = append(uris, r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	assert.Equal(t, []string{"a/config.yml", "b/config.yml"}, uris)
}

// datastoreOccurrencePaths opens the datastore at ds and returns the location
// paths of the blob of its single match.
func datastoreOccurrencePaths(t *testing.T, ds string) []string {
	t.Helper()
	s, err := store.New(store.Config{Path: filepath.Join(ds, "datastore.db")})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	matches, err := s.GetAllMatches()
	require.NoError(t, err)
	require.Len(t, matches, 1)
	occs, err := s.GetOccurrences(matches[0].BlobID)
	require.NoError(t, err)
	paths := make([]string, 0, len(occs))
	for _, o := range occs {
		paths = append(paths, o.Path)
	}
	return paths
}

// ENG-9178: `--incremental` skips the matching of a blob already in the
// datastore, but a rescan that finds that blob at a new path still records
// the new location. Without it, the copy is invisible in every output.
func TestScan_IncrementalRescanRecordsNewLocation(t *testing.T) {
	orig := scanIncremental
	t.Cleanup(func() { scanIncremental = orig })
	scanIncremental = true

	t.Run("folder", func(t *testing.T) {
		dir := t.TempDir()
		writeFileForTest(t, filepath.Join(dir, "a", "config.yml"), locTestSecret)
		t.Chdir(dir)
		ds := tempDatastore(t)

		scanForTest(t, ".", ds, "json", false)
		writeFileForTest(t, filepath.Join(dir, "b", "config.yml"), locTestSecret)
		scanForTest(t, ".", ds, "json", false)

		assert.Equal(t, []string{"a/config.yml", "b/config.yml"}, datastoreOccurrencePaths(t, ds))
	})

	// The same rule under --git: an uncommitted copy of a committed secret
	// gets its working-tree location on the incremental rescan.
	t.Run("git working-tree copy", func(t *testing.T) {
		dir := t.TempDir()
		gitRepoForTest(t, dir, "", map[string]string{"a/config.yml": locTestSecret})
		t.Chdir(dir)
		ds := tempDatastore(t)

		scanForTest(t, ".", ds, "json", true)
		writeFileForTest(t, filepath.Join(dir, "b", "config.yml"), locTestSecret)
		scanForTest(t, ".", ds, "json", true)

		assert.Contains(t, datastoreOccurrencePaths(t, ds), "b/config.yml")
	})
}
