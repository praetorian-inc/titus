package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	// The enumerator creation itself does not validate the target path;
	// that validation happens in runScan. So createEnumerator succeeds
	// regardless of whether the path exists.
	e, err := createEnumerator("/nonexistent/path/xyz", false)
	require.NoError(t, err)
	assert.NotNil(t, e)
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
