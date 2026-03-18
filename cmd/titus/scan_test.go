package main

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/enum"
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

func TestCreateEnumerator_InvalidTarget(t *testing.T) {
	// The enumerator creation itself does not validate the target path;
	// that validation happens in runScan. So createEnumerator succeeds
	// regardless of whether the path exists.
	e, err := createEnumerator("/nonexistent/path/xyz", false)
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestLoadRules_DefaultRuleset(t *testing.T) {
	rules, err := loadRules("", "", "", "default")
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
	rules, err := loadRules("", "", "", "all")
	require.NoError(t, err)
	ruleIDs := make(map[string]bool)
	for _, r := range rules {
		ruleIDs[r.ID] = true
	}
	assert.True(t, ruleIDs["np.aws.1"], "np.aws.1 should be present with ruleset=all")
	assert.True(t, ruleIDs["np.aws.3"], "np.aws.3 should be present with ruleset=all")
}

func TestLoadRules_UnknownRuleset(t *testing.T) {
	_, err := loadRules("", "", "", "bogus")
	assert.Error(t, err, "expected error for unknown ruleset")
}

func TestLoadRules_RulesetThenIncludeExclude(t *testing.T) {
	rules, err := loadRules("", "np\\.aws\\.", "", "default")
	require.NoError(t, err)
	ruleIDs := make(map[string]bool)
	for _, r := range rules {
		ruleIDs[r.ID] = true
		assert.Contains(t, r.ID, "np.aws", "expected only aws rules after include filter")
	}
	assert.False(t, ruleIDs["np.aws.1"], "np.aws.1 should not appear — not in default ruleset")
}

func TestLoadRules_AssetsRuleset(t *testing.T) {
	rules, err := loadRules("", "", "", "np.assets")
	require.NoError(t, err)
	ruleIDs := make(map[string]bool)
	for _, r := range rules {
		ruleIDs[r.ID] = true
	}
	assert.True(t, ruleIDs["np.aws.1"], "np.aws.1 should be in np.assets ruleset")
	assert.False(t, ruleIDs["np.aws.2"], "np.aws.2 (secret) should not be in np.assets ruleset")
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
