package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Command-tree wiring
// ---------------------------------------------------------------------------

// TestEnumCmd_ExistsUnderRoot verifies that enumCmd is registered directly on
// the root command (not hidden behind a subcommand).
func TestEnumCmd_ExistsUnderRoot(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"enum"})
	require.NoError(t, err)
	assert.Equal(t, "enum", cmd.Name())
}

// TestEnumCmd_NotHidden verifies that the enum parent is visible in help output
// (not marked Hidden).
func TestEnumCmd_NotHidden(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"enum"})
	require.NoError(t, err)
	assert.False(t, cmd.Hidden, "enum command should be visible (not hidden)")
}

// TestEnumCmd_SubcommandCount verifies that enumCmd has exactly the expected
// service subcommands.
func TestEnumCmd_SubcommandCount(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"enum"})
	require.NoError(t, err)

	names := make([]string, 0, len(cmd.Commands()))
	for _, sub := range cmd.Commands() {
		names = append(names, sub.Name())
	}

	expected := []string{"confluence", "gdrive", "github", "gitlab", "jira", "linear", "microsoft", "notion", "slack"}
	assert.ElementsMatch(t, expected, names, "enum subcommands should match")
}

// TestEnumCmd_HasMicrosoftSubcommand verifies the microsoft parent is a child
// of enumCmd.
func TestEnumCmd_HasMicrosoftSubcommand(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"enum", "microsoft"})
	require.NoError(t, err)
	assert.Equal(t, "microsoft", cmd.Name())
}

// TestMicrosoftCmd_HasSharepointSubcommand verifies that sharepoint is nested
// under enum microsoft (not directly under enum or root).
func TestMicrosoftCmd_HasSharepointSubcommand(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"enum", "microsoft", "sharepoint"})
	require.NoError(t, err)
	assert.Equal(t, "sharepoint", cmd.Name())
}

// TestRootCmd_OldCommandsAreHidden verifies that the 8 old commands
// are NOT visible top-level commands. rootCmd.Find still resolves them (they
// exist as hidden aliases), but this test confirms they are marked Hidden so
// they don't appear in help output.
func TestRootCmd_OldCommandsAreHidden(t *testing.T) {
	oldCommands := []string{"github", "gitlab", "slack", "notion", "linear", "confluence", "jira", "sharepoint"}

	for _, name := range oldCommands {
		t.Run(name, func(t *testing.T) {
			cmd, _, err := rootCmd.Find([]string{name})
			require.NoError(t, err, "alias %q should still be findable", name)
			assert.True(t, cmd.Hidden, "alias %q should be hidden from help output", name)
		})
	}
}

// TestRootCmd_OldCommandsAreDeprecated verifies that each alias carries a
// non-empty Deprecated message so Cobra prints the deprecation warning.
func TestRootCmd_OldCommandsAreDeprecated(t *testing.T) {
	oldCommands := []string{"github", "gitlab", "slack", "notion", "linear", "confluence", "jira", "sharepoint"}

	for _, name := range oldCommands {
		t.Run(name, func(t *testing.T) {
			cmd, _, err := rootCmd.Find([]string{name})
			require.NoError(t, err)
			assert.NotEmpty(t, cmd.Deprecated, "alias %q should have a Deprecated message", name)
		})
	}
}

// ---------------------------------------------------------------------------
// Flag inheritance: enum persistent flags
// ---------------------------------------------------------------------------

// TestEnumCmd_PersistentFlags verifies that each of the 7 shared scan flags is
// registered as a persistent flag on enumCmd (so all service subcommands
// inherit them without re-registering).
func TestEnumCmd_PersistentFlags(t *testing.T) {
	sharedFlags := []struct {
		name     string
		defValue string
	}{
		{"output", "titus.db"},
		{"format", "human"},
		{"rules", ""},
		{"rules-include", ""},
		{"rules-exclude", ""},
		{"ruleset", "default"},
		{"include-noisy", "false"},
	}

	for _, tf := range sharedFlags {
		t.Run(tf.name, func(t *testing.T) {
			flag := enumCmd.PersistentFlags().Lookup(tf.name)
			require.NotNil(t, flag, "--enum persistent flag --%s should exist", tf.name)
			assert.Equal(t, tf.defValue, flag.DefValue, "--%s default", tf.name)
		})
	}
}

// TestEnumServiceSubcmd_InheritsSharedFlags verifies that a representative
// service subcommand (confluence) can resolve the shared flags inherited from
// enumCmd's persistent flags.
func TestEnumServiceSubcmd_InheritsSharedFlags(t *testing.T) {
	// Use Find so we exercise the real command hierarchy.
	cmd, _, err := rootCmd.Find([]string{"enum", "confluence"})
	require.NoError(t, err)

	// InheritedFlags() returns flags from all ancestors' PersistentFlags.
	for _, name := range []string{"output", "format", "rules", "ruleset", "include-noisy"} {
		flag := cmd.InheritedFlags().Lookup(name)
		require.NotNil(t, flag, "enum confluence should inherit --%s from enum parent", name)
	}
}

// TestEnumGitHubCmd_InheritsSharedFlags does the same for the github subcommand,
// which has extra clone-specific flags of its own.
func TestEnumGitHubCmd_InheritsSharedFlags(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"enum", "github"})
	require.NoError(t, err)

	for _, name := range []string{"output", "format", "rules", "ruleset", "include-noisy"} {
		flag := cmd.InheritedFlags().Lookup(name)
		require.NotNil(t, flag, "enum github should inherit --%s from enum parent", name)
	}
}

// TestEnumGitLabCmd_InheritsSharedFlags does the same for gitlab.
func TestEnumGitLabCmd_InheritsSharedFlags(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"enum", "gitlab"})
	require.NoError(t, err)

	for _, name := range []string{"output", "format", "rules", "ruleset", "include-noisy"} {
		flag := cmd.InheritedFlags().Lookup(name)
		require.NotNil(t, flag, "enum gitlab should inherit --%s from enum parent", name)
	}
}

// ---------------------------------------------------------------------------
// Flag inheritance: microsoft persistent auth flags
// ---------------------------------------------------------------------------

// TestMicrosoftCmd_PersistentAuthFlags verifies the 4 auth flags are registered
// as persistent flags on microsoftCmd with the correct defaults.
func TestMicrosoftCmd_PersistentAuthFlags(t *testing.T) {
	authFlags := []struct {
		name     string
		defValue string
	}{
		{"token", ""},
		{"refresh-token", ""},
		{"client-id", "1950a258-227b-4e31-a9cf-717495945fc2"}, // auth.AzurePowerShellClientID
		{"tenant-id", "organizations"},                         // auth.DefaultTenantID
	}

	for _, tf := range authFlags {
		t.Run(tf.name, func(t *testing.T) {
			flag := microsoftCmd.PersistentFlags().Lookup(tf.name)
			require.NotNil(t, flag, "microsoft persistent flag --%s should exist", tf.name)
			assert.Equal(t, tf.defValue, flag.DefValue, "--%s default", tf.name)
		})
	}
}

// TestSharepointCmd_InheritsMicrosoftAuthFlags verifies that sharepoint (a child
// of microsoft) can resolve all 4 auth flags via inheritance, not by
// re-registering them.
func TestSharepointCmd_InheritsMicrosoftAuthFlags(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"enum", "microsoft", "sharepoint"})
	require.NoError(t, err)

	for _, name := range []string{"token", "refresh-token", "client-id", "tenant-id"} {
		flag := cmd.InheritedFlags().Lookup(name)
		require.NotNil(t, flag, "sharepoint should inherit --%s from microsoft parent", name)
	}
}

// TestSharepointCmd_HasSiteFlagLocally verifies --site is a local flag on
// sharepoint (not inherited), with an empty default.
func TestSharepointCmd_HasSiteFlagLocally(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"enum", "microsoft", "sharepoint"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("site")
	require.NotNil(t, flag, "sharepoint should have a local --site flag")
	assert.Equal(t, "", flag.DefValue, "--site default should be empty (all sites)")
}

// TestSharepointCmd_InheritsEnumSharedFlags verifies that sharepoint also
// inherits the shared output/format/rules flags from the enum grandparent.
func TestSharepointCmd_InheritsEnumSharedFlags(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"enum", "microsoft", "sharepoint"})
	require.NoError(t, err)

	for _, name := range []string{"output", "format", "rules", "ruleset", "include-noisy"} {
		flag := cmd.InheritedFlags().Lookup(name)
		require.NotNil(t, flag, "sharepoint should inherit --%s from enum grandparent", name)
	}
}

// ---------------------------------------------------------------------------
// Backward-compat: hidden aliases still accept the old flag sets
// ---------------------------------------------------------------------------

// TestSharepointAlias_HasClientIDFlag verifies that the old top-level sharepoint
// alias still exposes --client-id so scripts using the old path keep working.
func TestSharepointAlias_HasClientIDFlag(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"sharepoint"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("client-id")
	require.NotNil(t, flag, "sharepoint alias should have --client-id flag for backward compat")
	assert.Equal(t, "1950a258-227b-4e31-a9cf-717495945fc2", flag.DefValue)
}

// TestSharepointAlias_HasSiteFlag verifies the old sharepoint alias retains --site.
func TestSharepointAlias_HasSiteFlag(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"sharepoint"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("site")
	require.NotNil(t, flag, "sharepoint alias should have --site flag for backward compat")
}

// TestSharepointAlias_HasOutputFlag verifies the old sharepoint alias retains
// the shared --output flag.
func TestSharepointAlias_HasOutputFlag(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"sharepoint"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("output")
	require.NotNil(t, flag, "sharepoint alias should have --output flag for backward compat")
	assert.Equal(t, "titus.db", flag.DefValue)
}

// TestConfluenceAlias_HasTokenFlag verifies the confluence alias retains --token.
func TestConfluenceAlias_HasTokenFlag(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"confluence"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("token")
	require.NotNil(t, flag, "confluence alias should have --token flag for backward compat")
}

// TestLinearAlias_HasOutputFlag verifies that the linear alias (a simple API
// command) retains the shared --output flag.
func TestLinearAlias_HasOutputFlag(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"linear"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("output")
	require.NotNil(t, flag, "linear alias should have --output flag for backward compat")
}

// TestGitHubAlias_HasNoCloneFlag verifies the github alias retains clone-specific
// flags so scripts using "titus github --no-clone ..." keep working.
func TestGitHubAlias_HasNoCloneFlag(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"github"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("no-clone")
	require.NotNil(t, flag, "github alias should have --no-clone flag for backward compat")
}

// TestGitLabAlias_HasGitFlag verifies the gitlab alias retains the --git flag.
func TestGitLabAlias_HasGitFlag(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"gitlab"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("git")
	require.NotNil(t, flag, "gitlab alias should have --git flag for backward compat")
}

// TestGitHubAlias_ScanSubcmdIsHiddenAndDeprecated verifies that the github
// alias's nested scan subcommand is also hidden and deprecated.
func TestGitHubAlias_ScanSubcmdIsHiddenAndDeprecated(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"github", "scan"})
	require.NoError(t, err)

	assert.True(t, cmd.Hidden, "github alias scan subcommand should be hidden")
	assert.NotEmpty(t, cmd.Deprecated, "github alias scan subcommand should have deprecation message")
}

// TestGitLabAlias_ScanSubcmdIsHiddenAndDeprecated does the same for gitlab.
func TestGitLabAlias_ScanSubcmdIsHiddenAndDeprecated(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"gitlab", "scan"})
	require.NoError(t, err)

	assert.True(t, cmd.Hidden, "gitlab alias scan subcommand should be hidden")
	assert.NotEmpty(t, cmd.Deprecated, "gitlab alias scan subcommand should have deprecation message")
}

// ---------------------------------------------------------------------------
// runEnumScan: format validation and JSON output
// ---------------------------------------------------------------------------

// TestRunEnumScan_InvalidFormatReturnsError asserts that runEnumScan returns an
// error immediately when --format is set to an unsupported value.  The
// validation fires before any enumerator is constructed, so a nil enumerator
// is safe to pass here.
func TestRunEnumScan_InvalidFormatReturnsError(t *testing.T) {
	// Save and restore the global so parallel test runs are not affected.
	orig := enumFormat
	defer func() { enumFormat = orig }()

	enumFormat = "jsn"

	cmd := &cobra.Command{}
	err := runEnumScan(cmd, nil, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jsn")
	assert.Contains(t, err.Error(), "unsupported output format")
}

// TestRunEnumScan_JSONFormatNoSummaryLine locks in the fix that prevents
// human-readable summary lines from appearing when --format json is set.
// A real FilesystemEnumerator over a temp directory with a single innocuous
// text file is used so the test exercises the full pipeline without mocking.
func TestRunEnumScan_JSONFormatNoSummaryLine(t *testing.T) {
	// --- globals: save and restore ---
	origFormat := enumFormat
	origOutput := enumOutput
	origRulesPath := enumRulesPath
	origRulesInclude := enumRulesInclude
	origRulesExclude := enumRulesExclude
	origRuleset := enumRuleset
	origIncludeNoisy := enumIncludeNoisy
	defer func() {
		enumFormat = origFormat
		enumOutput = origOutput
		enumRulesPath = origRulesPath
		enumRulesInclude = origRulesInclude
		enumRulesExclude = origRulesExclude
		enumRuleset = origRuleset
		enumIncludeNoisy = origIncludeNoisy
	}()

	enumFormat = "json"
	enumOutput = ":memory:"
	enumRulesPath = ""
	enumRulesInclude = ""
	enumRulesExclude = ""
	enumRuleset = "default"
	enumIncludeNoisy = false

	// Create a temp directory with one innocuous text file (no secrets).
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(tmpDir+"/hello.txt", []byte("hello world\n"), 0644))

	enumerator := enum.NewFilesystemEnumerator(enum.Config{Root: tmpDir})

	// Capture stdout via cobra's output writer.
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetContext(context.Background())

	err := runEnumScan(cmd, enumerator, "filesystem")
	require.NoError(t, err)

	out := buf.String()

	// The JSON branch must NOT emit the human-readable summary line.
	assert.NotContains(t, out, "scan complete", "json format must not emit human summary line")

	// The output must be valid JSON (an array, possibly empty).
	var result []types.Match
	require.NoError(t, json.Unmarshal([]byte(out), &result), "stdout must be valid JSON array")
}
