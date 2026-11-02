package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExploreCommand_Exists(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"explore"})
	require.NoError(t, err)
	assert.Equal(t, "explore", cmd.Name())
}

func TestExploreCommand_DefaultDatastore(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"explore"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("datastore")
	require.NotNil(t, flag, "--datastore flag should exist")
	assert.Equal(t, "titus.ds", flag.DefValue)
}

func TestExploreCommand_RejectsTooManyArgs(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"explore"})
	require.NoError(t, err)
	assert.NotNil(t, cmd.Args, "Args validator should be set")
	assert.Error(t, cmd.Args(cmd, []string{"one", "two"}))
}

// resetDatastoreFlag puts exploreCmd's --datastore flag (value and Changed
// state) back to its default now and again when the test ends, so tests that
// share the package-level command do not depend on run order or -count.
func resetDatastoreFlag(t *testing.T) {
	t.Helper()
	flag := exploreCmd.Flags().Lookup("datastore")
	require.NotNil(t, flag)
	reset := func() {
		require.NoError(t, flag.Value.Set(flag.DefValue))
		flag.Changed = false
	}
	reset()
	t.Cleanup(reset)
}

func TestExploreCommand_PositionalArgOverridesDefault(t *testing.T) {
	resetDatastoreFlag(t)

	err := runExplore(exploreCmd, []string{"/tmp/custom.ds"})
	// runExplore will fail because the datastore doesn't exist,
	// but exploreDatastore should have been set before the error.
	assert.Error(t, err)
	assert.Equal(t, "/tmp/custom.ds", exploreDatastore)
}

func TestExploreCommand_PositionalArgConflictsWithFlag(t *testing.T) {
	resetDatastoreFlag(t)

	cmd, _, err := rootCmd.Find([]string{"explore"})
	require.NoError(t, err)
	require.NoError(t, cmd.Flags().Set("datastore", "/tmp/flagged.ds"))

	err = runExplore(cmd, []string{"/tmp/positional.ds"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot specify both")
}
