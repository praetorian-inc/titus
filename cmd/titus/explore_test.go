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

func TestExploreCommand_PositionalArgOverridesDefault(t *testing.T) {
	old := exploreDatastore
	defer func() { exploreDatastore = old }()

	exploreDatastore = "titus.ds"

	err := runExplore(exploreCmd, []string{"/tmp/custom.ds"})
	// runExplore will fail because the datastore doesn't exist,
	// but exploreDatastore should have been set before the error.
	assert.Error(t, err)
	assert.Equal(t, "/tmp/custom.ds", exploreDatastore)
}

func TestExploreCommand_PositionalArgConflictsWithFlag(t *testing.T) {
	old := exploreDatastore
	defer func() { exploreDatastore = old }()

	cmd, _, err := rootCmd.Find([]string{"explore"})
	require.NoError(t, err)
	require.NoError(t, cmd.Flags().Set("datastore", "/tmp/flagged.ds"))

	err = runExplore(cmd, []string{"/tmp/positional.ds"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot specify both")
}
