package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitLabScanCommand_NoCloneFlag(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"gitlab", "scan"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("no-clone")
	require.NotNil(t, flag, "--no-clone flag should exist")
	assert.Equal(t, "false", flag.DefValue)
}

func TestGitLabScanCommand_TokenOptional(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"gitlab", "scan"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("token")
	require.NotNil(t, flag, "--token flag should exist")
	assert.Equal(t, "", flag.DefValue, "token should have empty default (optional)")
}

func TestGitLabCmd_Exists(t *testing.T) {
	// Verify gitlab command exists
	if gitlabCmd == nil {
		t.Error("gitlabCmd is nil")
	}
}

func TestGitLabCmd_Use(t *testing.T) {
	// Verify command use string
	expected := "gitlab [namespace/project]"
	if gitlabCmd.Use != expected {
		t.Errorf("expected Use=%q, got %q", expected, gitlabCmd.Use)
	}
}

func TestGitLabScanCmd_Exists(t *testing.T) {
	// Verify gitlab scan subcommand exists
	if gitlabScanCmd == nil {
		t.Error("gitlabScanCmd is nil")
	}
}

func TestGitLabScanCmd_Use(t *testing.T) {
	// Verify scan command use string
	expected := "scan [namespace/project]"
	if gitlabScanCmd.Use != expected {
		t.Errorf("expected Use=%q, got %q", expected, gitlabScanCmd.Use)
	}
}

func TestGitLabScanCmd_Flags(t *testing.T) {
	// Verify required flags exist
	flags := gitlabScanCmd.Flags()

	if flags.Lookup("token") == nil {
		t.Error("--token flag not defined")
	}
	if flags.Lookup("group") == nil {
		t.Error("--group flag not defined")
	}
	if flags.Lookup("user") == nil {
		t.Error("--user flag not defined")
	}
	if flags.Lookup("url") == nil {
		t.Error("--url flag not defined")
	}
	if flags.Lookup("output") == nil {
		t.Error("--output flag not defined")
	}
	if flags.Lookup("format") == nil {
		t.Error("--format flag not defined")
	}
}

func TestGitLabScanCmd_FlagDefaults(t *testing.T) {
	// Verify flag defaults
	flags := gitlabScanCmd.Flags()

	outputFlag := flags.Lookup("output")
	if outputFlag != nil && outputFlag.DefValue != "titus.db" {
		t.Errorf("expected output default='titus.db', got %q", outputFlag.DefValue)
	}

	formatFlag := flags.Lookup("format")
	if formatFlag != nil && formatFlag.DefValue != "human" {
		t.Errorf("expected format default='human', got %q", formatFlag.DefValue)
	}
}

func TestGitLabCmd_HasScanSubcommand(t *testing.T) {
	// Verify gitlab command has scan subcommand
	found := false
	for _, cmd := range gitlabCmd.Commands() {
		if cmd.Name() == "scan" {
			found = true
			break
		}
	}

	if !found {
		t.Error("gitlab command does not have 'scan' subcommand")
	}
}

func TestGitLabScanCommand_GitFlag(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"gitlab", "scan"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("git")
	require.NotNil(t, flag, "--git flag should exist")
	assert.Equal(t, "false", flag.DefValue)
}
