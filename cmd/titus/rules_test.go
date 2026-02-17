package main

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunRulesList(t *testing.T) {
	// Create a buffer to capture output
	var buf bytes.Buffer

	// Create a test command with our buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	// Reset flags for test
	rulesPath = ""
	outputFormat = "table"

	// Execute rules list command (using builtin rules)
	err := runRulesList(cmd, []string{})
	require.NoError(t, err)

	// Verify output contains rule table headers
	output := buf.String()
	assert.Contains(t, output, "ID")
	assert.Contains(t, output, "Name")
}

func TestRunRulesListJSON(t *testing.T) {
	// Create a buffer to capture output
	var buf bytes.Buffer

	// Create a test command with our buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	// Reset flags for test
	rulesPath = ""
	outputFormat = "json"

	// Execute rules list command with JSON output
	err := runRulesList(cmd, []string{})
	require.NoError(t, err)

	// Verify output is valid JSON (either array or null if no builtin rules)
	output := buf.String()
	assert.True(t, output == "null\n" || output[0] == '[', "expected JSON array or null, got: %s", output)
}
