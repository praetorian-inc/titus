package main

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunVersion(t *testing.T) {
	// Create a buffer to capture output
	var buf bytes.Buffer

	// Create a test command with our buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	// Execute version command
	err := runVersion(cmd, []string{})
	require.NoError(t, err)

	// Verify output contains version info
	output := buf.String()
	assert.Contains(t, output, "Titus")
	assert.Contains(t, output, version)
}
