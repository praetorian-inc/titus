package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunScan(t *testing.T) {
	// Create a temporary directory with a test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Create a temporary rule file for testing
	rulesFile := filepath.Join(tmpDir, "test-rule.yaml")
	ruleYAML := `rules:
  - id: test.1
    name: Test Rule
    pattern: 'test'
    description: A test rule
`
	err = os.WriteFile(rulesFile, []byte(ruleYAML), 0644)
	require.NoError(t, err)

	// Create a buffer to capture output
	var buf bytes.Buffer

	// Create a test command with our buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	// Reset flags for test
	scanRulesPath = rulesFile
	scanOutputPath = filepath.Join(tmpDir, "scan.db")
	scanOutputFormat = "human"
	scanGit = false
	scanMaxFileSize = 10 * 1024 * 1024
	scanIncludeHidden = false

	// Execute scan command
	err = runScan(cmd, []string{tmpDir})
	require.NoError(t, err)

	// Verify database was created
	_, err = os.Stat(scanOutputPath)
	assert.NoError(t, err, "database file should be created")
}

func TestRunScanInvalidTarget(t *testing.T) {
	// Create a buffer to capture output
	var buf bytes.Buffer

	// Create a test command with our buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	// Reset flags for test
	scanOutputPath = ":memory:"

	// Execute scan command with nonexistent target
	err := runScan(cmd, []string{"/nonexistent/path"})
	assert.Error(t, err, "should error on nonexistent target")
}
