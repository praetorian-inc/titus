package main

import (
	"bytes"
	"os"
	"os/exec"
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

func TestRunScanGitAutoDetection(t *testing.T) {
	// Create a temporary directory and initialize a real git repository
	tmpDir := t.TempDir()

	// Initialize git repository
	err := os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("test content"), 0644)
	require.NoError(t, err)

	// Run git init to create a proper git repository
	gitInitCmd := exec.Command("git", "init")
	gitInitCmd.Dir = tmpDir
	err = gitInitCmd.Run()
	if err != nil {
		t.Skip("git not available, skipping git auto-detection test")
	}

	// Configure git (required for commits)
	gitConfigName := exec.Command("git", "config", "user.name", "Test User")
	gitConfigName.Dir = tmpDir
	_ = gitConfigName.Run()

	gitConfigEmail := exec.Command("git", "config", "user.email", "test@example.com")
	gitConfigEmail.Dir = tmpDir
	_ = gitConfigEmail.Run()

	// Add and commit the test file
	gitAdd := exec.Command("git", "add", "test.txt")
	gitAdd.Dir = tmpDir
	_ = gitAdd.Run()

	gitCommit := exec.Command("git", "commit", "-m", "Initial commit")
	gitCommit.Dir = tmpDir
	_ = gitCommit.Run()

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
	var errBuf bytes.Buffer

	// Create a test command with our buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetErr(&errBuf)

	// Reset flags for test - DON'T set scanGit to true (we want auto-detection)
	scanRulesPath = rulesFile
	scanOutputPath = filepath.Join(tmpDir, "scan.db")
	scanOutputFormat = "human"
	scanGit = false // Not explicitly set - should auto-detect
	scanNoGit = false
	scanMaxFileSize = 10 * 1024 * 1024
	scanIncludeHidden = false

	// Execute scan command
	err = runScan(cmd, []string{tmpDir})
	require.NoError(t, err)

	// Verify output contains auto-detection message
	output := buf.String() + errBuf.String()
	assert.Contains(t, output, "Detected git repository, scanning git history",
		"should print auto-detection message")

	// Verify database was created
	_, err = os.Stat(scanOutputPath)
	assert.NoError(t, err, "database file should be created")
}

func TestRunScanNoGitFlag(t *testing.T) {
	// Create a temporary directory and initialize a real git repository
	tmpDir := t.TempDir()

	// Initialize git repository
	err := os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("test content"), 0644)
	require.NoError(t, err)

	// Run git init to create a proper git repository
	gitInitCmd := exec.Command("git", "init")
	gitInitCmd.Dir = tmpDir
	err = gitInitCmd.Run()
	if err != nil {
		t.Skip("git not available, skipping --no-git flag test")
	}

	// Configure git (required for commits)
	gitConfigName := exec.Command("git", "config", "user.name", "Test User")
	gitConfigName.Dir = tmpDir
	_ = gitConfigName.Run()

	gitConfigEmail := exec.Command("git", "config", "user.email", "test@example.com")
	gitConfigEmail.Dir = tmpDir
	_ = gitConfigEmail.Run()

	// Add and commit the test file
	gitAdd := exec.Command("git", "add", "test.txt")
	gitAdd.Dir = tmpDir
	_ = gitAdd.Run()

	gitCommit := exec.Command("git", "commit", "-m", "Initial commit")
	gitCommit.Dir = tmpDir
	_ = gitCommit.Run()

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
	var errBuf bytes.Buffer

	// Create a test command with our buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetErr(&errBuf)

	// Reset flags for test - set scanNoGit to disable git even though it's a git repo
	scanRulesPath = rulesFile
	scanOutputPath = filepath.Join(tmpDir, "scan.db")
	scanOutputFormat = "human"
	scanGit = false
	scanNoGit = true // Explicitly disable git scanning
	scanMaxFileSize = 10 * 1024 * 1024
	scanIncludeHidden = false

	// Execute scan command
	err = runScan(cmd, []string{tmpDir})
	require.NoError(t, err)

	// Verify output does NOT contain auto-detection message
	output := buf.String() + errBuf.String()
	assert.NotContains(t, output, "Detected git repository",
		"should NOT print auto-detection message when --no-git is used")

	// Verify database was created
	_, err = os.Stat(scanOutputPath)
	assert.NoError(t, err, "database file should be created")
}
