package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMergeCmd creates a fresh merge command for testing
func newMergeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "merge <source1.db> <source2.db> [source3.db...]",
		Short: "Merge multiple Titus databases",
		Args:  cobra.MinimumNArgs(2),
		RunE:  runMerge,
	}
	cmd.Flags().StringVarP(&mergeOutput, "output", "o", "merged.db", "Output database path")
	return cmd
}

func TestMergeCmd_RequiresMinimumArgs(t *testing.T) {
	// Test with no args - the Args validator should reject
	cmd := newMergeCmd()
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires at least 2 arg")

	// Test with one arg
	cmd = newMergeCmd()
	cmd.SetArgs([]string{"source1.db"})
	err = cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires at least 2 arg")
}

func TestMergeCmd_MergesTwoDatabases(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "titus-merge-cmd-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create source1 with data
	source1Path := filepath.Join(tmpDir, "source1.db")
	source1, err := store.NewSQLite(source1Path)
	require.NoError(t, err)
	err = source1.AddBlob(types.ComputeBlobID([]byte("content1")), 8)
	require.NoError(t, err)
	err = source1.AddFinding(&types.Finding{ID: "finding1", RuleID: "rule1"})
	require.NoError(t, err)
	source1.Close()

	// Create source2 with data
	source2Path := filepath.Join(tmpDir, "source2.db")
	source2, err := store.NewSQLite(source2Path)
	require.NoError(t, err)
	err = source2.AddBlob(types.ComputeBlobID([]byte("content2")), 8)
	require.NoError(t, err)
	err = source2.AddFinding(&types.Finding{ID: "finding2", RuleID: "rule2"})
	require.NoError(t, err)
	source2.Close()

	// Run merge command
	destPath := filepath.Join(tmpDir, "merged.db")
	var buf bytes.Buffer
	cmd := newMergeCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{source1Path, source2Path, "--output", destPath})

	err = cmd.Execute()
	require.NoError(t, err)

	// Verify output
	output := buf.String()
	assert.Contains(t, output, "Merge complete")
	assert.Contains(t, output, "Sources processed: 2")
	assert.Contains(t, output, "Blobs merged: 2")
	assert.Contains(t, output, "Findings merged: 2")

	// Verify merged database
	dest, err := store.NewSQLite(destPath)
	require.NoError(t, err)
	defer dest.Close()

	exists1, _ := dest.FindingExists("finding1")
	exists2, _ := dest.FindingExists("finding2")
	assert.True(t, exists1)
	assert.True(t, exists2)
}

func TestMergeCmd_ReportsDeduplication(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "titus-merge-cmd-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create two sources with duplicate data
	content := []byte("same content")
	blobID := types.ComputeBlobID(content)

	source1Path := filepath.Join(tmpDir, "source1.db")
	source1, err := store.NewSQLite(source1Path)
	require.NoError(t, err)
	err = source1.AddBlob(blobID, int64(len(content)))
	require.NoError(t, err)
	err = source1.AddFinding(&types.Finding{ID: "same-finding", RuleID: "rule1"})
	require.NoError(t, err)
	source1.Close()

	source2Path := filepath.Join(tmpDir, "source2.db")
	source2, err := store.NewSQLite(source2Path)
	require.NoError(t, err)
	err = source2.AddBlob(blobID, int64(len(content)))
	require.NoError(t, err)
	err = source2.AddFinding(&types.Finding{ID: "same-finding", RuleID: "rule1"})
	require.NoError(t, err)
	source2.Close()

	// Run merge command
	destPath := filepath.Join(tmpDir, "merged.db")
	var buf bytes.Buffer
	cmd := newMergeCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{source1Path, source2Path, "--output", destPath})

	err = cmd.Execute()
	require.NoError(t, err)

	// Verify output shows deduplication (only 1 blob, 1 finding even though 2 sources)
	output := buf.String()
	assert.Contains(t, output, "Blobs merged: 1")
	assert.Contains(t, output, "Findings merged: 1")
}

func TestMergeCmd_FailsWithInvalidSource(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "titus-merge-cmd-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Run merge command with non-existent source
	destPath := filepath.Join(tmpDir, "merged.db")
	cmd := newMergeCmd()
	cmd.SetArgs([]string{"/nonexistent/source1.db", "/nonexistent/source2.db", "--output", destPath})

	err = cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "merge failed")
}
