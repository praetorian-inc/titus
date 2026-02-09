//go:build !wasm && cgo

package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMerge_EmptySources(t *testing.T) {
	_, err := Merge(MergeConfig{
		SourcePaths: []string{},
		DestPath:    "/tmp/dest.db",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no source databases")
}

func TestMerge_NoDestination(t *testing.T) {
	_, err := Merge(MergeConfig{
		SourcePaths: []string{"/tmp/source.db"},
		DestPath:    "",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "destination path is required")
}

func TestMerge_SingleSource(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "titus-merge-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create source database with data
	sourcePath := filepath.Join(tmpDir, "source.db")
	source, err := NewSQLite(sourcePath)
	require.NoError(t, err)

	// Add test data
	blobID := types.ComputeBlobID([]byte("test content"))
	err = source.AddBlob(blobID, 12)
	require.NoError(t, err)

	finding := &types.Finding{
		ID:     "finding1",
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("secret")},
	}
	err = source.AddFinding(finding)
	require.NoError(t, err)

	prov := types.FileProvenance{FilePath: "/path/to/file.txt"}
	err = source.AddProvenance(blobID, prov)
	require.NoError(t, err)

	source.Close()

	// Merge to destination
	destPath := filepath.Join(tmpDir, "dest.db")
	stats, err := Merge(MergeConfig{
		SourcePaths: []string{sourcePath},
		DestPath:    destPath,
	})
	require.NoError(t, err)

	// Verify stats
	assert.Equal(t, 1, stats.BlobsMerged)
	assert.Equal(t, 1, stats.FindingsMerged)
	assert.Equal(t, 1, stats.ProvenanceMerged)
	assert.Equal(t, 1, stats.SourcesProcessed)

	// Verify data in destination
	dest, err := NewSQLite(destPath)
	require.NoError(t, err)
	defer dest.Close()

	exists, err := dest.FindingExists("finding1")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestMerge_MultipleSources(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "titus-merge-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create source1 with data
	source1Path := filepath.Join(tmpDir, "source1.db")
	source1, err := NewSQLite(source1Path)
	require.NoError(t, err)

	blobID1 := types.ComputeBlobID([]byte("content1"))
	err = source1.AddBlob(blobID1, 8)
	require.NoError(t, err)
	err = source1.AddFinding(&types.Finding{ID: "finding1", RuleID: "rule1"})
	require.NoError(t, err)
	source1.Close()

	// Create source2 with data
	source2Path := filepath.Join(tmpDir, "source2.db")
	source2, err := NewSQLite(source2Path)
	require.NoError(t, err)

	blobID2 := types.ComputeBlobID([]byte("content2"))
	err = source2.AddBlob(blobID2, 8)
	require.NoError(t, err)
	err = source2.AddFinding(&types.Finding{ID: "finding2", RuleID: "rule2"})
	require.NoError(t, err)
	source2.Close()

	// Merge both sources
	destPath := filepath.Join(tmpDir, "merged.db")
	stats, err := Merge(MergeConfig{
		SourcePaths: []string{source1Path, source2Path},
		DestPath:    destPath,
	})
	require.NoError(t, err)

	// Verify stats
	assert.Equal(t, 2, stats.BlobsMerged)
	assert.Equal(t, 2, stats.FindingsMerged)
	assert.Equal(t, 2, stats.SourcesProcessed)

	// Verify both findings exist in merged database
	dest, err := NewSQLite(destPath)
	require.NoError(t, err)
	defer dest.Close()

	exists1, err := dest.FindingExists("finding1")
	require.NoError(t, err)
	assert.True(t, exists1)

	exists2, err := dest.FindingExists("finding2")
	require.NoError(t, err)
	assert.True(t, exists2)
}

func TestMerge_Deduplication(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "titus-merge-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create two sources with the same data (simulating duplicate finds)
	content := []byte("duplicate content")
	blobID := types.ComputeBlobID(content)

	source1Path := filepath.Join(tmpDir, "source1.db")
	source1, err := NewSQLite(source1Path)
	require.NoError(t, err)
	err = source1.AddBlob(blobID, int64(len(content)))
	require.NoError(t, err)
	err = source1.AddFinding(&types.Finding{ID: "duplicate-finding", RuleID: "rule1"})
	require.NoError(t, err)
	source1.Close()

	source2Path := filepath.Join(tmpDir, "source2.db")
	source2, err := NewSQLite(source2Path)
	require.NoError(t, err)
	// Same blob ID and finding ID
	err = source2.AddBlob(blobID, int64(len(content)))
	require.NoError(t, err)
	err = source2.AddFinding(&types.Finding{ID: "duplicate-finding", RuleID: "rule1"})
	require.NoError(t, err)
	source2.Close()

	// Merge both sources
	destPath := filepath.Join(tmpDir, "merged.db")
	stats, err := Merge(MergeConfig{
		SourcePaths: []string{source1Path, source2Path},
		DestPath:    destPath,
	})
	require.NoError(t, err)

	// First source adds the blob and finding
	// Second source should skip them (deduplication)
	assert.Equal(t, 1, stats.BlobsMerged, "should only merge 1 unique blob")
	assert.Equal(t, 1, stats.FindingsMerged, "should only merge 1 unique finding")
	assert.Equal(t, 2, stats.SourcesProcessed)
}

func TestMerge_WithMatches(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "titus-merge-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create source with match data
	sourcePath := filepath.Join(tmpDir, "source.db")
	source, err := NewSQLite(sourcePath)
	require.NoError(t, err)

	blobID := types.ComputeBlobID([]byte("test content with secret"))
	err = source.AddBlob(blobID, 25)
	require.NoError(t, err)

	match := &types.Match{
		BlobID:       blobID,
		RuleID:       "np.test.1",
		StructuralID: "match-struct-id",
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 10, End: 16},
		},
		Snippet: types.Snippet{Matching: []byte("secret")},
		Groups:  [][]byte{[]byte("secret")},
	}
	err = source.AddMatch(match)
	require.NoError(t, err)
	source.Close()

	// Merge
	destPath := filepath.Join(tmpDir, "dest.db")
	stats, err := Merge(MergeConfig{
		SourcePaths: []string{sourcePath},
		DestPath:    destPath,
	})
	require.NoError(t, err)

	assert.Equal(t, 1, stats.MatchesMerged)

	// Verify match exists in destination
	dest, err := NewSQLite(destPath)
	require.NoError(t, err)
	defer dest.Close()

	matches, err := dest.GetMatches(blobID)
	require.NoError(t, err)
	assert.Len(t, matches, 1)
	assert.Equal(t, "np.test.1", matches[0].RuleID)
}
