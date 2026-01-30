//go:build wasm

package store

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMemory(t *testing.T) {
	// Act
	store := NewMemory()

	// Assert
	require.NotNil(t, store)
	require.NotNil(t, store.blobs)
	require.NotNil(t, store.findings)
	require.NotNil(t, store.provenance)
}

func TestMemory_AddBlob(t *testing.T) {
	// Arrange
	store := NewMemory()

	blobID := types.ComputeBlobID([]byte("test content"))

	// Act
	err := store.AddBlob(blobID, 12)

	// Assert
	require.NoError(t, err)

	// Verify blob was stored
	exists, err := store.BlobExists(blobID)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestMemory_AddBlob_Duplicate(t *testing.T) {
	// Arrange
	store := NewMemory()

	blobID := types.ComputeBlobID([]byte("test content"))

	// Act - add same blob twice
	err := store.AddBlob(blobID, 12)
	require.NoError(t, err)

	err = store.AddBlob(blobID, 12)

	// Assert - second insert should be ignored (idempotent)
	assert.NoError(t, err)
}

func TestMemory_AddMatch(t *testing.T) {
	// Arrange
	store := NewMemory()

	blobID := types.ComputeBlobID([]byte("test content"))
	err := store.AddBlob(blobID, 12)
	require.NoError(t, err)

	match := &types.Match{
		BlobID:       blobID,
		StructuralID: "abc123",
		RuleID:       "np.test.1",
		RuleName:     "Test Rule",
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 0, End: 10},
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 1, Column: 1},
				End:   types.SourcePoint{Line: 1, Column: 11},
			},
		},
		Groups:  [][]byte{[]byte("group1")},
		Snippet: types.Snippet{Matching: []byte("test")},
	}

	// Act
	err = store.AddMatch(match)

	// Assert
	require.NoError(t, err)

	// Verify match was stored
	matches, err := store.GetMatches(blobID)
	require.NoError(t, err)
	assert.Len(t, matches, 1)
	assert.Equal(t, "abc123", matches[0].StructuralID)
}

func TestMemory_GetMatches(t *testing.T) {
	// Arrange
	store := NewMemory()

	blobID := types.ComputeBlobID([]byte("test content"))
	err := store.AddBlob(blobID, 12)
	require.NoError(t, err)

	match1 := &types.Match{BlobID: blobID, StructuralID: "abc123", RuleID: "np.test.1", RuleName: "Test 1"}
	match2 := &types.Match{BlobID: blobID, StructuralID: "def456", RuleID: "np.test.2", RuleName: "Test 2"}

	err = store.AddMatch(match1)
	require.NoError(t, err)
	err = store.AddMatch(match2)
	require.NoError(t, err)

	// Act
	matches, err := store.GetMatches(blobID)

	// Assert
	require.NoError(t, err)
	assert.Len(t, matches, 2)

	// Test with non-existent blob
	nonExistentBlob := types.ComputeBlobID([]byte("nonexistent"))
	emptyMatches, err := store.GetMatches(nonExistentBlob)
	require.NoError(t, err)
	assert.Empty(t, emptyMatches)
}

func TestMemory_GetAllMatches(t *testing.T) {
	// Arrange
	store := NewMemory()

	blobID1 := types.ComputeBlobID([]byte("content1"))
	blobID2 := types.ComputeBlobID([]byte("content2"))

	err := store.AddBlob(blobID1, 8)
	require.NoError(t, err)
	err = store.AddBlob(blobID2, 8)
	require.NoError(t, err)

	match1 := &types.Match{BlobID: blobID1, StructuralID: "abc123", RuleID: "np.test.1", RuleName: "Test 1"}
	match2 := &types.Match{BlobID: blobID2, StructuralID: "def456", RuleID: "np.test.2", RuleName: "Test 2"}

	err = store.AddMatch(match1)
	require.NoError(t, err)
	err = store.AddMatch(match2)
	require.NoError(t, err)

	// Act
	allMatches, err := store.GetAllMatches()

	// Assert
	require.NoError(t, err)
	assert.Len(t, allMatches, 2)
}

func TestMemory_AddFinding(t *testing.T) {
	// Arrange
	store := NewMemory()

	finding := &types.Finding{
		ID:     "finding123",
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("group1")},
	}

	// Act
	err := store.AddFinding(finding)

	// Assert
	require.NoError(t, err)

	// Verify finding was stored
	exists, err := store.FindingExists("finding123")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestMemory_AddFinding_Duplicate(t *testing.T) {
	// Arrange
	store := NewMemory()

	finding := &types.Finding{
		ID:     "finding123",
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("group1")},
	}

	// Act - add same finding twice
	err := store.AddFinding(finding)
	require.NoError(t, err)

	err = store.AddFinding(finding)

	// Assert - second insert should be deduplicated
	assert.NoError(t, err)

	// Verify only one finding exists
	findings, err := store.GetFindings()
	require.NoError(t, err)
	assert.Len(t, findings, 1)
}

func TestMemory_FindingExists(t *testing.T) {
	// Arrange
	store := NewMemory()

	finding := &types.Finding{
		ID:     "finding123",
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("group1")},
	}
	err := store.AddFinding(finding)
	require.NoError(t, err)

	// Act & Assert - existing finding
	exists, err := store.FindingExists("finding123")
	require.NoError(t, err)
	assert.True(t, exists)

	// Act & Assert - non-existing finding
	exists, err = store.FindingExists("nonexistent")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestMemory_GetFindings(t *testing.T) {
	// Arrange
	store := NewMemory()

	finding1 := &types.Finding{ID: "finding123", RuleID: "np.test.1", Groups: [][]byte{[]byte("group1")}}
	finding2 := &types.Finding{ID: "finding456", RuleID: "np.test.2", Groups: [][]byte{[]byte("group2")}}

	err := store.AddFinding(finding1)
	require.NoError(t, err)
	err = store.AddFinding(finding2)
	require.NoError(t, err)

	// Act
	findings, err := store.GetFindings()

	// Assert
	require.NoError(t, err)
	assert.Len(t, findings, 2)
}

func TestMemory_AddProvenance_File(t *testing.T) {
	// Arrange
	store := NewMemory()

	blobID := types.ComputeBlobID([]byte("test content"))
	err := store.AddBlob(blobID, 12)
	require.NoError(t, err)

	prov := types.FileProvenance{
		FilePath: "/path/to/file.txt",
	}

	// Act
	err = store.AddProvenance(blobID, prov)

	// Assert
	require.NoError(t, err)

	// Verify provenance was stored
	allProv, err := store.GetAllProvenance(blobID)
	require.NoError(t, err)
	assert.Len(t, allProv, 1)
}

func TestMemory_AddProvenance_Git(t *testing.T) {
	// Arrange
	store := NewMemory()

	blobID := types.ComputeBlobID([]byte("test content"))
	err := store.AddBlob(blobID, 12)
	require.NoError(t, err)

	prov := types.GitProvenance{
		RepoPath: "/path/to/repo",
		BlobPath: "src/main.go",
		Commit: &types.CommitMetadata{
			CommitID: "abc123",
		},
	}

	// Act
	err = store.AddProvenance(blobID, prov)

	// Assert
	require.NoError(t, err)

	// Verify provenance was stored
	retrievedProv, err := store.GetProvenance(blobID)
	require.NoError(t, err)
	assert.NotNil(t, retrievedProv)
}

func TestMemory_AddProvenance_Multiple(t *testing.T) {
	// Arrange
	store := NewMemory()

	blobID := types.ComputeBlobID([]byte("test content"))
	err := store.AddBlob(blobID, 12)
	require.NoError(t, err)

	// Act - add multiple provenance records to the same blob
	prov1 := types.FileProvenance{FilePath: "/path/to/file1.txt"}
	err = store.AddProvenance(blobID, prov1)
	require.NoError(t, err)

	prov2 := types.GitProvenance{
		RepoPath: "/path/to/repo",
		BlobPath: "src/main.go",
		Commit:   &types.CommitMetadata{CommitID: "abc123"},
	}
	err = store.AddProvenance(blobID, prov2)
	require.NoError(t, err)

	prov3 := types.FileProvenance{FilePath: "/path/to/file2.txt"}
	err = store.AddProvenance(blobID, prov3)
	require.NoError(t, err)

	// Assert - verify all three provenance records exist
	allProv, err := store.GetAllProvenance(blobID)
	require.NoError(t, err)
	assert.Len(t, allProv, 3, "should have 3 provenance records for the same blob")
}

func TestMemory_GetAllProvenance(t *testing.T) {
	// Arrange
	store := NewMemory()

	blobID := types.ComputeBlobID([]byte("test content"))
	err := store.AddBlob(blobID, 12)
	require.NoError(t, err)

	// Add multiple provenance types
	prov1 := types.FileProvenance{FilePath: "/path/to/file.txt"}
	err = store.AddProvenance(blobID, prov1)
	require.NoError(t, err)

	prov2 := types.GitProvenance{
		RepoPath: "/path/to/repo",
		BlobPath: "src/main.go",
		Commit:   &types.CommitMetadata{CommitID: "abc123"},
	}
	err = store.AddProvenance(blobID, prov2)
	require.NoError(t, err)

	// Act
	allProv, err := store.GetAllProvenance(blobID)

	// Assert
	require.NoError(t, err)
	require.Len(t, allProv, 2, "should return both provenance records")

	// Verify types are correct
	hasFile := false
	hasGit := false
	for _, p := range allProv {
		switch prov := p.(type) {
		case types.FileProvenance:
			hasFile = true
			assert.Equal(t, "/path/to/file.txt", prov.FilePath)
		case types.GitProvenance:
			hasGit = true
			assert.Equal(t, "/path/to/repo", prov.RepoPath)
			assert.Equal(t, "src/main.go", prov.BlobPath)
			assert.Equal(t, "abc123", prov.Commit.CommitID)
		}
	}
	assert.True(t, hasFile, "should have file provenance")
	assert.True(t, hasGit, "should have git provenance")

	// Test with non-existent blob
	nonExistentBlob := types.ComputeBlobID([]byte("nonexistent"))
	emptyProv, err := store.GetAllProvenance(nonExistentBlob)
	require.NoError(t, err)
	assert.Empty(t, emptyProv, "should return empty slice for non-existent blob")
}

func TestMemory_GetProvenance(t *testing.T) {
	// Arrange
	store := NewMemory()

	blobID := types.ComputeBlobID([]byte("test content"))
	err := store.AddBlob(blobID, 12)
	require.NoError(t, err)

	prov := types.FileProvenance{FilePath: "/path/to/file.txt"}
	err = store.AddProvenance(blobID, prov)
	require.NoError(t, err)

	// Act
	retrievedProv, err := store.GetProvenance(blobID)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, retrievedProv)

	fileProv, ok := retrievedProv.(types.FileProvenance)
	assert.True(t, ok, "should be FileProvenance type")
	assert.Equal(t, "/path/to/file.txt", fileProv.FilePath)
}

func TestMemory_BlobExists(t *testing.T) {
	// Arrange
	store := NewMemory()

	blobID := types.ComputeBlobID([]byte("test content"))

	// Act & Assert - blob should not exist initially
	exists, err := store.BlobExists(blobID)
	require.NoError(t, err)
	assert.False(t, exists)

	// Add the blob
	err = store.AddBlob(blobID, 12)
	require.NoError(t, err)

	// Act & Assert - blob should exist now
	exists, err = store.BlobExists(blobID)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestMemory_Close(t *testing.T) {
	// Arrange
	store := NewMemory()

	// Act
	err := store.Close()

	// Assert - Close should be a no-op for in-memory store
	assert.NoError(t, err)
}
