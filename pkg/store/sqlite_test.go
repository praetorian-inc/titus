package store

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSQLite_Memory(t *testing.T) {
	// Act
	store, err := NewSQLite(":memory:")
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()

	// Assert - verify schema was initialized
	var version int
	err = store.db.QueryRow("SELECT version FROM schema_version LIMIT 1").Scan(&version)
	require.NoError(t, err)
	assert.Equal(t, SchemaVersion, version)
}

func TestSQLite_AddBlob(t *testing.T) {
	// Arrange
	store, err := NewSQLite(":memory:")
	require.NoError(t, err)
	defer store.Close()

	blobID := types.ComputeBlobID([]byte("test content"))

	// Act
	err = store.AddBlob(blobID, 12)

	// Assert
	require.NoError(t, err)

	// Verify blob was inserted
	var id string
	var size int64
	err = store.db.QueryRow("SELECT id, size FROM blobs WHERE id = ?", blobID.Hex()).Scan(&id, &size)
	require.NoError(t, err)
	assert.Equal(t, blobID.Hex(), id)
	assert.Equal(t, int64(12), size)
}

func TestSQLite_AddBlob_Duplicate(t *testing.T) {
	// Arrange
	store, err := NewSQLite(":memory:")
	require.NoError(t, err)
	defer store.Close()

	blobID := types.ComputeBlobID([]byte("test content"))

	// Act - add same blob twice
	err = store.AddBlob(blobID, 12)
	require.NoError(t, err)

	err = store.AddBlob(blobID, 12)

	// Assert - second insert should be ignored (INSERT OR IGNORE)
	assert.NoError(t, err)
}

func TestSQLite_AddMatch(t *testing.T) {
	// Arrange
	store, err := NewSQLite(":memory:")
	require.NoError(t, err)
	defer store.Close()

	blobID := types.ComputeBlobID([]byte("test content"))
	err = store.AddBlob(blobID, 12)
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

	// Verify match was inserted
	var count int
	err = store.db.QueryRow("SELECT COUNT(*) FROM matches WHERE structural_id = ?", "abc123").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestSQLite_AddFinding(t *testing.T) {
	// Arrange
	store, err := NewSQLite(":memory:")
	require.NoError(t, err)
	defer store.Close()

	finding := &types.Finding{
		ID:     "finding123",
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("group1")},
	}

	// Act
	err = store.AddFinding(finding)

	// Assert
	require.NoError(t, err)

	// Verify finding was inserted
	var id string
	err = store.db.QueryRow("SELECT structural_id FROM findings WHERE structural_id = ?", "finding123").Scan(&id)
	require.NoError(t, err)
	assert.Equal(t, "finding123", id)
}

func TestSQLite_FindingExists(t *testing.T) {
	// Arrange
	store, err := NewSQLite(":memory:")
	require.NoError(t, err)
	defer store.Close()

	finding := &types.Finding{
		ID:     "finding123",
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("group1")},
	}
	err = store.AddFinding(finding)
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

func TestSQLite_AddProvenance_File(t *testing.T) {
	// Arrange
	store, err := NewSQLite(":memory:")
	require.NoError(t, err)
	defer store.Close()

	blobID := types.ComputeBlobID([]byte("test content"))
	err = store.AddBlob(blobID, 12)
	require.NoError(t, err)

	prov := types.FileProvenance{
		FilePath: "/path/to/file.txt",
	}

	// Act
	err = store.AddProvenance(blobID, prov)

	// Assert
	require.NoError(t, err)

	// Verify provenance was inserted
	var provType, path string
	err = store.db.QueryRow("SELECT type, path FROM provenance WHERE blob_id = ?", blobID.Hex()).Scan(&provType, &path)
	require.NoError(t, err)
	assert.Equal(t, "file", provType)
	assert.Equal(t, "/path/to/file.txt", path)
}

func TestSQLite_AddProvenance_Git(t *testing.T) {
	// Arrange
	store, err := NewSQLite(":memory:")
	require.NoError(t, err)
	defer store.Close()

	blobID := types.ComputeBlobID([]byte("test content"))
	err = store.AddBlob(blobID, 12)
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

	// Verify provenance was inserted
	var provType, repoPath, commitHash string
	err = store.db.QueryRow("SELECT type, repo_path, commit_hash FROM provenance WHERE blob_id = ?", blobID.Hex()).Scan(&provType, &repoPath, &commitHash)
	require.NoError(t, err)
	assert.Equal(t, "git", provType)
	assert.Equal(t, "/path/to/repo", repoPath)
	assert.Equal(t, "abc123", commitHash)
}

func TestSQLite_BlobExists(t *testing.T) {
	// Arrange
	store, err := NewSQLite(":memory:")
	require.NoError(t, err)
	defer store.Close()

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

func TestSQLite_Close(t *testing.T) {
	// Arrange
	store, err := NewSQLite(":memory:")
	require.NoError(t, err)

	// Act
	err = store.Close()

	// Assert
	assert.NoError(t, err)

	// Verify connection is closed (query should fail)
	err = store.db.Ping()
	assert.Error(t, err)
}

func TestSQLite_AddProvenance_Multiple(t *testing.T) {
	// Arrange
	store, err := NewSQLite(":memory:")
	require.NoError(t, err)
	defer store.Close()

	blobID := types.ComputeBlobID([]byte("test content"))
	err = store.AddBlob(blobID, 12)
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
	var count int
	err = store.db.QueryRow("SELECT COUNT(*) FROM provenance WHERE blob_id = ?", blobID.Hex()).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 3, count, "should have 3 provenance records for the same blob")

	// Verify we can retrieve all provenance
	allProv, err := store.GetAllProvenance(blobID)
	require.NoError(t, err)
	assert.Len(t, allProv, 3, "GetAllProvenance should return all 3 records")
}

func TestSQLite_AddProvenance_Deduplication(t *testing.T) {
	// Arrange
	store, err := NewSQLite(":memory:")
	require.NoError(t, err)
	defer store.Close()

	blobID := types.ComputeBlobID([]byte("test content"))
	err = store.AddBlob(blobID, 12)
	require.NoError(t, err)

	prov := types.GitProvenance{
		RepoPath: "/path/to/repo",
		BlobPath: "src/main.go",
		Commit:   &types.CommitMetadata{CommitID: "abc123"},
	}

	// Act - add the same provenance twice
	err = store.AddProvenance(blobID, prov)
	require.NoError(t, err)

	err = store.AddProvenance(blobID, prov)
	require.NoError(t, err, "duplicate insert should be ignored, not error")

	// Assert - verify only one record exists (deduplication worked)
	var count int
	err = store.db.QueryRow("SELECT COUNT(*) FROM provenance WHERE blob_id = ?", blobID.Hex()).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "duplicate provenance should be deduplicated")
}

func TestSQLite_GetAllProvenance(t *testing.T) {
	// Arrange
	store, err := NewSQLite(":memory:")
	require.NoError(t, err)
	defer store.Close()

	blobID := types.ComputeBlobID([]byte("test content"))
	err = store.AddBlob(blobID, 12)
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
