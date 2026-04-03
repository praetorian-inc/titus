//go:build !wasm

package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLite_SchemaWithLocationColumns(t *testing.T) {
	// Arrange
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	store, err := NewSQLite(dbPath)
	require.NoError(t, err)
	defer store.Close()

	blobID := types.ComputeBlobID([]byte("test content"))
	err = store.AddBlob(blobID, 12)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:           "np.test.1",
		Name:         "Test Rule",
		Pattern:      "test",
		StructuralID: "struct123",
	}
	err = store.AddRule(rule)
	require.NoError(t, err)

	// Create match with location data
	match := &types.Match{
		BlobID:       blobID,
		StructuralID: "match123",
		RuleID:       "np.test.1",
		RuleName:     "Test Rule",
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 10, End: 20},
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 5, Column: 3},
				End:   types.SourcePoint{Line: 7, Column: 15},
			},
		},
		Snippet: types.Snippet{Matching: []byte("test match")},
	}

	// Act - Add match
	err = store.AddMatch(match)
	require.NoError(t, err)

	// Retrieve match
	matches, err := store.GetMatches(blobID)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	// Assert - Verify location data persisted correctly
	retrieved := matches[0]
	assert.Equal(t, int64(10), retrieved.Location.Offset.Start)
	assert.Equal(t, int64(20), retrieved.Location.Offset.End)
	assert.Equal(t, 5, retrieved.Location.Source.Start.Line)
	assert.Equal(t, 3, retrieved.Location.Source.Start.Column)
	assert.Equal(t, 7, retrieved.Location.Source.End.Line)
	assert.Equal(t, 15, retrieved.Location.Source.End.Column)
}

func TestSQLite_GetAllMatchesWithLocation(t *testing.T) {
	// Arrange
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	store, err := NewSQLite(dbPath)
	require.NoError(t, err)
	defer store.Close()

	blobID1 := types.ComputeBlobID([]byte("content1"))
	blobID2 := types.ComputeBlobID([]byte("content2"))

	err = store.AddBlob(blobID1, 8)
	require.NoError(t, err)
	err = store.AddBlob(blobID2, 8)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:           "np.test.1",
		Name:         "Test Rule",
		Pattern:      "test",
		StructuralID: "struct123",
	}
	err = store.AddRule(rule)
	require.NoError(t, err)

	match1 := &types.Match{
		BlobID:       blobID1,
		StructuralID: "match1",
		RuleID:       "np.test.1",
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 0, End: 5},
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 1, Column: 1},
				End:   types.SourcePoint{Line: 1, Column: 6},
			},
		},
	}

	match2 := &types.Match{
		BlobID:       blobID2,
		StructuralID: "match2",
		RuleID:       "np.test.1",
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 10, End: 15},
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 2, Column: 5},
				End:   types.SourcePoint{Line: 3, Column: 1},
			},
		},
	}

	err = store.AddMatch(match1)
	require.NoError(t, err)
	err = store.AddMatch(match2)
	require.NoError(t, err)

	// Act
	allMatches, err := store.GetAllMatches()

	// Assert
	require.NoError(t, err)
	require.Len(t, allMatches, 2)

	// Verify both matches have location data
	for _, m := range allMatches {
		assert.NotZero(t, m.Location.Source.Start.Line, "Start line should be populated")
		assert.NotZero(t, m.Location.Source.Start.Column, "Start column should be populated")
		assert.NotZero(t, m.Location.Source.End.Line, "End line should be populated")
		assert.NotZero(t, m.Location.Source.End.Column, "End column should be populated")
	}
}

func TestSQLite_GetMatchesRuleName(t *testing.T) {
	// Arrange
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	store, err := NewSQLite(dbPath)
	require.NoError(t, err)
	defer store.Close()

	blobID := types.ComputeBlobID([]byte("test content"))
	err = store.AddBlob(blobID, 12)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:           "np.test.1",
		Name:         "Test Rule",
		Pattern:      "test",
		StructuralID: "struct123",
	}
	err = store.AddRule(rule)
	require.NoError(t, err)

	// Create match without RuleName — the store should populate it
	match := &types.Match{
		BlobID:       blobID,
		StructuralID: "match123",
		RuleID:       "np.test.1",
		Location:     types.Location{Offset: types.OffsetSpan{Start: 0, End: 10}},
		Snippet:      types.Snippet{Matching: []byte("test")},
	}

	err = store.AddMatch(match)
	require.NoError(t, err)

	// Act
	matches, err := store.GetMatches(blobID)

	// Assert
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, "Test Rule", matches[0].RuleName)
}

func TestSQLite_GetAllMatchesRuleName(t *testing.T) {
	// Arrange
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	store, err := NewSQLite(dbPath)
	require.NoError(t, err)
	defer store.Close()

	blobID1 := types.ComputeBlobID([]byte("content1"))
	blobID2 := types.ComputeBlobID([]byte("content2"))

	err = store.AddBlob(blobID1, 8)
	require.NoError(t, err)
	err = store.AddBlob(blobID2, 8)
	require.NoError(t, err)

	rule1 := &types.Rule{
		ID:           "np.test.1",
		Name:         "Test Rule 1",
		Pattern:      "test1",
		StructuralID: "struct123",
	}
	rule2 := &types.Rule{
		ID:           "np.test.2",
		Name:         "Test Rule 2",
		Pattern:      "test2",
		StructuralID: "struct456",
	}
	err = store.AddRule(rule1)
	require.NoError(t, err)
	err = store.AddRule(rule2)
	require.NoError(t, err)

	// Create matches without RuleName — the store should populate it
	match1 := &types.Match{
		BlobID:       blobID1,
		StructuralID: "match1",
		RuleID:       "np.test.1",
		Location:     types.Location{Offset: types.OffsetSpan{Start: 0, End: 5}},
	}
	match2 := &types.Match{
		BlobID:       blobID2,
		StructuralID: "match2",
		RuleID:       "np.test.2",
		Location:     types.Location{Offset: types.OffsetSpan{Start: 0, End: 5}},
	}

	err = store.AddMatch(match1)
	require.NoError(t, err)
	err = store.AddMatch(match2)
	require.NoError(t, err)

	// Act
	allMatches, err := store.GetAllMatches()

	// Assert
	require.NoError(t, err)
	require.Len(t, allMatches, 2)

	ruleNames := make(map[string]string)
	for _, m := range allMatches {
		ruleNames[m.RuleID] = m.RuleName
	}
	assert.Equal(t, "Test Rule 1", ruleNames["np.test.1"])
	assert.Equal(t, "Test Rule 2", ruleNames["np.test.2"])
}

func TestSQLite_NullLocationValues(t *testing.T) {
	// Test that matches without location data (finding_id and line/column nulls) work correctly
	// This ensures backward compatibility

	// Arrange
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	store, err := NewSQLite(dbPath)
	require.NoError(t, err)
	defer store.Close()

	blobID := types.ComputeBlobID([]byte("test content"))
	err = store.AddBlob(blobID, 12)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:           "np.test.1",
		Name:         "Test Rule",
		Pattern:      "test",
		StructuralID: "struct123",
	}
	err = store.AddRule(rule)
	require.NoError(t, err)

	// Create match WITHOUT location source data (only offsets)
	match := &types.Match{
		BlobID:       blobID,
		StructuralID: "match_no_location",
		RuleID:       "np.test.1",
		RuleName:     "Test Rule",
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 0, End: 10},
			Source: types.SourceSpan{}, // Zero values - no line/column data
		},
		Snippet: types.Snippet{Matching: []byte("test")},
	}

	// Act
	err = store.AddMatch(match)
	require.NoError(t, err)

	// Retrieve
	matches, err := store.GetMatches(blobID)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	// Assert - Zero values should be preserved
	retrieved := matches[0]
	assert.Equal(t, 0, retrieved.Location.Source.Start.Line)
	assert.Equal(t, 0, retrieved.Location.Source.Start.Column)
	assert.Equal(t, 0, retrieved.Location.Source.End.Line)
	assert.Equal(t, 0, retrieved.Location.Source.End.Column)
}

func TestSQLite_ProvenanceWithCommitMetadata(t *testing.T) {
	dir := t.TempDir()
	store, err := New(Config{Path: filepath.Join(dir, "test.db")})
	require.NoError(t, err)
	defer store.Close()

	blobID := types.ComputeBlobID([]byte("secret content"))
	err = store.AddBlob(blobID, 14)
	require.NoError(t, err)

	authorTS := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	committerTS := time.Date(2024, 3, 15, 11, 0, 0, 0, time.UTC)

	prov := types.GitProvenance{
		RepoPath: "/tmp/repo",
		BlobPath: "config.yml",
		Commit: &types.CommitMetadata{
			CommitID:           "abc123def456",
			AuthorName:         "John Doe",
			AuthorEmail:        "john@example.com",
			AuthorTimestamp:    authorTS,
			CommitterName:      "Jane Smith",
			CommitterEmail:     "jane@example.com",
			CommitterTimestamp: committerTS,
			Message:            "add config",
		},
	}

	err = store.AddProvenance(blobID, prov)
	require.NoError(t, err)

	provs, err := store.GetAllProvenance(blobID)
	require.NoError(t, err)
	require.Len(t, provs, 1)

	got, ok := provs[0].(types.GitProvenance)
	require.True(t, ok)
	assert.Equal(t, "/tmp/repo", got.RepoPath)
	assert.Equal(t, "config.yml", got.BlobPath)
	require.NotNil(t, got.Commit)
	assert.Equal(t, "abc123def456", got.Commit.CommitID)
	assert.Equal(t, "John Doe", got.Commit.AuthorName)
	assert.Equal(t, "john@example.com", got.Commit.AuthorEmail)
	assert.Equal(t, authorTS, got.Commit.AuthorTimestamp)
	assert.Equal(t, "Jane Smith", got.Commit.CommitterName)
	assert.Equal(t, "jane@example.com", got.Commit.CommitterEmail)
	assert.Equal(t, committerTS, got.Commit.CommitterTimestamp)
	assert.Equal(t, "add config", got.Commit.Message)
}
