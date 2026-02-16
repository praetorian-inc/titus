//go:build !wasm

package store

import (
	"path/filepath"
	"testing"

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
