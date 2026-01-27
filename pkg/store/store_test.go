package store

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_MemoryStore(t *testing.T) {
	// Act
	store, err := New(Config{Path: ":memory:"})

	// Assert
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()
}

func TestStore_Interface(t *testing.T) {
	// This test verifies that SQLiteStore implements the Store interface
	var _ Store = (*SQLiteStore)(nil)
}

func TestStore_E2E(t *testing.T) {
	// Arrange
	store, err := New(Config{Path: ":memory:"})
	require.NoError(t, err)
	defer store.Close()

	// Add a blob
	blobID := types.ComputeBlobID([]byte("secret content"))
	err = store.AddBlob(blobID, 14)
	require.NoError(t, err)

	// Add a match
	match := &types.Match{
		BlobID:       blobID,
		StructuralID: "match123",
		RuleID:       "np.test.1",
		RuleName:     "Test Rule",
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 0, End: 14},
		},
		Groups:  [][]byte{[]byte("secret")},
		Snippet: types.Snippet{Matching: []byte("secret content")},
	}
	err = store.AddMatch(match)
	require.NoError(t, err)

	// Add a finding
	finding := &types.Finding{
		ID:      "finding123",
		RuleID:  "np.test.1",
		Groups:  [][]byte{[]byte("secret")},
		Matches: []*types.Match{match},
	}
	err = store.AddFinding(finding)
	require.NoError(t, err)

	// Add provenance
	prov := types.FileProvenance{FilePath: "/tmp/secret.txt"}
	err = store.AddProvenance(blobID, prov)
	require.NoError(t, err)

	// Act - retrieve matches
	matches, err := store.GetMatches(blobID)
	require.NoError(t, err)
	assert.Len(t, matches, 1)
	assert.Equal(t, "match123", matches[0].StructuralID)

	// Act - retrieve findings
	findings, err := store.GetFindings()
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "finding123", findings[0].ID)

	// Act - check finding exists
	exists, err := store.FindingExists("finding123")
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = store.FindingExists("nonexistent")
	require.NoError(t, err)
	assert.False(t, exists)
}
