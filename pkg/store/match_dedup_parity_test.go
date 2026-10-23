//go:build !wasm

package store

import (
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAddMatch_DuplicateStructuralIDParity asserts every store ignores a match
// whose StructuralID is already stored (the SQLite matches.structural_id UNIQUE
// + INSERT OR IGNORE contract): the first write wins, and GetAllMatches /
// GetMatches return it once.
func TestAddMatch_DuplicateStructuralIDParity(t *testing.T) {
	stores := []struct {
		name string
		open func(t *testing.T) Store
	}{
		{"memory", func(t *testing.T) Store { return NewMemory() }},
		{"sqlite-in-memory", func(t *testing.T) Store {
			s, err := NewSQLite(":memory:")
			require.NoError(t, err)
			return s
		}},
		{"sqlite-file", func(t *testing.T) Store {
			s, err := NewSQLite(filepath.Join(t.TempDir(), "titus.db"))
			require.NoError(t, err)
			return s
		}},
	}

	for _, tc := range stores {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.open(t)
			t.Cleanup(func() { _ = s.Close() })

			blobID := types.ComputeBlobID([]byte("same secret content"))
			require.NoError(t, s.AddBlob(blobID, 19))
			require.NoError(t, s.AddRule(&types.Rule{
				ID: "np.test.1", Name: "Test Rule", Pattern: "x", StructuralID: "rule-sid",
			}))

			first := &types.Match{
				BlobID: blobID, StructuralID: "dup-sid", RuleID: "np.test.1", RuleName: "Test Rule",
				Location: types.Location{Offset: types.OffsetSpan{Start: 1, End: 5}},
				Snippet:  types.Snippet{Matching: []byte("first")},
			}
			second := &types.Match{
				BlobID: blobID, StructuralID: "dup-sid", RuleID: "np.test.1", RuleName: "Test Rule",
				Location: types.Location{Offset: types.OffsetSpan{Start: 7, End: 9}},
				Snippet:  types.Snippet{Matching: []byte("second")},
			}
			distinct := &types.Match{
				BlobID: blobID, StructuralID: "other-sid", RuleID: "np.test.1", RuleName: "Test Rule",
				Snippet: types.Snippet{Matching: []byte("other")},
			}

			require.NoError(t, s.AddMatch(first))
			require.NoError(t, s.AddMatch(second), "duplicate StructuralID is ignored, not an error")
			require.NoError(t, s.AddMatch(distinct))

			all, err := s.GetAllMatches()
			require.NoError(t, err)
			require.Len(t, all, 2)

			byBlob, err := s.GetMatches(blobID)
			require.NoError(t, err)
			require.Len(t, byBlob, 2)

			for _, got := range [][]*types.Match{all, byBlob} {
				var dup *types.Match
				for _, m := range got {
					if m.StructuralID == "dup-sid" {
						dup = m
					}
				}
				require.NotNil(t, dup)
				assert.Equal(t, []byte("first"), dup.Snippet.Matching, "first write wins")
				assert.Equal(t, int64(1), int64(dup.Location.Offset.Start))
			}
		})
	}
}
