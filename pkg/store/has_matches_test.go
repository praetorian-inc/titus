//go:build !wasm

package store

import (
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ENG-9178: HasMatches tells a stored blob with matches (whose new
// locations an --incremental rescan must still record) from a stored blob
// without any and from a blob never stored, on every store.
func TestStore_HasMatches(t *testing.T) {
	for name, open := range map[string]func(t *testing.T) Store{
		"memory": func(*testing.T) Store { return NewMemory() },
		"sqlite": func(t *testing.T) Store {
			s, err := NewSQLite(filepath.Join(t.TempDir(), "test.db"))
			require.NoError(t, err)
			return s
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			t.Cleanup(func() { _ = s.Close() })

			matched := types.ComputeBlobID([]byte("matched"))
			clean := types.ComputeBlobID([]byte("clean"))
			unknown := types.ComputeBlobID([]byte("unknown"))
			require.NoError(t, s.AddBlob(matched, 7))
			require.NoError(t, s.AddBlob(clean, 5))
			require.NoError(t, s.AddRule(&types.Rule{ID: "np.test.1", Name: "Test Rule", Pattern: "x", StructuralID: "r1"}))
			require.NoError(t, s.AddMatch(&types.Match{
				BlobID:       matched,
				StructuralID: "m1",
				RuleID:       "np.test.1",
				RuleName:     "Test Rule",
				Location:     types.Location{Offset: types.OffsetSpan{Start: 0, End: 3}},
				Snippet:      types.Snippet{Matching: []byte("mat")},
			}))

			for _, tc := range []struct {
				name string
				id   types.BlobID
				want bool
			}{
				{"stored blob with a match", matched, true},
				{"stored blob without matches", clean, false},
				{"blob never stored", unknown, false},
			} {
				got, err := s.HasMatches(tc.id)
				require.NoError(t, err, tc.name)
				assert.Equal(t, tc.want, got, tc.name)
			}
		})
	}
}
