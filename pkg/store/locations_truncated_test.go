//go:build !wasm

package store

import (
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func truncProv(path string, truncated bool) types.GitProvenance {
	return types.GitProvenance{
		RepoPath:           "github.com/acme/api",
		BlobPath:           path,
		Commit:             &types.CommitMetadata{CommitID: commitA.CommitID, AuthorName: "Ann"},
		LocationsTruncated: truncated,
	}
}

// truncByPath returns each git provenance row's LocationsTruncated flag by
// blob path.
func truncByPath(t *testing.T, s Store, id types.BlobID) map[string]bool {
	t.Helper()
	provs, err := s.GetAllProvenance(id)
	require.NoError(t, err)
	got := map[string]bool{}
	for _, p := range provs {
		g, ok := p.(types.GitProvenance)
		require.True(t, ok)
		got[g.BlobPath] = g.LocationsTruncated
	}
	return got
}

// ENG-9178: the flag round-trips through both stores without disturbing the
// commit metadata read alongside it.
func TestStore_LocationsTruncatedRoundTrip(t *testing.T) {
	for _, f := range storeFactories {
		t.Run(f.name, func(t *testing.T) {
			s := f.open(t)
			id := types.ComputeBlobID([]byte("roundtrip"))
			require.NoError(t, s.AddBlob(id, 9))
			require.NoError(t, s.AddProvenance(id, truncProv("on.yml", true)))
			require.NoError(t, s.AddProvenance(id, truncProv("off.yml", false)))

			assert.Equal(t, map[string]bool{"on.yml": true, "off.yml": false}, truncByPath(t, s, id))
			provs, err := s.GetAllProvenance(id)
			require.NoError(t, err)
			for _, p := range provs {
				g := p.(types.GitProvenance)
				require.NotNil(t, g.Commit)
				assert.Equal(t, "Ann", g.Commit.AuthorName)
			}
		})
	}
}

// The flag is sticky per row: a later truncated write of an existing row
// marks it, a later untruncated write never clears it, and a truncated write
// of one row leaves the blob's other rows unmarked.
func TestStore_LocationsTruncatedSticky(t *testing.T) {
	for _, f := range storeFactories {
		t.Run(f.name, func(t *testing.T) {
			s := f.open(t)
			id := types.ComputeBlobID([]byte("sticky"))
			require.NoError(t, s.AddBlob(id, 6))
			require.NoError(t, s.AddProvenance(id, truncProv("a.yml", false)))
			require.NoError(t, s.AddProvenance(id, truncProv("b.yml", false)))

			require.NoError(t, s.AddProvenance(id, truncProv("a.yml", true)))
			assert.Equal(t, map[string]bool{"a.yml": true, "b.yml": false}, truncByPath(t, s, id))

			require.NoError(t, s.AddProvenance(id, truncProv("a.yml", false)))
			assert.Equal(t, map[string]bool{"a.yml": true, "b.yml": false}, truncByPath(t, s, id))
		})
	}
}

// A datastore written before the column existed (writeLegacyDatastore) opens,
// reads the flag as false with its commit metadata intact, and can then be
// marked truncated by a rescan.
func TestSQLite_LegacyDatastoreLocationsTruncated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	blob := types.ComputeBlobID([]byte("secret"))
	writeLegacyDatastore(t, path, blob)

	s, err := NewSQLite(path)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	provs, err := s.GetAllProvenance(blob)
	require.NoError(t, err)
	require.Len(t, provs, 1)
	g := provs[0].(types.GitProvenance)
	assert.False(t, g.LocationsTruncated)
	require.NotNil(t, g.Commit)
	assert.Equal(t, commitA.CommitterTimestamp, g.Commit.CommitterTimestamp, "full query, not the legacy fallback")

	g.LocationsTruncated = true
	require.NoError(t, s.AddProvenance(blob, g))
	assert.Equal(t, map[string]bool{"config.yml": true}, truncByPath(t, s, blob))
}
