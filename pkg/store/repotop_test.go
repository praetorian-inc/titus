//go:build !wasm

package store

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ENG-9178: the provenance table persists no scan-local fields, so both
// stores return a git provenance without RepoRoot, RepoTop, RemoteIdentity
// or Locations, whatever was written.
func TestStore_ProvenanceDropsScanLocalFields(t *testing.T) {
	for _, f := range storeFactories {
		t.Run(f.name, func(t *testing.T) {
			s := f.open(t)
			id := types.ComputeBlobID([]byte("repotop"))
			require.NoError(t, s.AddBlob(id, 7))
			require.NoError(t, s.AddProvenance(id, types.GitProvenance{
				RepoPath: ".", BlobPath: "sub/c.yml", Commit: commitA,
				RepoRoot: "/r/repo/sub", RepoTop: "/r/repo", RemoteIdentity: true,
				Locations: []types.GitLocation{{Path: "sub/c.yml", Commit: commitA}},
			}))
			provs, err := s.GetAllProvenance(id)
			require.NoError(t, err)
			require.Len(t, provs, 1)
			g, ok := provs[0].(types.GitProvenance)
			require.True(t, ok, "got %T", provs[0])
			assert.Empty(t, g.RepoTop)
			assert.Empty(t, g.RepoRoot)
			assert.False(t, g.RemoteIdentity)
			assert.Nil(t, g.Locations)
			assert.Equal(t, "sub/c.yml", g.BlobPath)
		})
	}
}
