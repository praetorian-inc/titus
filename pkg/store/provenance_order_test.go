//go:build !wasm

package store

import (
	"cmp"
	"slices"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// provRow is the (repository, path, commit) identity of a git provenance row.
type provRow struct{ repo, path, commit string }

func gitProvRows(t *testing.T, provs []types.Provenance) []provRow {
	t.Helper()
	rows := make([]provRow, 0, len(provs))
	for _, p := range provs {
		g, ok := p.(types.GitProvenance)
		require.True(t, ok, "want GitProvenance, got %T", p)
		r := provRow{repo: g.RepoPath, path: g.BlobPath}
		if g.Commit != nil {
			r.commit = g.Commit.CommitID
		}
		rows = append(rows, r)
	}
	return rows
}

// SEC-15: GetAllProvenance returns rows in a deterministic order sorted by
// repository, path, then commit, whatever the insertion order, and hostile
// path bytes round-trip unchanged.
func TestStore_GetAllProvenanceOrderedAndExact(t *testing.T) {
	const (
		hostileSQL = "x'); DROP TABLE findings;--"
		newline    = "a\nb"
	)
	// Deliberately not sorted on any of the three keys.
	inserted := []provRow{
		{"github.com/zeta/svc", "config.yml", commitA.CommitID},
		{"github.com/acme/api", newline, commitB.CommitID},
		{"github.com/acme/api", "config.yml", commitB.CommitID},
		{"github.com/acme/api", hostileSQL, commitA.CommitID},
		{"github.com/acme/api", "config.yml", commitA.CommitID},
		{"github.com/beta/web", "a.yml", commitA.CommitID},
	}
	want := slices.Clone(inserted)
	slices.SortFunc(want, func(a, b provRow) int {
		return cmp.Or(cmp.Compare(a.repo, b.repo), cmp.Compare(a.path, b.path), cmp.Compare(a.commit, b.commit))
	})
	require.NotEqual(t, inserted, want, "fixture must be inserted out of order")

	for _, f := range storeFactories {
		t.Run(f.name, func(t *testing.T) {
			s := f.open(t)
			blob := types.ComputeBlobID([]byte("ordered"))
			require.NoError(t, s.AddBlob(blob, 7))
			for _, r := range inserted {
				require.NoError(t, s.AddProvenance(blob, types.GitProvenance{
					RepoPath: r.repo,
					BlobPath: r.path,
					Commit:   &types.CommitMetadata{CommitID: r.commit},
				}))
			}

			for i := range 5 {
				provs, err := s.GetAllProvenance(blob)
				require.NoError(t, err)
				assert.Equal(t, want, gitProvRows(t, provs), "read %d", i)
			}

			if sq, ok := s.(*SQLiteStore); ok {
				var n int
				require.NoError(t, sq.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'findings'`).Scan(&n))
				assert.Equal(t, 1, n, "findings table must survive the hostile path")
			}
		})
	}
}
