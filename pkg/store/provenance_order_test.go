//go:build !wasm

package store

import (
	"cmp"
	"database/sql"
	"path/filepath"
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

// locationsTruncatedColumn reads the declared NOT NULL flag and default of
// provenance.locations_truncated.
func locationsTruncatedColumn(t *testing.T, s *SQLiteStore) (notNull bool, dflt sql.NullString) {
	t.Helper()
	require.NoError(t, s.db.QueryRow(
		`SELECT "notnull", dflt_value FROM pragma_table_info('provenance') WHERE name = 'locations_truncated'`,
	).Scan(&notNull, &dflt), "locations_truncated column missing")
	return notNull, dflt
}

// SEC-16: opening a pre-ENG-9178 datastore adds locations_truncated as
// NOT NULL DEFAULT 0, so the old row reads 0 (not NULL) and false; a second
// open is a no-op.
func TestSQLite_LegacyDatastoreLocationsTruncatedColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	blob := types.ComputeBlobID([]byte("secret"))
	writeLegacyDatastore(t, path, blob)

	for open := range 2 {
		s, err := NewSQLite(path)
		require.NoError(t, err, "open %d", open)

		notNull, dflt := locationsTruncatedColumn(t, s)
		assert.True(t, notNull, "open %d: locations_truncated must be NOT NULL", open)
		assert.Equal(t, sql.NullString{String: "0", Valid: true}, dflt, "open %d: locations_truncated default", open)

		var raw sql.NullInt64
		require.NoError(t, s.db.QueryRow(`SELECT locations_truncated FROM provenance WHERE blob_id = ?`, blob.Hex()).Scan(&raw))
		assert.Equal(t, sql.NullInt64{Int64: 0, Valid: true}, raw, "open %d: legacy row value", open)

		provs, err := s.GetAllProvenance(blob)
		require.NoError(t, err)
		require.Len(t, provs, 1)
		g, ok := provs[0].(types.GitProvenance)
		require.True(t, ok)
		assert.False(t, g.LocationsTruncated)
		assert.Equal(t, "config.yml", g.BlobPath)

		require.NoError(t, s.Close())
	}
}

// SEC-16: a fresh datastore declares the same NOT NULL DEFAULT 0 column.
func TestSQLite_FreshDatastoreLocationsTruncatedColumn(t *testing.T) {
	s, err := NewSQLite(filepath.Join(t.TempDir(), "ds.db"))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	notNull, dflt := locationsTruncatedColumn(t, s)
	assert.True(t, notNull)
	assert.Equal(t, sql.NullString{String: "0", Valid: true}, dflt)
}
