//go:build !wasm

package store

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Tests for Store.ListSources and its merge (LAB-7490 R16, test-plan
// fixtures 1-7).
//
// Deviation D1 (recorded in the test summary): the MemoryStore keeps a host
// pointer per provenance row and never stores nil, so a git provenance row with
// a NULL host (what Titus <= v1.2.11 wrote) is not representable there. The
// fixtures that need a NULL host (R16 fixtures 1-3) are therefore SQLite-only
// and built from raw v1.2.11-shape SQL, the one place raw SQL is allowed.
// Fixture 4 (fresh writes) runs against both stores and asserts equality.

func lsBlob(name string) types.BlobID { return types.ComputeBlobID([]byte(name)) }

// lsLegacyDatastore writes a v1.2.11-shape datastore (provenance without host
// column, no blob_locations) and returns its path.
//
//	X  matches stored; git acme/api config.yml, git /work/a a.go
//	Z  no matches;     git acme/api z.txt
//	F  no matches;     file /tmp/f.txt (host NULL)
func lsLegacyDatastore(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	for _, stmt := range legacySchema4059973 {
		_, err := db.Exec(stmt)
		require.NoError(t, err)
	}
	for _, b := range []string{"x", "z", "f"} {
		_, err := db.Exec(`INSERT INTO blobs (id, size) VALUES (?, 6)`, lsBlob(b).Hex())
		require.NoError(t, err)
	}
	_, err = db.Exec(`INSERT INTO rules (id, name, pattern, structural_id) VALUES ('np.test.1', 't', 'p', 's')`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO matches (blob_id, rule_id, structural_id, offset_start, offset_end) VALUES (?, 'np.test.1', 'm1', 0, 5)`,
		lsBlob("x").Hex())
	require.NoError(t, err)
	for _, p := range []struct{ blob, typ, path, repo, commit string }{
		{"x", "git", "config.yml", "acme/api", commitA.CommitID},
		{"x", "git", "a.go", "/work/a", commitA.CommitID},
		{"z", "git", "z.txt", "acme/api", commitB.CommitID},
	} {
		_, err := db.Exec(`INSERT INTO provenance (blob_id, type, path, repo_path, commit_hash) VALUES (?, ?, ?, ?, ?)`,
			lsBlob(p.blob).Hex(), p.typ, p.path, p.repo, p.commit)
		require.NoError(t, err)
	}
	_, err = db.Exec(`INSERT INTO provenance (blob_id, type, path) VALUES (?, 'file', '/tmp/f.txt')`, lsBlob("f").Hex())
	require.NoError(t, err)
	return path
}

func lsOpen(t *testing.T, path string) *SQLiteStore {
	t.Helper()
	s, err := NewSQLite(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func lsSources(t *testing.T, s Store) []types.SourceRecord {
	t.Helper()
	got, err := s.ListSources()
	require.NoError(t, err)
	return got
}

// R16 fixture 5: the merge deduplicates on every field and merges none.
func TestMergeSources(t *testing.T) {
	plain := types.SourceRecord{Kind: "git", Repository: "acme/api", HostRecorded: true, Path: "a.go"}
	hnr := plain
	hnr.HostRecorded = false

	tests := []struct {
		name string
		in   []types.SourceRecord
		want []types.SourceRecord
	}{
		{"nil input is an empty non-nil list", nil, []types.SourceRecord{}},
		{"equal records collapse", []types.SourceRecord{plain, plain, plain}, []types.SourceRecord{plain}},
		{"same value recorded and not recorded stays two, not-recorded first",
			[]types.SourceRecord{plain, hnr}, []types.SourceRecord{hnr, plain}},
		{"a differing AbsolutePath is a different record",
			[]types.SourceRecord{
				{Kind: "git", Repository: "r", HostRecorded: true, Path: "a", AbsolutePath: "/x/a"},
				{Kind: "git", Repository: "r", HostRecorded: true, Path: "a"},
			},
			[]types.SourceRecord{
				{Kind: "git", Repository: "r", HostRecorded: true, Path: "a"},
				{Kind: "git", Repository: "r", HostRecorded: true, Path: "a", AbsolutePath: "/x/a"},
			}},
		{"a differing Host is a different record",
			[]types.SourceRecord{
				{Kind: "git", Repository: "r", Host: "b.example", HostRecorded: true, Path: "a"},
				{Kind: "git", Repository: "r", Host: "a.example", HostRecorded: true, Path: "a"},
			},
			[]types.SourceRecord{
				{Kind: "git", Repository: "r", Host: "a.example", HostRecorded: true, Path: "a"},
				{Kind: "git", Repository: "r", Host: "b.example", HostRecorded: true, Path: "a"},
			}},
		{"ordered by kind, repository, host, path",
			[]types.SourceRecord{
				{Kind: "git", Repository: "b", Path: "1", HostRecorded: true},
				{Kind: "git", Repository: "a", Path: "2", HostRecorded: true},
				{Kind: "file", Path: "z", HostRecorded: true},
				{Kind: "git", Repository: "a", Path: "1", HostRecorded: true},
			},
			[]types.SourceRecord{
				{Kind: "file", Path: "z", HostRecorded: true},
				{Kind: "git", Repository: "a", Path: "1", HostRecorded: true},
				{Kind: "git", Repository: "a", Path: "2", HostRecorded: true},
				{Kind: "git", Repository: "b", Path: "1", HostRecorded: true},
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeSources(tt.in)
			require.NotNil(t, got)
			assert.Equal(t, tt.want, got)

			// Input order never changes the output.
			rev := slices.Clone(tt.in)
			slices.Reverse(rev)
			assert.Equal(t, tt.want, mergeSources(rev))
		})
	}
}

// R16 fixture 1 (SQLite only, D1): a v1.2.11 datastore. Every git source is
// host not recorded, a blob with no matches is still listed (sources all), and
// no findings annotation exists on the record.
func TestListSources_Gen1Legacy(t *testing.T) {
	s := lsOpen(t, lsLegacyDatastore(t))

	got := lsSources(t, s)

	assert.Equal(t, []types.SourceRecord{
		{Kind: "file", HostRecorded: true, Path: "/tmp/f.txt"},
		{Kind: "git", Repository: "/work/a", HostRecorded: false, Path: "a.go"},
		{Kind: "git", Repository: "acme/api", HostRecorded: false, Path: "config.yml"},
		// Z has no match; it is still a source.
		{Kind: "git", Repository: "acme/api", HostRecorded: false, Path: "z.txt"},
	}, got)

	// The record carries no findings annotation (R16 ruling 2).
	raw, err := json.Marshal(got)
	require.NoError(t, err)
	assert.NotContains(t, strings.ToLower(string(raw)), "located")
	assert.NotContains(t, strings.ToLower(string(raw)), "findings")
}

// R16 fixture 2 (SQLite only, D1): the new code rescans part of a v1.2.11
// datastore. Touched rows become recorded, untouched rows stay host not
// recorded, and the rescan's own rows are listed recorded.
func TestListSources_Gen1ToGen2Rescan(t *testing.T) {
	s := lsOpen(t, lsLegacyDatastore(t))
	x := lsBlob("x")

	// The scanner rescans the typed-root repository: same provenance row, host
	// resolved to "" (no origin), which fills the NULL.
	require.NoError(t, s.AddProvenance(x, types.GitProvenance{RepoPath: "/work/a", BlobPath: "a.go", Commit: commitA}))
	// And scans the same blob from a hosted clone: new provenance row plus the
	// location row the scanner writes with it.
	hosted := types.GitProvenance{RepoPath: "github.com/acme/api", Host: "github.com", RemoteIdentity: true, BlobPath: "config.yml", Commit: commitA}
	require.NoError(t, s.AddProvenance(x, hosted))
	require.NoError(t, s.AddOccurrences(x, types.OccurrencesOf(hosted)))

	got := lsSources(t, s)

	assert.Equal(t, []types.SourceRecord{
		{Kind: "file", HostRecorded: true, Path: "/tmp/f.txt"},
		// touched: NULL host filled, now recorded
		{Kind: "git", Repository: "/work/a", HostRecorded: true, Path: "a.go"},
		// untouched legacy rows stay host not recorded
		{Kind: "git", Repository: "acme/api", HostRecorded: false, Path: "config.yml"},
		{Kind: "git", Repository: "acme/api", HostRecorded: false, Path: "z.txt"},
		// the rescan's provenance row and its location row are one record
		{Kind: "git", Repository: "github.com/acme/api", Host: "github.com", HostRecorded: true, Path: "config.yml"},
	}, got)
}

// R16 fixture 3 (SQLite only, D1): the cross-blob collision. v1.2.11 recorded
// blob X for a no-origin repo with a NULL host; the new code scans the edited
// file as blob Y with an empty host. The displayed value is equal, the recorded
// state differs, so they must stay two records.
func TestListSources_CrossBlobCollision(t *testing.T) {
	provX := func(t *testing.T) *SQLiteStore {
		path := filepath.Join(t.TempDir(), "legacy.db")
		db, err := sql.Open("sqlite", path)
		require.NoError(t, err)
		for _, stmt := range legacySchema4059973 {
			_, err := db.Exec(stmt)
			require.NoError(t, err)
		}
		_, err = db.Exec(`INSERT INTO blobs (id, size) VALUES (?, 6)`, lsBlob("x").Hex())
		require.NoError(t, err)
		_, err = db.Exec(`INSERT INTO provenance (blob_id, type, path, repo_path, commit_hash) VALUES (?, 'git', 'a.go', '.', ?)`,
			lsBlob("x").Hex(), commitA.CommitID)
		require.NoError(t, err)
		require.NoError(t, db.Close())
		return lsOpen(t, path)
	}
	y := lsBlob("y")
	newProv := types.GitProvenance{RepoPath: ".", BlobPath: "a.go", Commit: commitB, RepoRoot: "/work/a"}

	t.Run("provenance only: X not recorded, Y recorded", func(t *testing.T) {
		s := provX(t)
		require.NoError(t, s.AddBlob(y, 7))
		require.NoError(t, s.AddProvenance(y, newProv))

		got := lsSources(t, s)

		assert.Equal(t, []types.SourceRecord{
			{Kind: "git", Repository: ".", HostRecorded: false, Path: "a.go"},
			{Kind: "git", Repository: ".", HostRecorded: true, Path: "a.go"},
		}, got)
	})

	t.Run("with the scanner's location row for Y", func(t *testing.T) {
		s := provX(t)
		require.NoError(t, s.AddBlob(y, 7))
		require.NoError(t, s.AddProvenance(y, newProv))
		require.NoError(t, s.AddOccurrences(y, types.OccurrencesOf(newProv)))

		got := lsSources(t, s)

		// X stays labelled; Y is plain, as provenance and as a location carrying
		// its absolute path.
		assert.Equal(t, []types.SourceRecord{
			{Kind: "git", Repository: ".", HostRecorded: false, Path: "a.go"},
			{Kind: "git", Repository: ".", HostRecorded: true, Path: "a.go"},
			{Kind: "git", Repository: ".", HostRecorded: true, Path: "a.go", AbsolutePath: filepath.Join("/work/a", "a.go")},
		}, got)
	})
}

// R16 fixture 4 and 7: fresh writes by the current code. Both stores list the
// same records and all of them are recorded.
func TestListSources_Gen2Fresh_Parity(t *testing.T) {
	hosted := types.GitProvenance{RepoPath: "github.com/acme/api", Host: "github.com", RemoteIdentity: true, BlobPath: "a.txt", Commit: commitA}
	local := types.GitProvenance{RepoPath: "/work/b", BlobPath: "b.txt", Commit: commitA, RepoRoot: "/work/b"}
	want := []types.SourceRecord{
		{Kind: "file", HostRecorded: true, Path: "/tmp/f.txt"},
		{Kind: "git", Repository: "/work/b", HostRecorded: true, Path: "b.txt"},
		{Kind: "git", Repository: "/work/b", HostRecorded: true, Path: "b.txt", AbsolutePath: filepath.Join("/work/b", "b.txt")},
		{Kind: "git", Repository: "github.com/acme/api", Host: "github.com", HostRecorded: true, Path: "a.txt"},
	}

	var results [][]types.SourceRecord
	for _, f := range storeFactories {
		t.Run(f.name, func(t *testing.T) {
			s := f.open(t)
			for name, p := range map[string]types.Provenance{
				"a": hosted, "b": local, "f": types.FileProvenance{FilePath: "/tmp/f.txt"},
			} {
				require.NoError(t, s.AddBlob(lsBlob(name), 6))
				require.NoError(t, s.AddProvenance(lsBlob(name), p))
				if g, ok := p.(types.GitProvenance); ok {
					require.NoError(t, s.AddOccurrences(lsBlob(name), types.OccurrencesOf(g)))
				}
			}

			got := lsSources(t, s)

			assert.Equal(t, want, got)
			results = append(results, got)
		})
	}
	require.Len(t, results, 2)
	assert.Equal(t, results[0], results[1], "sqlite and memory list the same sources")
}

// S-T003 and R16 fixture 7: a row never loses a recorded host, and fills only
// a NULL one. Both stores agree on what a rescan does to a recorded row.
func TestAddProvenance_FillsNullHostKeepsRecorded(t *testing.T) {
	prov := func(host string) types.GitProvenance {
		return types.GitProvenance{RepoPath: "acme/api", Host: host, BlobPath: "a.go", Commit: commitA}
	}
	t.Run("sqlite fills a NULL host once", func(t *testing.T) {
		s := lsOpen(t, lsLegacyDatastore(t))
		x := lsBlob("x")
		row := func() types.SourceRecord {
			for _, r := range lsSources(t, s) {
				if r.Repository == "/work/a" {
					return r
				}
			}
			t.Fatal("row missing")
			return types.SourceRecord{}
		}
		require.False(t, row().HostRecorded, "precondition: the legacy row is not recorded")

		require.NoError(t, s.AddProvenance(x, types.GitProvenance{RepoPath: "/work/a", Host: "gitlab.example.com", BlobPath: "a.go", Commit: commitA}))
		assert.Equal(t, types.SourceRecord{Kind: "git", Repository: "/work/a", Host: "gitlab.example.com", HostRecorded: true, Path: "a.go"}, row())

		// A later scan reporting another host does not overwrite it.
		require.NoError(t, s.AddProvenance(x, types.GitProvenance{RepoPath: "/work/a", Host: "evil.example.com", BlobPath: "a.go", Commit: commitA}))
		assert.Equal(t, "gitlab.example.com", row().Host)
	})

	for _, f := range storeFactories {
		t.Run(f.name+"/recorded host is kept", func(t *testing.T) {
			s := f.open(t)
			b := lsBlob("k")
			require.NoError(t, s.AddBlob(b, 6))
			require.NoError(t, s.AddProvenance(b, prov("gitlab.example.com")))
			require.NoError(t, s.AddProvenance(b, prov("evil.example.com")))
			require.NoError(t, s.AddProvenance(b, prov("")))

			assert.Equal(t, []types.SourceRecord{
				{Kind: "git", Repository: "acme/api", Host: "gitlab.example.com", HostRecorded: true, Path: "a.go"},
			}, lsSources(t, s))
		})
		t.Run(f.name+"/a recorded empty host is a recorded value and is kept", func(t *testing.T) {
			s := f.open(t)
			b := lsBlob("k")
			require.NoError(t, s.AddBlob(b, 6))
			require.NoError(t, s.AddProvenance(b, prov("")))
			require.NoError(t, s.AddProvenance(b, prov("github.com")))

			assert.Equal(t, []types.SourceRecord{
				{Kind: "git", Repository: "acme/api", HostRecorded: true, Path: "a.go"},
			}, lsSources(t, s))
		})
	}
}

// S-T003: a location row stored without a host is filled by a later write and
// a recorded host is never overwritten, in both stores.
func TestAddOccurrences_FillsEmptyHostKeepsRecorded(t *testing.T) {
	occ := func(host string) []types.Occurrence {
		return []types.Occurrence{{Kind: "git", Repository: "github.com/acme/api", Host: host, Path: "a.txt",
			Commit: commitA.CommitID, CommitDate: commitA.CommitterTimestamp, HostRecorded: true}}
	}
	hostOf := func(t *testing.T, s Store, b types.BlobID) string {
		got, err := s.GetOccurrences(b)
		require.NoError(t, err)
		require.Len(t, got, 1, "one location, however often it is written")
		return got[0].Host
	}
	for _, f := range storeFactories {
		t.Run(f.name+"/empty is filled", func(t *testing.T) {
			s := f.open(t)
			b := lsBlob("o")
			require.NoError(t, s.AddBlob(b, 6))
			require.NoError(t, s.AddOccurrences(b, occ("")))
			require.Equal(t, "", hostOf(t, s, b))

			require.NoError(t, s.AddOccurrences(b, occ("github.com")))

			assert.Equal(t, "github.com", hostOf(t, s, b))
		})
		t.Run(f.name+"/recorded is kept", func(t *testing.T) {
			s := f.open(t)
			b := lsBlob("o")
			require.NoError(t, s.AddBlob(b, 6))
			require.NoError(t, s.AddOccurrences(b, occ("github.com")))

			require.NoError(t, s.AddOccurrences(b, occ("evil.example.com")))
			require.NoError(t, s.AddOccurrences(b, occ("")))

			assert.Equal(t, "github.com", hostOf(t, s, b))
		})
	}
}

// R16 fixture 6: ListSources reads only.
func TestListSources_ReadOnly(t *testing.T) {
	s := lsOpen(t, lsLegacyDatastore(t))
	require.NoError(t, s.AddOccurrences(lsBlob("x"), []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Host: "github.com", Path: "config.yml", HostRecorded: true},
	}))
	counts := func() map[string]int {
		out := map[string]int{}
		for _, q := range []string{
			`SELECT COUNT(*) FROM provenance`,
			`SELECT COUNT(*) FROM provenance WHERE host IS NULL`,
			`SELECT COUNT(*) FROM blob_locations`,
			`SELECT COUNT(*) FROM blobs`,
			`SELECT COUNT(*) FROM matches`,
			`SELECT COUNT(*) FROM rules`,
			`SELECT total_changes()`,
		} {
			var n int
			require.NoError(t, s.db.QueryRow(q).Scan(&n))
			out[q] = n
		}
		return out
	}
	before := counts()
	require.Positive(t, before[`SELECT COUNT(*) FROM provenance WHERE host IS NULL`], "precondition: legacy NULL rows exist")

	first := lsSources(t, s)
	second := lsSources(t, s)

	assert.Equal(t, before, counts(), "no row was inserted, updated or deleted (including host NULL -> value)")
	assert.Equal(t, first, second)
}

// Non-git kinds are always recorded: only a git row can be a repository whose
// host was never captured.
func TestListSources_NonGitKindsAlwaysRecorded(t *testing.T) {
	t.Run("sqlite legacy NULL host on a file row", func(t *testing.T) {
		s := lsOpen(t, lsLegacyDatastore(t))
		for _, r := range lsSources(t, s) {
			if r.Kind == "file" {
				assert.True(t, r.HostRecorded, "%+v", r)
			}
		}
	})
	for _, f := range storeFactories {
		t.Run(f.name+"/fresh non-git rows", func(t *testing.T) {
			s := f.open(t)
			require.NoError(t, s.AddBlob(lsBlob("n"), 6))
			require.NoError(t, s.AddProvenance(lsBlob("n"), types.FileProvenance{FilePath: "/tmp/n.txt"}))
			require.NoError(t, s.AddProvenance(lsBlob("n"), types.ExtendedProvenance{Payload: map[string]interface{}{"source": "slack", "id": "C1"}}))

			got := lsSources(t, s)

			require.Len(t, got, 2)
			for _, r := range got {
				assert.NotEqual(t, "git", r.Kind)
				assert.True(t, r.HostRecorded, "%+v", r)
			}
		})
	}
}

// S-T009: the host columns migrate idempotently on every shape a user can
// hold, and have the documented nullability.
func TestOpen_HostColumnsMigrationIsIdempotent(t *testing.T) {
	// A datastore written by a build between ENG-9178 and this change (a
	// blob_locations table without host) is not a supported generation for
	// labelling (R16), but it must still open.
	preHostLocations := func(t *testing.T) string {
		path := lsLegacyDatastore(t)
		db, err := sql.Open("sqlite", path)
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		_, err = db.Exec(`CREATE TABLE blob_locations (
			id INTEGER PRIMARY KEY, blob_id TEXT NOT NULL REFERENCES blobs(id), kind TEXT NOT NULL,
			repository TEXT NOT NULL DEFAULT '', path TEXT NOT NULL, absolute_path TEXT NOT NULL DEFAULT '',
			commit_hash TEXT NOT NULL DEFAULT '', commit_ts INTEGER NOT NULL DEFAULT 0, working_tree INTEGER NOT NULL DEFAULT 0,
			UNIQUE(blob_id, kind, repository, path, absolute_path, commit_hash, working_tree))`)
		require.NoError(t, err)
		_, err = db.Exec(`INSERT INTO blob_locations (blob_id, kind, repository, path) VALUES (?, 'git', 'github.com/acme/api', 'config.yml')`,
			lsBlob("x").Hex())
		require.NoError(t, err)
		return path
	}
	shapes := map[string]func(t *testing.T) string{
		"v1.2.11":                     lsLegacyDatastore,
		"blob_locations without host": preHostLocations,
		"fresh":                       func(t *testing.T) string { return filepath.Join(t.TempDir(), "fresh.db") },
	}
	for name, mk := range shapes {
		t.Run(name, func(t *testing.T) {
			path := mk(t)
			var firstView []types.SourceRecord
			for i := range 3 {
				s, err := NewSQLite(path)
				require.NoError(t, err, "open #%d", i+1)
				view, err := s.ListSources()
				require.NoError(t, err)
				if i == 0 {
					firstView = view
				} else {
					assert.Equal(t, firstView, view, "reopening changes nothing")
				}
				require.NoError(t, s.Close())
			}

			s := lsOpen(t, path)
			column := func(table string) (notNull int, dflt sql.NullString) {
				require.NoError(t, s.db.QueryRow(`SELECT "notnull", dflt_value FROM pragma_table_info(?) WHERE name = 'host'`, table).Scan(&notNull, &dflt))
				return notNull, dflt
			}
			nn, _ := column("provenance")
			assert.Zero(t, nn, "provenance.host is nullable: NULL means not recorded")
			nn, dflt := column("blob_locations")
			assert.Equal(t, 1, nn, "blob_locations.host is NOT NULL")
			assert.Equal(t, "''", dflt.String)
		})
	}
}
