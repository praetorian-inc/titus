//go:build !wasm

package store

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/types"
)

// branchRow is one committed location of the test blob with the given branch.
func branchRow(branch string) types.Occurrence {
	o := gitOcc("github.com/acme/api", "config.yml", commitA)
	o.Branch = branch
	return o
}

func branchBlob(t *testing.T, s Store) types.BlobID {
	t.Helper()
	blob := types.ComputeBlobID([]byte("secret"))
	require.NoError(t, s.AddBlob(blob, 6))
	return blob
}

// Branch upsert semantics on every Store: a resolved branch replaces (the
// latest scan's checkout wins), an empty one never erases, and the UNIQUE key
// does not include the branch, so the location stays one row.
func TestStore_Branch_UpsertSemantics(t *testing.T) {
	tests := []struct {
		name   string
		writes []string // Branch of each AddOccurrences call, in order
		want   string
	}{
		{"single write is stored", []string{"main"}, "main"},
		{"a later resolved branch replaces the earlier", []string{"main", "feature/login"}, "feature/login"},
		{"an empty branch never erases a resolved one", []string{"main", ""}, "main"},
		{"a resolved branch fills an empty one", []string{"", "main"}, "main"},
		{"empty stays empty", []string{"", ""}, ""},
		{"replace then empty then replace", []string{"a", "", "b", ""}, "b"},
	}
	for _, f := range storeFactories {
		for _, tc := range tests {
			t.Run(f.name+"/"+tc.name, func(t *testing.T) {
				s := f.open(t)
				blob := branchBlob(t, s)
				for _, b := range tc.writes {
					require.NoError(t, s.AddOccurrences(blob, []types.Occurrence{branchRow(b)}))
				}
				got, err := s.GetOccurrences(blob)
				require.NoError(t, err)
				require.Len(t, got, 1, "the UNIQUE key does not include the branch: one location, one row")
				assert.Equal(t, branchRow(tc.want), got[0])
			})
		}
	}
}

// Different locations keep their own branch.
func TestStore_Branch_PerLocation(t *testing.T) {
	for _, f := range storeFactories {
		t.Run(f.name, func(t *testing.T) {
			s := f.open(t)
			blob := branchBlob(t, s)
			a := gitOcc("github.com/acme/api", "config.yml", commitA)
			a.Branch = "main"
			b := gitOcc("github.com/acme/api", "deploy/config.yml", commitB)
			b.Branch = "feature/login"
			wt := types.Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", AbsolutePath: "/src/api/config.yml", WorkingTree: true, HostRecorded: true}
			require.NoError(t, s.AddOccurrences(blob, []types.Occurrence{a, b, wt}))

			got, err := s.GetOccurrences(blob)
			require.NoError(t, err)
			assert.ElementsMatch(t, []types.Occurrence{a, b, wt}, got)
		})
	}
}

// Branch is stored on the location row only: a provenance record carrying one
// does not surface it, in SQLite (no provenance column) and in memory alike.
func TestStore_Branch_ProvenanceAloneDoesNotCarryBranch(t *testing.T) {
	for _, f := range storeFactories {
		t.Run(f.name, func(t *testing.T) {
			s := f.open(t)
			blob := branchBlob(t, s)
			withBranch := &types.CommitMetadata{CommitID: commitA.CommitID, CommitterTimestamp: commitA.CommitterTimestamp, Branch: "main"}
			require.NoError(t, s.AddProvenance(blob, types.GitProvenance{
				RepoPath: "github.com/acme/api", BlobPath: "config.yml", Commit: withBranch, Host: "github.com",
			}))
			got, err := s.GetOccurrences(blob)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, "", got[0].Branch)

			// With the location row written too, the row's branch shows.
			require.NoError(t, s.AddOccurrences(blob, []types.Occurrence{branchRow("main")}))
			got, err = s.GetOccurrences(blob)
			require.NoError(t, err)
			require.Len(t, got, 1, "provenance and row are one location")
			assert.Equal(t, "main", got[0].Branch)

			// The stored provenance is unchanged by the branch.
			provs, err := s.GetAllProvenance(blob)
			require.NoError(t, err)
			require.Len(t, provs, 1)
			assert.Equal(t, "", provs[0].(types.GitProvenance).Commit.Branch)
		})
	}
}

// Host semantics are unchanged by the branch column: a recorded host is never
// overwritten, an empty one is filled, whatever the branch does.
func TestStore_Branch_HostSemanticsUnchanged(t *testing.T) {
	for _, f := range storeFactories {
		t.Run(f.name, func(t *testing.T) {
			s := f.open(t)
			blob := branchBlob(t, s)
			first := branchRow("main")
			first.Host = "github.com"
			second := branchRow("feature/login")
			second.Host = "gitlab.com"
			require.NoError(t, s.AddOccurrences(blob, []types.Occurrence{first}))
			require.NoError(t, s.AddOccurrences(blob, []types.Occurrence{second}))

			got, err := s.GetOccurrences(blob)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, "feature/login", got[0].Branch, "the branch is replaced")
			assert.Equal(t, "github.com", got[0].Host, "a recorded host is never overwritten")

			// An empty host is filled by a later row, together with the branch.
			s2 := f.open(t)
			blob2 := branchBlob(t, s2)
			require.NoError(t, s2.AddOccurrences(blob2, []types.Occurrence{branchRow("")}))
			filled := branchRow("main")
			filled.Host = "github.com"
			require.NoError(t, s2.AddOccurrences(blob2, []types.Occurrence{filled}))
			got, err = s2.GetOccurrences(blob2)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, "main", got[0].Branch)
			assert.Equal(t, "github.com", got[0].Host)
		})
	}
}

// Both stores answer identically for one mixed write sequence.
func TestStore_Branch_SQLiteMemoryParity(t *testing.T) {
	seq := [][]types.Occurrence{
		{branchRow("main"), gitOcc("github.com/acme/api", "other.yml", commitB)},
		{branchRow(""), func() types.Occurrence {
			o := gitOcc("github.com/acme/api", "other.yml", commitB)
			o.Branch = "x"
			return o
		}()},
		{branchRow("release/1.0")},
	}
	results := map[string][]types.Occurrence{}
	for _, f := range storeFactories {
		s := f.open(t)
		blob := branchBlob(t, s)
		for _, w := range seq {
			require.NoError(t, s.AddOccurrences(blob, w))
		}
		got, err := s.GetOccurrences(blob)
		require.NoError(t, err)
		results[f.name] = got
	}
	require.Len(t, results["sqlite"], 2)
	assert.Equal(t, results["sqlite"], results["memory"])
	byPath := map[string]string{}
	for _, o := range results["sqlite"] {
		byPath[o.Path] = o.Branch
	}
	assert.Equal(t, map[string]string{"config.yml": "release/1.0", "other.yml": "x"}, byPath)
}

// --- migration (SQLite only: the column exists only there) -------------------

// legacyBranchlessDatastore is a datastore whose blob_locations table has the
// host column and no branch column, with one location row holding a host.
func legacyBranchlessDatastore(t *testing.T) string {
	t.Helper()
	path := lsLegacyDatastore(t)
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	_, err = db.Exec(`CREATE TABLE blob_locations (
		id INTEGER PRIMARY KEY, blob_id TEXT NOT NULL REFERENCES blobs(id), kind TEXT NOT NULL,
		repository TEXT NOT NULL DEFAULT '', path TEXT NOT NULL, absolute_path TEXT NOT NULL DEFAULT '',
		commit_hash TEXT NOT NULL DEFAULT '', commit_ts INTEGER NOT NULL DEFAULT 0, working_tree INTEGER NOT NULL DEFAULT 0,
		host TEXT NOT NULL DEFAULT '',
		UNIQUE(blob_id, kind, repository, path, absolute_path, commit_hash, working_tree))`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO blob_locations (blob_id, kind, repository, path, commit_hash, commit_ts, host) VALUES (?, 'git', 'github.com/acme/api', 'config.yml', ?, ?, 'github.com')`,
		lsBlob("x").Hex(), commitA.CommitID, commitA.CommitterTimestamp.Unix())
	require.NoError(t, err)
	return path
}

func acmeRows(t *testing.T, s *SQLiteStore) []types.Occurrence {
	t.Helper()
	got, err := s.GetOccurrences(lsBlob("x"))
	require.NoError(t, err)
	var out []types.Occurrence
	for _, o := range got {
		if o.Repository == "github.com/acme/api" {
			out = append(out, o)
		}
	}
	return out
}

func TestSQLite_Branch_MigrationFromColumnlessTable(t *testing.T) {
	path := legacyBranchlessDatastore(t)

	// Open: the column is added, existing rows read as no branch, host intact.
	s, err := NewSQLite(path)
	require.NoError(t, err)
	var notNull int
	var dflt sql.NullString
	require.NoError(t, s.db.QueryRow(`SELECT "notnull", dflt_value FROM pragma_table_info('blob_locations') WHERE name = 'branch'`).Scan(&notNull, &dflt))
	assert.Equal(t, 1, notNull, "blob_locations.branch is NOT NULL")
	assert.Equal(t, "''", dflt.String)

	rows := acmeRows(t, s)
	require.Len(t, rows, 1)
	assert.Equal(t, "", rows[0].Branch)
	assert.Equal(t, "github.com", rows[0].Host)
	assert.True(t, rows[0].HostRecorded)
	assert.Equal(t, commitA.CommitID, rows[0].Commit)

	// The UNIQUE key is unchanged: the branch is not part of it.
	var uniqueCols string
	require.NoError(t, s.db.QueryRow(`SELECT group_concat(name, ',') FROM (SELECT name FROM pragma_index_info((SELECT name FROM pragma_index_list('blob_locations') WHERE origin = 'u')) ORDER BY seqno)`).Scan(&uniqueCols))
	assert.Equal(t, "blob_id,kind,repository,path,absolute_path,commit_hash,working_tree", uniqueCols)

	// A rescan fills the branch in place, without a second row, host intact.
	up := branchRow("main")
	up.Host = "other-host"
	require.NoError(t, s.AddOccurrences(lsBlob("x"), []types.Occurrence{up}))
	rows = acmeRows(t, s)
	require.Len(t, rows, 1)
	assert.Equal(t, "main", rows[0].Branch)
	assert.Equal(t, "github.com", rows[0].Host)
	require.NoError(t, s.Close())

	// Opening again twice more is idempotent: the ALTER does not run twice
	// into an error and nothing already stored is lost.
	for i := range 2 {
		s, err = NewSQLite(path)
		require.NoError(t, err, "reopen #%d", i+1)
		rows = acmeRows(t, s)
		require.Len(t, rows, 1)
		assert.Equal(t, "main", rows[0].Branch, "the stored branch survives a reopen")
		require.NoError(t, s.Close())
	}
}

// A datastore with the branch column already present opens twice cleanly.
func TestSQLite_Branch_FreshDatastoreOpensTwice(t *testing.T) {
	path := t.TempDir() + "/fresh.db"
	for i := range 3 {
		s, err := NewSQLite(path)
		require.NoError(t, err, "open #%d", i+1)
		if i == 0 {
			blob := branchBlob(t, s)
			require.NoError(t, s.AddOccurrences(blob, []types.Occurrence{branchRow("main")}))
		}
		got, err := s.GetOccurrences(types.ComputeBlobID([]byte("secret")))
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "main", got[0].Branch)
		require.NoError(t, s.Close())
	}
}

// --- no rewrite of an unchanged location -------------------------------------

// countingSQLite opens a datastore whose blob_locations updates are counted by
// a trigger: the conditional upsert must not touch a row it has nothing to
// change on.
func countingSQLite(t *testing.T) (*SQLiteStore, func() int) {
	t.Helper()
	s, err := NewSQLite(t.TempDir() + "/count.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	_, err = s.db.Exec(`CREATE TABLE loc_updates (n INTEGER);
		CREATE TRIGGER loc_upd AFTER UPDATE ON blob_locations BEGIN INSERT INTO loc_updates VALUES (1); END`)
	require.NoError(t, err)
	return s, func() int {
		var n int
		require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM loc_updates`).Scan(&n))
		return n
	}
}

func withHost(o types.Occurrence, host string) types.Occurrence {
	o.Host = host
	return o
}

func TestSQLite_Branch_UnchangedLocationIsNotRewritten(t *testing.T) {
	tests := []struct {
		name        string
		first       types.Occurrence
		second      types.Occurrence
		wantUpdates int
		wantBranch  string
		wantHost    string
	}{
		{"same branch", branchRow("main"), branchRow("main"), 0, "main", ""},
		{"empty branch over resolved one", branchRow("main"), branchRow(""), 0, "main", ""},
		{"empty over empty", branchRow(""), branchRow(""), 0, "", ""},
		{"resolved branch replaces the stored one", branchRow("main"), branchRow("feature/login"), 1, "feature/login", ""},
		{"resolved branch fills an empty one", branchRow(""), branchRow("main"), 1, "main", ""},
		{"host backfill still works", branchRow("main"), withHost(branchRow("main"), "github.com"), 1, "main", "github.com"},
		{"host backfill with an empty branch keeps the branch", branchRow("main"), withHost(branchRow(""), "github.com"), 1, "main", "github.com"},
		{"a recorded host is not rewritten", withHost(branchRow("main"), "github.com"), withHost(branchRow("main"), "gitlab.com"), 0, "main", "github.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, updates := countingSQLite(t)
			blob := branchBlob(t, s)
			require.NoError(t, s.AddOccurrences(blob, []types.Occurrence{tc.first}))
			require.Equal(t, 0, updates(), "the first write is an insert")
			require.NoError(t, s.AddOccurrences(blob, []types.Occurrence{tc.second}))
			assert.Equal(t, tc.wantUpdates, updates())

			got, err := s.GetOccurrences(blob)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, tc.wantBranch, got[0].Branch)
			assert.Equal(t, tc.wantHost, got[0].Host)
		})
	}
}

// Rescanning the same location repeatedly, as every scan of an unchanged repo
// does, never rewrites its row.
func TestSQLite_Branch_RepeatedRescanWritesNothing(t *testing.T) {
	s, updates := countingSQLite(t)
	blob := branchBlob(t, s)
	for range 5 {
		require.NoError(t, s.AddOccurrences(blob, []types.Occurrence{branchRow("main")}))
	}
	assert.Equal(t, 0, updates())
}
