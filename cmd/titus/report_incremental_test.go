package main

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

// Scan-level integration tests: the real runScan writes the datastore, the
// real report commands read it back.

func setIncremental(t *testing.T, v bool) {
	t.Helper()
	orig := scanIncremental
	t.Cleanup(func() { scanIncremental = orig })
	scanIncremental = v
}

// incrLocKey is the comparable form of a reported location.
func incrLocKeys(t *testing.T, stdout string) []string {
	t.Helper()
	var keys []string
	for _, f := range selDecodeFindings(t, stdout) {
		for _, m := range f.Matches {
			var raw []struct {
				Repository   *string `json:"repository"`
				Path         string  `json:"path"`
				Commit       *string `json:"commit"`
				AbsolutePath *string `json:"absolute_path"`
			}
			b, err := json.Marshal(m.Locations)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(b, &raw))
			for _, l := range raw {
				repo, commit, abs := "-", "-", "-"
				if l.Repository != nil {
					repo = *l.Repository
				}
				if l.Commit != nil {
					commit = *l.Commit
				}
				if l.AbsolutePath != nil {
					abs = *l.AbsolutePath
				}
				keys = append(keys, strings.Join([]string{repo, l.Path, commit, abs}, "|"))
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// C-INCREMENTAL-PARITY (DS4): a second repository holding an already-scanned
// blob is recorded by an incremental scan exactly as a full scan records it.
func TestScanIncremental_ReportParity(t *testing.T) {
	r1 := t.TempDir()
	r2 := t.TempDir()
	gitRepoForTest(t, r1, "https://github.com/acme/api.git", map[string]string{"config/app.env": locTestSecret})
	gitRepoForTest(t, r2, "https://github.com/other/api.git", map[string]string{"settings/app.env": locTestSecret})
	writeFileForTest(t, filepath.Join(r2, "copy", "app.env"), locTestSecret) // uncommitted working-tree copy

	ds := tempDatastore(t)
	setIncremental(t, false)
	scanForTest(t, r1, ds, "json", true)
	setIncremental(t, true)
	scanForTest(t, r2, ds, "json", true)

	control := tempDatastore(t)
	setIncremental(t, false)
	scanForTest(t, r2, control, "json", true)

	other := selRunOK(t, selArgs(ds, nil, "--format", "json", "--repo", "github.com/other/api")...)
	got := incrLocKeys(t, other.stdout)
	want := incrLocKeys(t, selRunOK(t, selArgs(control, nil, "--format", "json", "--repo", "github.com/other/api")...).stdout)
	require.NotEmpty(t, want)
	assert.Equal(t, want, got, "incremental scan records what a full scan records")

	var committed, workingTree bool
	for _, k := range got {
		parts := strings.Split(k, "|")
		if parts[0] == "github.com/other/api" && parts[1] == "settings/app.env" && parts[2] != "-" {
			committed = true
		}
		if parts[1] == "copy/app.env" && strings.HasPrefix(parts[3], r2) || parts[1] == "copy/app.env" && strings.HasSuffix(parts[3], "copy/app.env") {
			workingTree = true
		}
	}
	assert.True(t, committed, "committed copy at k2 recorded: %v", got)
	assert.True(t, workingTree, "working-tree copy recorded with an absolute path: %v", got)

	// The selector reaches the finding made by the first scan.
	assert.Len(t, selDecodeFindings(t, other.stdout), 1)

	all, _ := srcRun(t, ds, true)
	assert.Contains(t, all.repoValues(), "github.com/other/api")
	assert.Contains(t, all.repoValues(), "github.com/acme/api")
}

// S-T010 / R16-2: rescanning a datastore whose provenance has a NULL host
// fills the host, so the source is no longer marked host not recorded.
func TestScanIncremental_LegacyRescanFillsHost(t *testing.T) {
	repo := t.TempDir()
	gitRepoForTest(t, repo, "https://github.com/acme/api.git", map[string]string{"a/config.yml": locTestSecret})
	t.Chdir(repo)
	ds := tempDatastore(t)

	setIncremental(t, false)
	scanForTest(t, ".", ds, "json", true)
	// Reproduce a Titus <= v1.2.11 file: no recorded host, no location rows.
	clearAllHosts(t, filepath.Join(ds, "datastore.db"))

	before := selRunOK(t, selArgs(ds, nil, "--format", "json")...)
	for _, f := range selDecodeFindings(t, before.stdout) {
		for _, m := range f.Matches {
			for _, l := range m.Locations {
				assert.False(t, l.HostRecorded, "legacy row is flagged before the rescan")
			}
		}
	}

	setIncremental(t, true)
	scanForTest(t, ".", ds, "json", true)

	after := selRunOK(t, selArgs(ds, nil, "--format", "json")...)
	seen := 0
	for _, f := range selDecodeFindings(t, after.stdout) {
		for _, m := range f.Matches {
			for _, l := range m.Locations {
				seen++
				assert.True(t, l.HostRecorded, "rescan fills the host: %+v", l)
			}
		}
	}
	assert.Positive(t, seen)
	d, _ := srcRun(t, ds, true)
	for _, r := range d.Repos {
		assert.True(t, r.HostRecorded, "%s", r.Value)
	}
	assert.Contains(t, d.repoValues(), "github.com/acme/api")
}

// S-T003: the scanner records the remote's host; none without a remote; a
// credentialed remote records the host and never the credential.
func TestScanE2E_RecordsRepositoryHost(t *testing.T) {
	tests := []struct {
		id, origin, wantHost string
	}{
		{"origin", "https://github.com/acme/api.git", "github.com"},
		{"no-origin", "", ""},
		{"userinfo", "https://user:TOKEN123@github.com/acme/api.git", "github.com"},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			repo := t.TempDir()
			gitRepoForTest(t, repo, tc.origin, map[string]string{"a/config.yml": locTestSecret})
			ds := tempDatastore(t)
			setIncremental(t, false)
			scanForTest(t, repo, ds, "json", true)

			s, err := store.New(store.Config{Path: filepath.Join(ds, "datastore.db")})
			require.NoError(t, err)
			defer func() { _ = s.Close() }()
			recs, err := s.ListSources()
			require.NoError(t, err)
			require.NotEmpty(t, recs)
			gitRecs := 0
			for _, r := range recs {
				if r.Kind != "git" {
					continue
				}
				gitRecs++
				assert.Equal(t, tc.wantHost, r.Host)
				assert.True(t, r.HostRecorded, "a new write is never host not recorded")
				assert.NotContains(t, r.Repository, "TOKEN123")
				assert.NotContains(t, r.Repository, "user:")
			}
			require.NotZero(t, gitRecs, "the scan produced a git source record: %+v", recs)
			d, run := srcRun(t, ds, true)
			assert.NotContains(t, run.stdout, "TOKEN123")
			if tc.wantHost != "" {
				assert.Contains(t, d.repoValues(), "github.com/acme/api")
			}
		})
	}
}

// S-T010: a blob with no match writes provenance (so its source is listed)
// but no location rows.
func TestScanIncremental_NoMatchBlobWritesProvenanceNotLocations(t *testing.T) {
	repo := t.TempDir()
	gitRepoForTest(t, repo, "https://github.com/acme/quiet.git", map[string]string{"notes.txt": "nothing to see here\n"})
	ds := tempDatastore(t)
	setIncremental(t, true)
	scanForTest(t, repo, ds, "json", true)

	s, err := store.New(store.Config{Path: filepath.Join(ds, "datastore.db")})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	recs, err := s.ListSources()
	require.NoError(t, err)
	var found bool
	for _, r := range recs {
		if r.Repository == "github.com/acme/quiet" || strings.HasSuffix(r.Repository, "acme/quiet") {
			found = true
			assert.Equal(t, "git", r.Kind)
		}
	}
	assert.True(t, found, "the scanned repository is a recorded source: %+v", recs)

	blob := types.ComputeBlobID([]byte("nothing to see here\n"))
	// GetOccurrences merges provenance and location rows, so it cannot tell
	// them apart; count the tables directly.
	db, err := sql.Open("sqlite", filepath.Join(ds, "datastore.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	var provRows, locRows int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM provenance WHERE blob_id = ? AND path = 'notes.txt'`, blob.Hex()).Scan(&provRows))
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM blob_locations WHERE blob_id = ?`, blob.Hex()).Scan(&locRows))
	assert.Equal(t, 1, provRows, "the no-match blob's provenance is recorded")
	assert.Zero(t, locRows, "a no-match blob gets no location rows")

	scoped, _ := srcRun(t, ds, false)
	assert.NotContains(t, scoped.repoValues(), "github.com/acme/quiet", "no finding, so not in the findings scope")
	all, _ := srcRun(t, ds, true)
	assert.Contains(t, all.repoValues(), "github.com/acme/quiet")
}
