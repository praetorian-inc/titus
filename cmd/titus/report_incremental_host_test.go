package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/types"
)

// A repository scanned with --incremental is known only through provenance (an
// incremental scan writes no blob_locations row for content the datastore
// already holds or for a blob it scans first). Its recorded host must survive
// that route, so --repo and --namespace select it and the report does not
// flag it "host not recorded". Those rows were written by a binary that
// records the host, so they are not legacy rows.
func TestScanIncremental_ProvenanceOnlyRepoIsSelectableByRepoAndNamespace(t *testing.T) {
	repoA, repoB := t.TempDir(), t.TempDir()
	gitRepoForTest(t, repoA, "https://github.com/acme/api.git", map[string]string{"config/app.env": locTestSecret})
	gitRepoForTest(t, repoB, "https://github.com/other/api.git", map[string]string{"config/app.env": locTestSecret})
	ds := tempDatastore(t)

	// Scan A stores the blob with the only rule excluded: no match, so the
	// scan writes provenance and no location row. Scan B then matches it.
	setIncremental(t, true)
	scanExcludingForTest(t, repoA, ds, "json", true, `^test\.locations\.`)
	setIncremental(t, false)
	scanForTest(t, repoB, ds, "json", true)

	for _, flags := range [][]string{{"--repo", "acme/api"}, {"--namespace", "acme"}} {
		t.Run(flags[0]+" "+flags[1], func(t *testing.T) {
			j := selRunOK(t, selArgs(ds, nil, append([]string{"--format", "json"}, flags...)...)...)
			findings := selDecodeFindings(t, j.stdout)
			require.Len(t, findings, 1, "the acme/api location selects the finding")
			var sawAcme bool
			for _, f := range findings {
				for _, m := range f.Matches {
					for _, l := range m.Locations {
						if l.Repository != nil && *l.Repository == "github.com/acme/api" {
							sawAcme = true
							assert.True(t, l.HostRecorded, "a new write is never host not recorded")
						}
					}
				}
			}
			assert.True(t, sawAcme, "the provenance-only acme/api location is reported: %s", j.stdout)

			h := selRunOK(t, selArgs(ds, nil, flags...)...)
			assert.NotContains(t, h.stdout, "host not recorded")
		})
	}
}

// A second --incremental scan of clean content from another repository keeps
// the source (provenance) without writing any location row.
func TestScanIncremental_CleanContentFromSecondRepoKeepsSourceWithoutLocations(t *testing.T) {
	const clean = "nothing to see here\n"
	repoA, repoB := t.TempDir(), t.TempDir()
	gitRepoForTest(t, repoA, "https://github.com/acme/quiet.git", map[string]string{"notes.txt": clean})
	gitRepoForTest(t, repoB, "https://github.com/other/quiet.git", map[string]string{"notes.txt": clean})
	ds := tempDatastore(t)

	setIncremental(t, true)
	scanForTest(t, repoA, ds, "json", true)
	scanForTest(t, repoB, ds, "json", true)

	all, _ := srcRun(t, ds, true)
	assert.Contains(t, all.repoValues(), "github.com/acme/quiet")
	assert.Contains(t, all.repoValues(), "github.com/other/quiet")

	db, err := sql.Open("sqlite", filepath.Join(ds, "datastore.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	blob := types.ComputeBlobID([]byte(clean))
	var provRows, locRows int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM provenance WHERE blob_id = ? AND repo_path = 'github.com/other/quiet'`, blob.Hex()).Scan(&provRows))
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM blob_locations WHERE blob_id = ?`, blob.Hex()).Scan(&locRows))
	assert.Equal(t, 1, provRows, "the second repository's provenance row is kept")
	assert.Zero(t, locRows, "clean content gets no location rows")
}
