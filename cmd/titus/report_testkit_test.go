package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

// Shared helpers for the report selector, `report sources` and incremental
// rescan tests (LAB-7490).
//
// Lines ending in the marker BASEDROP use a symbol or a column that does not
// exist at base commit 5a910ac. The unfiltered goldens under
// testdata/report_unfiltered were generated at that base commit from this
// file with those lines deleted (see report_select_cli_test.go for the exact
// command), which is what makes them an independent oracle for "output
// without selectors is unchanged".

// cliResult is one in-process CLI invocation with the streams kept apart.
type cliResult struct {
	stdout string
	stderr string
	err    error
}

// resetReportFlags returns every package-level flag variable of the report
// commands to its registered default. cobra binds flags to package variables
// and never resets them, so an invocation would otherwise inherit the
// previous one's values. The help flags are reset too: cobra leaves --help
// set after a run.
func resetReportFlags() {
	reportRepos, reportNamespaces, reportPaths = nil, nil, nil    // BASEDROP
	summaryRepos, summaryNamespaces, summaryPaths = nil, nil, nil // BASEDROP
	sourcesFormat = "human"                                       // BASEDROP
	reportFormat, summaryFormat = "human", "human"
	reportShowRejected = false
	reportDatastore = "titus.ds"
	reportColor = "auto"
	resetHelpFlag(rootCmd.Flags().Lookup("help"))
	resetHelpFlag(reportCmd.Flags().Lookup("help"))
	resetHelpFlag(summaryCmd.Flags().Lookup("help"))
	resetHelpFlag(sourcesCmd.Flags().Lookup("help"))    // BASEDROP
	resetHelpFlag(sourcesAllCmd.Flags().Lookup("help")) // BASEDROP
}

func resetHelpFlag(f *pflag.Flag) {
	if f == nil {
		return
	}
	_ = f.Value.Set("false")
	f.Changed = false
}

// runRootSplit runs the root command in process with stdout and stderr in
// separate buffers and every report flag reset before and after. NO_COLOR is
// set so the "auto" color mode is deterministic.
func runRootSplit(t *testing.T, args ...string) cliResult {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	var stdout, stderr bytes.Buffer
	resetReportFlags()
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetReportFlags()
	})
	err := Execute()
	return cliResult{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

// selTestRuleID is a builtin rule, so the report resolves its name and
// structural ID the way it does for a real scan.
const selTestRuleID = "np.aws.1"

var selTestCommitDate = time.Date(2026, 6, 15, 9, 30, 0, 0, time.UTC)

// dsBuilder seeds a SQLite datastore through the store API only: provenance
// with AddProvenance, locations with types.OccurrencesOf + AddOccurrences.
type dsBuilder struct {
	t        *testing.T
	s        store.Store
	path     string
	rule     *types.Rule
	blobs    map[string]types.BlobID
	groups   map[string][][]byte
	matches  int
	commits  int
	legacies []types.BlobID
}

func newDSBuilder(t *testing.T) *dsBuilder {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ds.db")
	s, err := store.New(store.Config{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	rules, err := rule.NewLoader().LoadBuiltinRules()
	require.NoError(t, err)
	i := slices.IndexFunc(rules, func(r *types.Rule) bool { return r.ID == selTestRuleID })
	require.GreaterOrEqual(t, i, 0, "builtin rule %s not found", selTestRuleID)
	require.NoError(t, s.AddRule(rules[i]))

	return &dsBuilder{
		t: t, s: s, path: path, rule: rules[i],
		blobs:  map[string]types.BlobID{},
		groups: map[string][][]byte{},
	}
}

// blob adds the blob key once and returns its ID.
func (b *dsBuilder) blob(key string) types.BlobID {
	b.t.Helper()
	if id, ok := b.blobs[key]; ok {
		return id
	}
	content := []byte("content-" + key)
	id := types.ComputeBlobID(content)
	require.NoError(b.t, b.s.AddBlob(id, int64(len(content))))
	b.blobs[key] = id
	return id
}

// match records a match of blob key with the given secret. Blobs that share a
// secret share a finding.
func (b *dsBuilder) match(key, secret string) {
	b.t.Helper()
	blobID := b.blob(key)
	groups := [][]byte{[]byte(secret)}
	b.groups[key] = groups
	findingID := types.ComputeFindingID(b.rule.StructuralID, groups)
	require.NoError(b.t, b.s.AddFinding(&types.Finding{ID: findingID, RuleID: b.rule.ID, Groups: groups}))
	b.matches++
	require.NoError(b.t, b.s.AddMatch(&types.Match{
		StructuralID: fmt.Sprintf("sm-%s-%d", key, b.matches),
		RuleID:       b.rule.ID,
		BlobID:       blobID,
		Groups:       groups,
		Location: types.Location{Source: types.SourceSpan{
			Start: types.SourcePoint{Line: 3, Column: 7},
			End:   types.SourcePoint{Line: 3, Column: 7 + len(secret)},
		}},
		Snippet: types.Snippet{Matching: []byte(secret)},
	}))
}

// finding adds blob key with a match whose secret is unique to the key and
// returns the finding ID.
func (b *dsBuilder) finding(key string) string {
	b.t.Helper()
	b.match(key, "sel_"+key)
	return types.ComputeFindingID(b.rule.StructuralID, b.groups[key])
}

func (b *dsBuilder) nextCommit() *types.CommitMetadata {
	b.commits++
	return &types.CommitMetadata{CommitID: fmt.Sprintf("%040x", b.commits), CommitterTimestamp: selTestCommitDate}
}

func (b *dsBuilder) addProv(key string, prov types.Provenance) {
	b.t.Helper()
	blobID := b.blob(key)
	require.NoError(b.t, b.s.AddProvenance(blobID, prov))
	require.NoError(b.t, b.s.AddOccurrences(blobID, types.OccurrencesOf(prov)))
}

// remoteLoc records the blob at a repository identified by its remote, the
// shape an API-enumerated repository has: no scan root.
func (b *dsBuilder) remoteLoc(key, host, repo, path string) {
	b.t.Helper()
	b.addProv(key, types.GitProvenance{
		RepoPath:       host + "/" + repo,
		Host:           host, // BASEDROP
		RemoteIdentity: true,
		BlobPath:       path,
		Commit:         b.nextCommit(),
	})
}

// localLoc records the blob at a repository scanned from a local folder with
// no remote: the repository is recorded as typed and the scan root is kept.
func (b *dsBuilder) localLoc(key, repoAsTyped, root, path string) {
	b.t.Helper()
	b.addProv(key, types.GitProvenance{
		RepoPath: repoAsTyped,
		RepoRoot: root,
		BlobPath: path,
		Commit:   b.nextCommit(),
	})
}

// hnrLoc records the blob at a repository written by a Titus that did not
// record the host (<= v1.2.11): a git provenance row with no covering
// location row, whose host column is NULL. Only the provenance row exists, so
// the report shows it as "host not recorded".
func (b *dsBuilder) hnrLoc(key, repo, path string) {
	b.t.Helper()
	blobID := b.blob(key)
	require.NoError(b.t, b.s.AddProvenance(blobID, types.GitProvenance{
		RepoPath: repo,
		BlobPath: path,
		Commit:   b.nextCommit(),
	}))
	b.legacies = append(b.legacies, blobID)
}

// reject marks the finding of the given ID rejected.
func (b *dsBuilder) reject(findingID string) {
	b.t.Helper()
	require.NoError(b.t, b.s.SetAnnotation("finding", findingID, store.StatusReject, ""))
}

// done closes the store and returns the datastore path. A Titus <= v1.2.11
// wrote a NULL host; the current writer never does, so the host of the rows
// hnrLoc made is cleared with the one UPDATE that reproduces that older file.
func (b *dsBuilder) done() string {
	b.t.Helper()
	require.NoError(b.t, b.s.Close())
	if len(b.legacies) > 0 {
		clearProvenanceHosts(b.t, b.path, b.legacies) // BASEDROP
	}
	return b.path
}

func clearProvenanceHosts(t *testing.T, path string, blobs []types.BlobID) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	for _, id := range blobs {
		_, err := db.Exec(`UPDATE provenance SET host = NULL WHERE blob_id = ? AND type = 'git'`, id.Hex())
		require.NoError(t, err)
	}
}

// ds1 names the locations of DS1 (test-plan section 7): host, repository,
// path, blob (and so finding) key.
var ds1Locations = []struct {
	name, host, repo, path, blob string
}{
	{"L1", "github.com", "acme/api", "config/app.env", "B1"},
	{"L2", "github.com", "other/api", "settings/app.env", "B1"},
	{"L3", "gitlab.example.com", "acme/api", "deploy.yml", "B2"},
	{"L4", "github.com", "acme/team/api", "a.txt", "B3"},
	{"L5", "gitlab.example.com", "acme/team/sub/api", "b.txt", "B4"},
	{"L6", "gitlab.example.com", "acme/team-other/api", "c.txt", "B5"},
	{"L7", "", "acme/api", "h1.txt", "B6"},
	{"L8", "", "api", "h2.txt", "B7"},
	{"L9", "", "team/api", "h3.txt", "B8"},
	{"L10", "", "zzz/unrelated", "h4.txt", "B9"},
	{"L11", "github.com", "acmecorp/api", "d.txt", "B10"},
}

// ds1FindingKey maps a finding name to the blob key it is seeded under. The
// plan's F1..F10 are the findings of B1..B10.
func ds1FindingKey(n int) string { return fmt.Sprintf("B%d", n) }

// ds1Names maps "repository path" as the JSON report prints a location to the
// plan's location name.
var ds1Names = func() map[string]string {
	m := map[string]string{}
	for _, l := range ds1Locations {
		repo := l.repo
		if l.host != "" {
			repo = l.host + "/" + l.repo
		}
		m[repo+" "+l.path] = l.name
	}
	return m
}()

func seedDS1Into(b *dsBuilder, rejected ...string) {
	b.t.Helper()
	ids := map[string]string{}
	for n := 1; n <= 10; n++ {
		ids[ds1FindingKey(n)] = b.finding(ds1FindingKey(n))
	}
	for _, l := range ds1Locations {
		if l.host == "" {
			b.hnrLoc(l.blob, l.repo, l.path)
		} else {
			b.remoteLoc(l.blob, l.host, l.repo, l.path)
		}
	}
	for _, key := range rejected {
		b.reject(ids[key])
	}
}

// seedDS1 builds DS1: eleven locations over ten findings, host-qualified
// repositories at two hosts and four "host not recorded" rows. Blob keys
// listed in rejected have their finding rejected. It returns the datastore.
func seedDS1(t *testing.T, rejected ...string) string {
	t.Helper()
	b := newDSBuilder(t)
	seedDS1Into(b, rejected...)
	return b.done()
}

// ds2Roots holds the absolute folders of DS2, rooted under a temp dir.
type ds2Roots struct {
	a, b, x, y string
}

// seedDS2 builds DS2: the same repository scanned from two clones (committed
// and working-tree locations each) and the same relative file scanned from
// two folders. Folder paths are rooted under a temp dir.
func seedDS2(t *testing.T) (string, ds2Roots) {
	t.Helper()
	root := t.TempDir()
	roots := ds2Roots{
		a: filepath.Join(root, "work", "a", "api"),
		b: filepath.Join(root, "work", "b", "api"),
		x: filepath.Join(root, "work", "x"),
		y: filepath.Join(root, "work", "y"),
	}
	b := newDSBuilder(t)
	const repo = "github.com/acme/api"
	committed := func(key, scanRoot, path string) {
		b.finding(key)
		b.addProv(key, types.GitProvenance{
			RepoPath: repo, Host: "github.com", RemoteIdentity: true, // BASEDROP
			RepoRoot: scanRoot, BlobPath: path, Commit: b.nextCommit(),
		})
	}
	workingTree := func(key, scanRoot, path string) {
		b.finding(key)
		b.addProv(key, types.GitProvenance{
			RepoPath: repo, Host: "github.com", RemoteIdentity: true, // BASEDROP
			RepoRoot: scanRoot, BlobPath: path,
			Locations: []types.GitLocation{{Path: path, WorkingTree: true}},
		})
	}
	committed("C1", roots.a, "config/app.env")
	workingTree("C2", roots.a, "config/app.env")
	b.finding("C3")
	for _, dir := range []string{roots.x, roots.y} {
		// FileProvenance records the absolute path of its relative path
		// against the working directory at the time of the scan.
		require.NoError(t, os.MkdirAll(dir, 0o755))
		t.Chdir(dir)
		b.addProv("C3", types.FileProvenance{FilePath: "secrets.txt"})
	}
	committed("C4", roots.b, "lib/key.go")
	workingTree("C5", roots.b, "lib/key.go")
	return b.done(), roots
}

// seedDS3 builds DS1 plus sources that have no findings: a repository whose
// blob has no matches, and a record that yields no selector value.
func seedDS3(t *testing.T, rejected ...string) string {
	t.Helper()
	b := newDSBuilder(t)
	seedDS1Into(b, rejected...)
	// A scanned repository where nothing matched.
	b.blob("CLEAN")
	b.remoteLoc("CLEAN", "github.com", "acme/clean", "README.md")
	// An extended source record with neither a repository nor a path.
	b.addProv("EXT", types.ExtendedProvenance{Payload: map[string]interface{}{"source": "confluence"}})
	return b.done()
}

// seedDS5 builds one finding with fullMatches+1 matches: the first
// fullMatches blobs are in github.com/acme/api and the last in
// github.com/other/api. It returns the datastore and the last blob's ID.
func seedDS5(t *testing.T) (string, types.BlobID) {
	t.Helper()
	b := newDSBuilder(t)
	var last types.BlobID
	for i := 1; i <= fullMatches+1; i++ {
		key := fmt.Sprintf("D%d", i)
		b.match(key, "sel_shared")
		repo := "acme/api"
		if i == fullMatches+1 {
			repo = "other/api"
		}
		b.remoteLoc(key, "github.com", repo, fmt.Sprintf("f%d.txt", i))
		last = b.blobs[key]
	}
	return b.done(), last
}

// reportCmdArgs returns `report <sub...> --datastore ds <rest...>`.
func reportCmdArgs(ds string, sub []string, rest ...string) []string {
	args := append([]string{"report"}, sub...)
	args = append(args, "--datastore", ds)
	return append(args, rest...)
}

// reportLocationNames runs `report --format json` output through the DS1
// naming table and returns the names of every location in the report, one
// entry per occurrence, sorted.
func reportLocationNames(t *testing.T, stdout string) []string {
	t.Helper()
	var names []string
	for _, f := range decodeReportJSON(t, []byte(stdout)) {
		for _, m := range f.Matches {
			for _, l := range m.Locations {
				repo := ""
				if l.Repository != nil {
					repo = *l.Repository
				}
				key := repo + " " + l.Path
				name, ok := ds1Names[key]
				require.True(t, ok, "location %q is not a DS1 location", key)
				names = append(names, name)
			}
		}
	}
	return sortedNames(names...)
}

// sortedNames orders location names numerically (L2 before L10).
func sortedNames(names ...string) []string {
	out := slices.Clone(names)
	slices.SortFunc(out, func(a, b string) int {
		return strings.Compare(fmt.Sprintf("%03s", a), fmt.Sprintf("%03s", b))
	})
	return out
}

// jsonValid reports whether data is exactly one JSON document.
func jsonValid(data string) bool {
	return json.Valid([]byte(data))
}

// clearAllHosts reproduces a datastore written by Titus <= v1.2.11: every
// provenance host NULL and no blob_locations rows.
func clearAllHosts(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	_, err = db.Exec(`UPDATE provenance SET host = NULL WHERE type = 'git'`) // BASEDROP
	require.NoError(t, err)
	_, err = db.Exec(`DELETE FROM blob_locations`) // BASEDROP
	require.NoError(t, err)
}
