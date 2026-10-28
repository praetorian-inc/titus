package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

// Unit tests for the pure selection logic in report_select.go. Every
// occurrence is produced by the same path a datastore uses (OccurrencesOf for
// a recorded location, MergeOccurrences for a legacy row whose host was never
// recorded), never by setting HostRecorded or Host by hand. The expected
// selections come from the approved outcome plan (outcome-plan-2.json, DS1 and
// DS2), not from running the selector. The helpers carry the su prefix so they
// cannot collide with the CLI testkit.

var suCommitDate = time.Date(2026, 6, 15, 9, 30, 0, 0, time.UTC)

func suCommit(n int) *types.CommitMetadata {
	return &types.CommitMetadata{CommitID: fmt.Sprintf("%040x", n), CommitterTimestamp: suCommitDate}
}

// suRemote is a committed location of a repository identified by its remote
// (host/owner/repo), the shape an API-enumerated or remote-cloned repository has.
func suRemote(host, repo, path string) types.Occurrence {
	return types.OccurrencesOf(types.GitProvenance{
		RepoPath:       host + "/" + repo,
		Host:           host,
		RemoteIdentity: true,
		BlobPath:       path,
		Commit:         suCommit(1),
	})[0]
}

// suRemoteWT is a working-tree copy of a remote-identified repository. Its
// absolute path is recorded, its commit is not.
func suRemoteWT(host, repo, root, path string) types.Occurrence {
	return types.OccurrencesOf(types.GitProvenance{
		RepoPath:       host + "/" + repo,
		Host:           host,
		RemoteIdentity: true,
		RepoRoot:       root,
		Locations:      []types.GitLocation{{Path: path, WorkingTree: true}},
	})[0]
}

// suLocal is a committed location of a repository with no remote: the scan
// root is recorded, so the location has an absolute path and no host.
func suLocal(repo, root, path string) types.Occurrence {
	return types.OccurrencesOf(types.GitProvenance{
		RepoPath: repo,
		RepoRoot: root,
		BlobPath: path,
		Commit:   suCommit(2),
	})[0]
}

// suHNR is a legacy git provenance row with no covering location row, the
// shape a datastore written by Titus <= v1.2.11 has. MergeOccurrences marks it
// HostRecorded=false.
func suHNR(repo, path string) types.Occurrence {
	occs := types.MergeOccurrences(nil, []types.Provenance{types.GitProvenance{
		RepoPath: repo,
		BlobPath: path,
		Commit:   suCommit(3),
	}})
	if len(occs) != 1 || occs[0].HostRecorded {
		panic(fmt.Sprintf("suHNR: want one host-not-recorded occurrence, got %+v", occs))
	}
	return occs[0]
}

func suFile(path string) types.Occurrence {
	return types.OccurrencesOf(types.FileProvenance{FilePath: path})[0]
}

// suDS1 is outcome-plan-2.json DS1 (locations L1..L11) as occurrences.
func suDS1() map[string]types.Occurrence {
	return map[string]types.Occurrence{
		"L1":  suRemote("github.com", "acme/api", "config/app.env"),
		"L2":  suRemote("github.com", "other/api", "settings/app.env"),
		"L3":  suRemote("gitlab.example.com", "acme/api", "deploy.yml"),
		"L4":  suRemote("github.com", "acme/team/api", "a.txt"),
		"L5":  suRemote("gitlab.example.com", "acme/team/sub/api", "b.txt"),
		"L6":  suRemote("gitlab.example.com", "acme/team-other/api", "c.txt"),
		"L7":  suHNR("acme/api", "h1.txt"),
		"L8":  suHNR("api", "h2.txt"),
		"L9":  suHNR("team/api", "h3.txt"),
		"L10": suHNR("zzz/unrelated", "h4.txt"),
		"L11": suRemote("github.com", "acmecorp/api", "d.txt"),
	}
}

// suDS2 is outcome-plan-2.json DS2 (locations P1..P5): the same remote
// repository committed (P1) and as a working tree under /work/a/api (P2), two
// local repositories holding identically named files (P3, P4), and a sibling
// folder whose name extends /work/a (P5).
func suDS2() map[string]types.Occurrence {
	return map[string]types.Occurrence{
		"P1": suRemote("github.com", "acme/api", "config/app.env"),
		"P2": suRemoteWT("github.com", "acme/api", "/work/a/api", "config/app.env"),
		"P3": suLocal("repo-x", "/work/x", "secrets.txt"),
		"P4": suLocal("repo-y", "/work/y", "secrets.txt"),
		"P5": suLocal("repo-ab", "/work/ab", "lib/key.go"),
	}
}

// suDS3 is a legacy host-not-recorded row whose repository is work/a, beside a
// local repository really scanned from /work/a. Both are rows a datastore can
// hold: the first is a Titus <= v1.2.11 row, the second a current local scan.
func suDS3() map[string]types.Occurrence {
	return map[string]types.Occurrence{
		"H1": suHNR("work/a", "legacy.txt"),
		"A1": suLocal("repo-a", "/work/a", "real.txt"),
	}
}

func suSelected(t *testing.T, sel *reportSelector, set map[string]types.Occurrence) []string {
	t.Helper()
	var got []string
	for name, o := range set {
		if sel.selects(o) {
			got = append(got, name)
		}
	}
	if got == nil {
		got = []string{}
	}
	return sortedNames(got...)
}

// suWant is the expected-name counterpart of suSelected: sorted, never nil.
func suWant(names []string) []string {
	if names == nil {
		names = []string{}
	}
	return sortedNames(names...)
}

// TestNewReportSelector_Validation covers the value rules of the three flags
// (R17 item 1): blank is invalid for every flag, --namespace additionally
// rejects a trailing "/" or an empty segment, and --repo and --path accept
// every other non-blank value, including those a scan can record verbatim.
//
// It fails if validation is dropped (a blank would be accepted and later match
// every location whose form is empty), if --repo borrowed --namespace's segment
// rule (a typed "api/" repository would become unselectable), or if the error
// stops naming the flag.
func TestNewReportSelector_Validation(t *testing.T) {
	tests := []struct {
		name      string
		repos     []string
		ns        []string
		paths     []string
		wantErr   string // substring; "" = valid
		wantFlag  string
		wantRepos int
	}{
		{name: "S-T003/repo typed trailing slash", repos: []string{"api/"}, wantRepos: 1},
		{name: "S-T003/repo empty segment", repos: []string{"a//api"}, wantRepos: 1},
		{name: "S-T003/repo lone slash", repos: []string{"/"}, wantRepos: 1},
		{name: "S-T003/repo URL form", repos: []string{"https://x/acme/api.git"}, wantRepos: 1},
		{name: "S-T003/repo absolute folder", repos: []string{"/work/a/api"}, wantRepos: 1},
		{name: "S-T003/repo with spaces and commas", repos: []string{"my repo,v2"}, wantRepos: 1},
		{name: "S-T003/repo empty", repos: []string{""}, wantErr: "--repo requires a non-empty value", wantFlag: "--repo"},
		{name: "S-T003/repo blank", repos: []string{"  "}, wantErr: "--repo requires a non-empty value", wantFlag: "--repo"},
		{name: "S-T003/repo second value empty", repos: []string{"acme/api", ""}, wantErr: "--repo requires a non-empty value", wantFlag: "--repo"},
		{name: "S-T003/namespace plain", ns: []string{"acme/team"}},
		{name: "S-T003/namespace host", ns: []string{"github.com"}},
		{name: "S-T003/namespace absolute folder", ns: []string{"/work/a"}},
		{name: "S-T003/namespace trailing slash", ns: []string{"api/"}, wantErr: "--namespace value", wantFlag: "--namespace"},
		{name: "S-T003/namespace empty segment", ns: []string{"a//b"}, wantErr: "--namespace value", wantFlag: "--namespace"},
		{name: "S-T003/namespace lone slash", ns: []string{"/"}, wantErr: "--namespace value", wantFlag: "--namespace"},
		{name: "S-T003/namespace empty", ns: []string{""}, wantErr: "--namespace requires a non-empty value", wantFlag: "--namespace"},
		{name: "S-T003/namespace blank", ns: []string{" "}, wantErr: "--namespace requires a non-empty value", wantFlag: "--namespace"},
		{name: "S-T003/path plain", paths: []string{"config/app.env"}},
		{name: "S-T003/path absolute", paths: []string{"/work/a/api/config/app.env"}},
		{name: "S-T003/path trailing slash is not rejected", paths: []string{"dir/"}},
		{name: "S-T003/path with space", paths: []string{"my file.txt"}},
		{name: "S-T003/path empty", paths: []string{""}, wantErr: "--path requires a non-empty value", wantFlag: "--path"},
		{name: "S-T003/path blank", paths: []string{"\t"}, wantErr: "--path requires a non-empty value", wantFlag: "--path"},
		{name: "S-T003/mixed valid", repos: []string{"a"}, ns: []string{"b"}, paths: []string{"c"}, wantRepos: 1},
		{name: "S-T003/one bad value among valid ones", repos: []string{"a"}, ns: []string{"b", ""}, paths: []string{"c"}, wantErr: "--namespace requires a non-empty value", wantFlag: "--namespace"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sel, err := newReportSelector(tc.repos, tc.ns, tc.paths)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Contains(t, err.Error(), tc.wantFlag)
				assert.Nil(t, sel, "an invalid selector must never be returned, so no caller can fall back to a half-built one")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, sel)
			assert.True(t, sel.active())
			assert.Len(t, sel.repos, tc.wantRepos)
		})
	}

	t.Run("S-T003/no values is inactive and not an error", func(t *testing.T) {
		sel, err := newReportSelector(nil, nil, nil)
		require.NoError(t, err)
		assert.False(t, sel.active())
		assert.False(t, sel.filtersRepositories())
	})
	t.Run("S-T003/nil selector is inactive", func(t *testing.T) {
		var sel *reportSelector
		assert.False(t, sel.active())
		assert.False(t, sel.filtersRepositories())
		assert.True(t, sel.selects(suRemote("github.com", "a/b", "x")))
	})
	t.Run("S-T003/path alone does not filter repositories", func(t *testing.T) {
		sel, err := newReportSelector(nil, nil, []string{"a.txt"})
		require.NoError(t, err)
		assert.True(t, sel.active())
		assert.False(t, sel.filtersRepositories())
	})
}

// TestReportSelector_SelectsTable pins the selection rules to the approved
// outcome-plan-2.json expectations over DS1 and DS2, plus the literal-value
// rows of S-T005. Each row names its plan case.
//
// It fails if matching became a raw string prefix (C-NS-BOUNDARY and C-NS-HOST
// would add L6 and L11), if the host-less first-segment extension were dropped
// or applied to recorded hosts (C-REPO-HOSTLESS, C-NOPARSE-HOST), if selector
// kinds intersected instead of uniting, or if the absolute-path forms were not
// consulted (C-*-ABSFOLDER, C-PATH-*).
func TestReportSelector_SelectsTable(t *testing.T) {
	type sel struct{ repos, ns, paths []string }
	tests := []struct {
		name string
		set  func() map[string]types.Occurrence
		sel  sel
		want []string
	}{
		// repeated, mixed and overlapping selectors (INV-UNION)
		{"C-UNION-OVERLAP", suDS1, sel{repos: []string{"github.com/acme/api"}, ns: []string{"github.com/acme"}}, []string{"L1", "L4", "L7"}},
		{"C-UNION-MIXED", suDS1, sel{repos: []string{"github.com/other/api"}, paths: []string{"deploy.yml"}}, []string{"L2", "L3"}},
		{"C-UNION-REPEAT", suDS1, sel{repos: []string{"github.com/other/api", "gitlab.example.com/acme/team/sub/api"}}, []string{"L2", "L5"}},
		// repository forms (INV-REPO, INV-NOPARSE)
		{"C-REPO-HOSTLESS", suDS1, sel{repos: []string{"acme/api"}}, []string{"L1", "L3", "L7", "L8"}},
		{"C-REPO-DISPLAYED", suDS1, sel{repos: []string{"gitlab.example.com/acme/api"}}, []string{"L3", "L7"}},
		{"C-NOPARSE-HOST", suDS1, sel{repos: []string{"github.com/acme/api"}}, []string{"L1", "L7"}},
		{"C-REPO-ABSFOLDER", suDS2, sel{repos: []string{"/work/a/api"}}, []string{"P2"}},
		// namespaces (INV-NS)
		{"C-NS-HOST", suDS1, sel{ns: []string{"github.com/acme"}}, []string{"L1", "L4", "L7"}},
		{"C-NS-HOSTLESS", suDS1, sel{ns: []string{"acme"}}, []string{"L1", "L3", "L4", "L5", "L6", "L7"}},
		{"C-NS-BOUNDARY", suDS1, sel{ns: []string{"acme/team"}}, []string{"L4", "L5", "L9"}},
		{"C-NS-ABSFOLDER", suDS2, sel{ns: []string{"/work/a"}}, []string{"P2"}},
		// host-not-recorded matching (INV-HNR-MATCH)
		{"C-HNR-REPO", suDS1, sel{repos: []string{"github.com/acme/api"}}, []string{"L1", "L7"}},
		{"C-HNR-REPO-SHORT", suDS1, sel{repos: []string{"acme/api"}}, []string{"L1", "L3", "L7", "L8"}},
		{"C-HNR-NS", suDS1, sel{ns: []string{"acme/team"}}, []string{"L4", "L5", "L9"}},
		{"C-HNR-NS-EMPTY", suDS1, sel{ns: []string{"github.com"}}, []string{"L1", "L2", "L4", "L11"}},
		{"S-T003/HNR unrelated record never selected by another repo", suDS1, sel{repos: []string{"github.com/zzz/other"}}, []string{}},
		// A host-not-recorded record is selected by its listed form and, by the
		// documented HNR extension, by any host-qualified spelling of it.
		{"S-T003/HNR record selected by its listed form", suDS1, sel{repos: []string{"zzz/unrelated"}}, []string{"L10"}},
		{"S-T003/HNR record selected by host-qualified form", suDS1, sel{repos: []string{"github.com/zzz/unrelated"}}, []string{"L10"}},
		{"S-T003/recorded host is not selected by another host", suDS1, sel{repos: []string{"gitlab.example.com/other/api"}}, []string{}},
		// An absolute-folder selector is never a host-qualified spelling: the
		// first-segment extension must not turn "/work/a" or "C:/work/a" into
		// "work/a" (INV-HNR-MATCH, absolute forms).
		{"HNR-ABS/repo folder does not select hostless work/a", suDS3, sel{repos: []string{"/work/a"}}, []string{"A1"}},
		{"HNR-ABS/namespace folder /work does not select hostless work/a", suDS3, sel{ns: []string{"/work"}}, []string{"A1"}},
		{"HNR-ABS/namespace folder /work/a does not select hostless work/a", suDS3, sel{ns: []string{"/work/a"}}, []string{"A1"}},
		{"HNR-ABS/repo drive form does not select hostless work/a", suDS3, sel{repos: []string{"C:/work/a"}}, []string{}},
		{"HNR-ABS/control repo host-qualified selects hostless work/a", suDS3, sel{repos: []string{"github.com/work/a"}}, []string{"H1"}},
		{"HNR-ABS/control namespace host-qualified selects hostless work/a", suDS3, sel{ns: []string{"github.com/work"}}, []string{"H1"}},
		// paths (INV-PATH)
		{"C-PATH-ABS-WT", suDS2, sel{paths: []string{"/work/a/api/config/app.env"}}, []string{"P2"}},
		{"C-PATH-DISPLAYED", suDS2, sel{paths: []string{"config/app.env"}}, []string{"P1", "P2"}},
		{"C-PATH-IDENTICAL-FOLDERS", suDS2, sel{paths: []string{"/work/x/secrets.txt"}}, []string{"P3"}},
		{"S-T003/path matches whole value only", suDS2, sel{paths: []string{"secrets"}}, []string{}},
		{"S-T003/namespace folder sibling P5 is not a segment prefix", suDS2, sel{ns: []string{"/work/a"}}, []string{"P2"}},
		{"S-T003/namespace folder that equals the folder", suDS2, sel{ns: []string{"/work/ab"}}, []string{"P5"}},
		// no selector selects everything
		{"C-UNFILTERED/no selector selects all", suDS1, sel{}, []string{"L1", "L10", "L11", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := newReportSelector(tc.sel.repos, tc.sel.ns, tc.sel.paths)
			require.NoError(t, err)
			assert.Equal(t, suWant(tc.want), suSelected(t, s, tc.set()))
		})
	}

	// S-T005: a selector value is compared literally. LIKE wildcards, shell
	// globs, regexp syntax, quotes, "..", and backslashes are ordinary
	// characters, so they select a record only by exact (or whole-segment)
	// equality.
	t.Run("S-T005", func(t *testing.T) {
		set := map[string]types.Occurrence{
			"under":  suRemote("github.com", "acme/ap_i", "a_b.txt"),
			"other":  suRemote("github.com", "acme/apxi", "axb.txt"),
			"pct":    suRemote("github.com", "acme/100%", "p%.txt"),
			"plain":  suRemote("github.com", "acme/1000", "p1.txt"),
			"quote":  suRemote("github.com", "acme/it's", "it's.txt"),
			"star":   suRemote("github.com", "acme/st*r", "s*.txt"),
			"stars":  suRemote("github.com", "acme/starr", "sa.txt"),
			"dots":   suRemote("github.com", "acme/dots", "../up.txt"),
			"back":   suRemote("github.com", "acme/back\\slash", "b\\s.txt"),
			"slash":  suRemote("github.com", "acme/back", "bs.txt"),
			"regexp": suRemote("github.com", "acme/a.c", "a.c"),
			"rx2":    suRemote("github.com", "acme/abc", "abc"),
		}
		tests := []struct {
			name string
			sel  sel
			want []string
		}{
			{"underscore is literal", sel{repos: []string{"github.com/acme/ap_i"}}, []string{"under"}},
			{"underscore is not a one-char wildcard (namespace)", sel{ns: []string{"github.com/acme/ap_"}}, []string{}},
			{"percent is literal", sel{repos: []string{"github.com/acme/100%"}}, []string{"pct"}},
			{"percent is not a wildcard", sel{repos: []string{"github.com/acme/%"}}, []string{}},
			{"percent namespace is not a wildcard", sel{ns: []string{"github.com/acme/10%"}}, []string{}},
			{"single quote is literal", sel{repos: []string{"github.com/acme/it's"}}, []string{"quote"}},
			{"single quote does not break out", sel{repos: []string{"x' OR '1'='1"}}, []string{}},
			{"star is literal", sel{repos: []string{"github.com/acme/st*r"}}, []string{"star"}},
			{"star is not a glob", sel{repos: []string{"github.com/acme/*"}}, []string{}},
			{"star path is literal", sel{paths: []string{"s*.txt"}}, []string{"star"}},
			{"bare star path selects nothing", sel{paths: []string{"*"}}, []string{}},
			{"dotdot repo selects nothing", sel{repos: []string{".."}}, []string{}},
			{"dotdot path is literal", sel{paths: []string{"../up.txt"}}, []string{"dots"}},
			{"dotdot path does not resolve", sel{paths: []string{"up.txt"}}, []string{}},
			{"backslash is literal", sel{repos: []string{"github.com/acme/back\\slash"}}, []string{"back"}},
			{"backslash is not a separator", sel{repos: []string{"github.com\\acme\\back"}}, []string{}},
			{"regexp dot is literal", sel{repos: []string{"github.com/acme/a.c"}}, []string{"regexp"}},
			{"regexp dot is not any-char", sel{repos: []string{"github.com/acme/a.*"}}, []string{}},
			{"regexp anchors are literal", sel{repos: []string{"^github.com/acme/abc$"}}, []string{}},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				s, err := newReportSelector(tc.sel.repos, tc.sel.ns, tc.sel.paths)
				require.NoError(t, err)
				assert.Equal(t, suWant(tc.want), suSelected(t, s, set))
			})
		}
	})
}

// TestOccurrenceForms is the regression for the comparable repository forms
// (R17 item 5): the displayed repository, the repository without its recorded
// host, and the absolute folder, each present only when it was recorded.
//
// It fails if a host were synthesized for a record that has none, if the
// host-less form were produced when no host was recorded, or if the folder
// were derived for a committed location of a remote-identified repository
// (whose scan root is not recorded in the location).
func TestOccurrenceForms(t *testing.T) {
	tests := []struct {
		name string
		occ  types.Occurrence
		want []string
	}{
		{"host recorded committed", suRemote("github.com", "acme/api", "x"), []string{"github.com/acme/api", "acme/api"}},
		{"host recorded working tree adds folder", suRemoteWT("github.com", "acme/api", "/work/a/api", "config/app.env"),
			[]string{"github.com/acme/api", "acme/api", "/work/a/api"}},
		{"self-hosted host", suRemote("gitlab.example.com", "acme/team/api", "x"), []string{"gitlab.example.com/acme/team/api", "acme/team/api"}},
		{"host not recorded keeps the stored value only", suHNR("acme/api", "x"), []string{"acme/api"}},
		{"host not recorded with a host-looking first segment is not split", suHNR("github.com/acme/api", "x"), []string{"github.com/acme/api"}},
		{"local repository has folder and no host form", suLocal("api/", "/work/api", "k.txt"), []string{"api/", "/work/api"}},
		{"local repository nested path trims the whole relative path", suLocal("tool", "/work/t", "lib/k.go"), []string{"tool", "/work/t"}},
		{"file location has no repository forms", suFile("notes.txt"), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, occurrenceForms(tc.occ))
		})
	}

	t.Run("folder is independent of host recording", func(t *testing.T) {
		recorded := suRemoteWT("github.com", "acme/api", "/work/a/api", "config/app.env")
		assert.True(t, recorded.HostRecorded)
		assert.Equal(t, "/work/a/api", absoluteFolder(recorded))
		local := suLocal("r", "/work/r", "f.txt")
		assert.Equal(t, "/work/r", absoluteFolder(local))
	})
	t.Run("no folder without an absolute path or for non-git", func(t *testing.T) {
		assert.Empty(t, absoluteFolder(suRemote("github.com", "acme/api", "x")), "a committed remote location records no absolute path")
		assert.Empty(t, absoluteFolder(suFile("notes.txt")))
	})
}

// TestSelectorValues covers what `report sources` lists for one occurrence
// (R17 item 2, 3): every recorded repository form and its whole-segment
// namespaces, with segments that could not validate left out.
//
// It fails if the typed form "api/" yielded the invalid namespace "api/", if
// an empty-segment prefix were listed, if a host were synthesized for a
// record without one, or if folder ancestors were listed as namespaces.
func TestSelectorValues(t *testing.T) {
	tests := []struct {
		name      string
		occ       types.Occurrence
		wantRepos []string
		wantNS    []string
		wantPaths []string
	}{
		{
			name:      "S-T009/typed trailing slash",
			occ:       suLocal("api/", "/work/api", "k.txt"),
			wantRepos: []string{"api/", "/work/api"},
			wantNS:    []string{"api"},
			wantPaths: []string{"k.txt", "/work/api/k.txt"},
		},
		{
			name:      "S-T009/typed empty segment",
			occ:       suLocal("a//api", "/work/aa", "k.txt"),
			wantRepos: []string{"a//api", "/work/aa"},
			wantNS:    []string{"a"},
			wantPaths: []string{"k.txt", "/work/aa/k.txt"},
		},
		{
			name:      "S-T009/hosted repository lists both forms and every prefix",
			occ:       suRemote("github.com", "acme/api", "config/app.env"),
			wantRepos: []string{"github.com/acme/api", "acme/api"},
			wantNS:    []string{"github.com", "github.com/acme", "acme"},
			wantPaths: []string{"config/app.env"},
		},
		{
			name:      "S-T009/hosted working tree lists the folder as a repository only",
			occ:       suRemoteWT("github.com", "acme/api", "/work/a/api", "config/app.env"),
			wantRepos: []string{"github.com/acme/api", "acme/api", "/work/a/api"},
			wantNS:    []string{"github.com", "github.com/acme", "acme"},
			wantPaths: []string{"config/app.env", "/work/a/api/config/app.env"},
		},
		{
			name:      "S-T009/host not recorded lists the stored value and no host",
			occ:       suHNR("acme/team/api", "h.txt"),
			wantRepos: []string{"acme/team/api"},
			wantNS:    []string{"acme", "acme/team"},
			wantPaths: []string{"h.txt"},
		},
		{
			name:      "S-T009/host not recorded single segment has no namespace",
			occ:       suHNR("api", "h.txt"),
			wantRepos: []string{"api"},
			wantNS:    nil,
			wantPaths: []string{"h.txt"},
		},
		{
			name:      "S-T009/legacy URL path",
			occ:       suHNR("https://x/acme/api.git", "h.txt"),
			wantRepos: []string{"https://x/acme/api.git"},
			wantNS:    []string{"https:"},
			wantPaths: []string{"h.txt"},
		},
		{
			name:      "S-T009/file location lists a path only",
			occ:       suFile("notes.txt"),
			wantRepos: nil,
			wantNS:    nil,
			wantPaths: []string{"notes.txt", suFile("notes.txt").AbsolutePath},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repos, ns, paths := selectorValues(tc.occ)
			assert.Equal(t, tc.wantRepos, repos)
			assert.Equal(t, tc.wantNS, ns)
			assert.Equal(t, tc.wantPaths, paths)
		})
	}

	t.Run("S-T009/no duplicates when path equals absolute path", func(t *testing.T) {
		o := suLocal("r", "/work/r", "f.txt")
		_, _, paths := selectorValues(o)
		seen := map[string]bool{}
		for _, p := range paths {
			assert.False(t, seen[p], "duplicate %q", p)
			seen[p] = true
		}
	})
}

// TestSelectorValues_EveryListedValueValidatesAndSelects is the round-trip
// property of R17 item 3: a value that `report sources` lists must be accepted
// by the flag it is listed for and must select the occurrence it came from.
// A listing the selector rejects or cannot match is a dead end for the user.
//
// It fails if any generated value is rejected by validation or selects
// nothing, for the typed, empty-segment, hosted, legacy URL, folder and
// host-not-recorded fixtures.
func TestSelectorValues_EveryListedValueValidatesAndSelects(t *testing.T) {
	fixtures := map[string]types.Occurrence{
		"typed trailing slash":    suLocal("api/", "/work/api", "k.txt"),
		"typed empty segment":     suLocal("a//api", "/work/aa", "k.txt"),
		"hosted":                  suRemote("github.com", "acme/api", "config/app.env"),
		"hosted self-hosted":      suRemote("gitlab.example.com", "acme/team/sub/api", "b.txt"),
		"hosted working tree":     suRemoteWT("github.com", "acme/api", "/work/a/api", "config/app.env"),
		"legacy URL path":         suHNR("https://x/acme/api.git", "h.txt"),
		"host not recorded":       suHNR("acme/team/api", "h.txt"),
		"host not recorded short": suHNR("api", "h.txt"),
		"local folder":            suLocal("tool", "/work/t", "lib/k.go"),
		"file":                    suFile("notes.txt"),
	}
	for name, o := range fixtures {
		t.Run("S-T009/"+name, func(t *testing.T) {
			repos, ns, paths := selectorValues(o)
			require.NotEmpty(t, append(append(append([]string{}, repos...), ns...), paths...), "a source must list at least one value")
			for _, v := range repos {
				sel, err := newReportSelector([]string{v}, nil, nil)
				require.NoError(t, err, "--repo %q", v)
				assert.True(t, sel.selects(o), "--repo %q must select its own source", v)
			}
			for _, v := range ns {
				sel, err := newReportSelector(nil, []string{v}, nil)
				require.NoError(t, err, "--namespace %q", v)
				assert.True(t, sel.selects(o), "--namespace %q must select its own source", v)
			}
			for _, v := range paths {
				sel, err := newReportSelector(nil, nil, []string{v})
				require.NoError(t, err, "--path %q", v)
				assert.True(t, sel.selects(o), "--path %q must select its own source", v)
			}
		})
	}
}

// suStores runs a test against every Store implementation, as the occurrence
// suite in pkg/store does.
//
// open returns the store and its datastore path. The memory store is never
// persisted, so it has no path and cannot hold a legacy row (a NULL
// provenance.host); a test that needs one runs for SQLite only.
var suStores = []struct {
	name string
	open func(t *testing.T) (store.Store, string)
}{
	{"sqlite", func(t *testing.T) (store.Store, string) {
		path := filepath.Join(t.TempDir(), "ds.db")
		s, err := store.New(store.Config{Path: path})
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })
		return s, path
	}},
	{"memory", func(t *testing.T) (store.Store, string) { return store.NewMemory(), "" }},
}

// suAddRecorded records a location the way a scan does: a provenance row and
// the location rows derived from it.
func suAddRecorded(t *testing.T, s store.Store, blob types.BlobID, p types.GitProvenance) {
	t.Helper()
	require.NoError(t, s.AddProvenance(blob, p))
	require.NoError(t, s.AddOccurrences(blob, types.OccurrencesOf(p)))
}

// suAddHNR records a location the way a datastore written before the host was
// recorded holds it: a provenance row whose host is NULL, with no location
// row. A fresh AddProvenance writes an empty string (a recorded empty host), and the
// migration that added provenance.host leaves old rows NULL, so the row is
// written and then reset to the migrated shape. dbPath is the SQLite
// datastore file; the memory store cannot hold such a row.
func suAddHNR(t *testing.T, s store.Store, dbPath string, blob types.BlobID, repo, path string) {
	t.Helper()
	require.NotEmpty(t, dbPath, "only a SQLite datastore can hold a host-not-recorded row")
	require.NoError(t, s.AddProvenance(blob, types.GitProvenance{RepoPath: repo, BlobPath: path, Commit: suCommit(3)}))
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	res, err := db.Exec(`UPDATE provenance SET host = NULL WHERE blob_id = ? AND repo_path = ? AND path = ?`, blob.Hex(), repo, path)
	require.NoError(t, err)
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "the provenance row to legacy-ify exists")
}

func suRemoteProv(host, repo, path string, n int) types.GitProvenance {
	return types.GitProvenance{
		RepoPath: host + "/" + repo, Host: host, RemoteIdentity: true,
		BlobPath: path, Commit: suCommit(n),
	}
}

func suLocationKeys(occs []types.Occurrence) []string {
	keys := make([]string, 0, len(occs))
	for _, o := range occs {
		keys = append(keys, o.Repository+" "+o.Path)
	}
	return keys
}

// TestSelectingStore_GetOccurrencesPrunesPerLocation is S-T011 and the
// INV-PERLOC unit: the wrapped store narrows one blob's locations to the
// selected ones, not the blob to an all-or-nothing keep. The blob is recorded
// at github.com/acme/api first and github.com/other/api second, so a store
// that kept the first-stored location (or the whole blob) would show L1 for a
// selection of L2.
//
// It fails if GetOccurrences returned the raw list, if it kept the first
// location instead of the selected one, if pruning mutated the underlying
// store, or if the cache were keyed so a second blob saw the first blob's
// locations.
func TestSelectingStore_GetOccurrencesPrunesPerLocation(t *testing.T) {
	for _, f := range suStores {
		t.Run(f.name, func(t *testing.T) {
			s, dbPath := f.open(t)
			legacy := dbPath != "" // only SQLite can hold a host-not-recorded row
			b1 := types.ComputeBlobID([]byte("shared"))
			b2 := types.ComputeBlobID([]byte("only-other"))
			require.NoError(t, s.AddBlob(b1, 6))
			require.NoError(t, s.AddBlob(b2, 10))
			suAddRecorded(t, s, b1, suRemoteProv("github.com", "acme/api", "config/app.env", 1))
			suAddRecorded(t, s, b1, suRemoteProv("github.com", "other/api", "settings/app.env", 2))
			wantRaw := 2
			if legacy {
				suAddHNR(t, s, dbPath, b1, "legacy/api", "h.txt")
				wantRaw = 3
			}
			suAddRecorded(t, s, b2, suRemoteProv("github.com", "other/api", "x.txt", 3))

			raw1, err := s.GetOccurrences(b1)
			require.NoError(t, err)
			require.Len(t, raw1, wantRaw, "precondition: the locations stored for the blob")

			t.Run("S-T011/second-stored location only", func(t *testing.T) {
				sel, err := newReportSelector([]string{"github.com/other/api"}, nil, nil)
				require.NoError(t, err)
				ss := &selectingStore{Store: s, sel: sel, cache: map[types.BlobID]selectedBlob{}}

				got, err := ss.GetOccurrences(b1)
				require.NoError(t, err)
				assert.Equal(t, []string{"github.com/other/api settings/app.env"}, suLocationKeys(got))

				got2, err := ss.GetOccurrences(b2)
				require.NoError(t, err)
				assert.Equal(t, []string{"github.com/other/api x.txt"}, suLocationKeys(got2), "a second blob must not see the first blob's cached locations")
			})
			t.Run("S-T011/first-stored location only", func(t *testing.T) {
				sel, err := newReportSelector([]string{"github.com/acme/api"}, nil, nil)
				require.NoError(t, err)
				ss := &selectingStore{Store: s, sel: sel, cache: map[types.BlobID]selectedBlob{}}
				got, err := ss.GetOccurrences(b1)
				require.NoError(t, err)
				assert.Equal(t, []string{"github.com/acme/api config/app.env"}, suLocationKeys(got))
			})
			t.Run("S-T011/union across locations of one blob", func(t *testing.T) {
				sel, err := newReportSelector([]string{"github.com/acme/api"}, nil, []string{"settings/app.env"})
				require.NoError(t, err)
				ss := &selectingStore{Store: s, sel: sel, cache: map[types.BlobID]selectedBlob{}}
				got, err := ss.GetOccurrences(b1)
				require.NoError(t, err)
				assert.Equal(t, []string{"github.com/acme/api config/app.env", "github.com/other/api settings/app.env"}, suLocationKeys(got))
			})
			t.Run("S-T011/no selected location leaves none", func(t *testing.T) {
				sel, err := newReportSelector([]string{"nobody/nothing"}, nil, nil)
				require.NoError(t, err)
				ss := &selectingStore{Store: s, sel: sel, cache: map[types.BlobID]selectedBlob{}}
				got, err := ss.GetOccurrences(b1)
				require.NoError(t, err)
				assert.Empty(t, got)
			})
			t.Run("S-T011/host-not-recorded location keeps its marker", func(t *testing.T) {
				if !legacy {
					t.Skip("the memory store is never persisted, so it cannot hold a host-not-recorded row")
				}
				sel, err := newReportSelector([]string{"github.com/legacy/api"}, nil, nil)
				require.NoError(t, err)
				ss := &selectingStore{Store: s, sel: sel, cache: map[types.BlobID]selectedBlob{}}
				got, err := ss.GetOccurrences(b1)
				require.NoError(t, err)
				require.Len(t, got, 1)
				assert.Equal(t, "legacy/api", got[0].Repository, "the stored value is kept, no host is invented")
				assert.False(t, got[0].HostRecorded)
			})
			t.Run("S-T011/underlying store is not narrowed", func(t *testing.T) {
				again, err := s.GetOccurrences(b1)
				require.NoError(t, err)
				assert.Equal(t, raw1, again)
			})
		})
	}
}

// TestApplySelection_RetainsAndCounts is the unit for the findings and
// matches a selection keeps and the host-not-recorded count behind the notice
// (S-T007): a match is retained when at least one of its blob's locations is
// selected, a finding when it keeps a match, and the unselected host-less
// locations are counted once per blob however many matches the blob has.
//
// It fails if findings were kept with their locations emptied (C-ABSENT), if
// the count were per match instead of per blob (B3 has two matches), if
// selected host-less locations were counted, or if an inactive selector did
// not return its inputs untouched (C-UNFILTERED).
func TestApplySelection_RetainsAndCounts(t *testing.T) {
	r := &types.Rule{ID: "np.test.1", Name: "Test Rule", Pattern: "tok_.*"}
	r.StructuralID = r.ComputeStructuralID()
	ruleMap := map[string]*types.Rule{r.ID: r}

	mkFinding := func(secret string) (*types.Finding, [][]byte) {
		g := [][]byte{[]byte(secret)}
		return &types.Finding{ID: types.ComputeFindingID(r.StructuralID, g), RuleID: r.ID, Groups: g}, g
	}
	mkMatch := func(id string, blob types.BlobID, g [][]byte) *types.Match {
		return &types.Match{StructuralID: id, RuleID: r.ID, BlobID: blob, Groups: g}
	}

	for _, f := range suStores {
		t.Run(f.name, func(t *testing.T) {
			s, dbPath := f.open(t)
			legacy := dbPath != "" // only SQLite can hold a host-not-recorded row
			b1 := types.ComputeBlobID([]byte("b1"))
			b2 := types.ComputeBlobID([]byte("b2"))
			b3 := types.ComputeBlobID([]byte("b3"))
			for _, b := range []types.BlobID{b1, b2, b3} {
				require.NoError(t, s.AddBlob(b, 2))
			}
			// B1: acme/api and other/api. B2: gitlab acme/api. B3: two
			// host-less locations only.
			suAddRecorded(t, s, b1, suRemoteProv("github.com", "acme/api", "config/app.env", 1))
			suAddRecorded(t, s, b1, suRemoteProv("github.com", "other/api", "settings/app.env", 2))
			suAddRecorded(t, s, b2, suRemoteProv("gitlab.example.com", "acme/api", "deploy.yml", 3))
			// The memory store cannot hold host-less rows, so B3 has no
			// locations there and nothing is counted.
			unselectedHNR := 0
			if legacy {
				suAddHNR(t, s, dbPath, b3, "legacy/api", "h1.txt")
				suAddHNR(t, s, dbPath, b3, "legacy/api", "h2.txt")
				unselectedHNR = 2
			}
			skipWithoutLegacy := func(t *testing.T) {
				t.Helper()
				if !legacy {
					t.Skip("the memory store is never persisted, so it cannot hold a host-not-recorded row")
				}
			}

			f1, g1 := mkFinding("tok_one")
			f2, g2 := mkFinding("tok_two")
			f3, g3 := mkFinding("tok_three")
			f4, g4 := mkFinding("tok_four")
			findings := []*types.Finding{f1, f2, f3, f4}
			m1 := mkMatch("m1", b1, g1)
			m2 := mkMatch("m2", b2, g2)
			m3 := mkMatch("m3", b3, g3)
			m4 := mkMatch("m4", b3, g4) // second match on the same host-less blob
			matches := []*types.Match{m1, m2, m3, m4}

			ids := func(fs []*types.Finding) []string {
				var out []string
				for _, x := range fs {
					out = append(out, x.ID)
				}
				return out
			}
			sids := func(ms []*types.Match) []string {
				var out []string
				for _, x := range ms {
					out = append(out, x.StructuralID)
				}
				return out
			}

			t.Run("C-UNFILTERED/inactive selector returns its inputs", func(t *testing.T) {
				sel, err := newReportSelector(nil, nil, nil)
				require.NoError(t, err)
				gotS, gotF, gotM, n, err := applySelection(s, sel, findings, matches, ruleMap)
				require.NoError(t, err)
				assert.True(t, gotS == s, "the writers must keep the original store when nothing is selected")
				assert.Equal(t, ids(findings), ids(gotF))
				assert.Equal(t, sids(matches), sids(gotM))
				assert.Zero(t, n)
			})

			t.Run("C-ABSENT/repo selects the second location of B1", func(t *testing.T) {
				sel, err := newReportSelector([]string{"github.com/other/api"}, nil, nil)
				require.NoError(t, err)
				gotS, gotF, gotM, n, err := applySelection(s, sel, findings, matches, ruleMap)
				require.NoError(t, err)
				assert.Equal(t, []string{f1.ID}, ids(gotF))
				assert.Equal(t, []string{"m1"}, sids(gotM))
				assert.Equal(t, unselectedHNR, n, "B3's host-less locations (SQLite only) are unselected")
				occs, err := gotS.GetOccurrences(b1)
				require.NoError(t, err)
				assert.Equal(t, []string{"github.com/other/api settings/app.env"}, suLocationKeys(occs))
			})

			t.Run("S-T007/host-less count is per blob, not per match", func(t *testing.T) {
				skipWithoutLegacy(t)
				sel, err := newReportSelector([]string{"github.com/acme/api"}, nil, nil)
				require.NoError(t, err)
				_, gotF, gotM, n, err := applySelection(s, sel, findings, matches, ruleMap)
				require.NoError(t, err)
				assert.Equal(t, []string{f1.ID}, ids(gotF))
				assert.Equal(t, []string{"m1"}, sids(gotM))
				assert.Equal(t, 2, n, "two host-less locations on B3, which has two matches: counted once per location, not four")
			})

			t.Run("S-T007/selected host-less locations are not counted", func(t *testing.T) {
				skipWithoutLegacy(t)
				sel, err := newReportSelector([]string{"legacy/api"}, nil, nil)
				require.NoError(t, err)
				_, gotF, gotM, n, err := applySelection(s, sel, findings, matches, ruleMap)
				require.NoError(t, err)
				assert.ElementsMatch(t, []string{f3.ID, f4.ID}, ids(gotF))
				assert.ElementsMatch(t, []string{"m3", "m4"}, sids(gotM))
				assert.Zero(t, n)
			})

			t.Run("S-T007/namespace selection counts the unselected host-less locations", func(t *testing.T) {
				skipWithoutLegacy(t)
				sel, err := newReportSelector(nil, []string{"github.com"}, nil)
				require.NoError(t, err)
				_, gotF, _, n, err := applySelection(s, sel, findings, matches, ruleMap)
				require.NoError(t, err)
				assert.Equal(t, []string{f1.ID}, ids(gotF))
				assert.Equal(t, 2, n)
			})

			t.Run("C-NOMATCH/nothing selected keeps no finding", func(t *testing.T) {
				sel, err := newReportSelector([]string{"nobody/nothing"}, nil, nil)
				require.NoError(t, err)
				_, gotF, gotM, n, err := applySelection(s, sel, findings, matches, ruleMap)
				require.NoError(t, err)
				assert.Empty(t, gotF)
				assert.Empty(t, gotM)
				assert.Equal(t, unselectedHNR, n)
			})

			t.Run("C-UNION-MIXED/path selector retains by location", func(t *testing.T) {
				sel, err := newReportSelector(nil, nil, []string{"deploy.yml"})
				require.NoError(t, err)
				_, gotF, gotM, _, err := applySelection(s, sel, findings, matches, ruleMap)
				require.NoError(t, err)
				assert.Equal(t, []string{f2.ID}, ids(gotF))
				assert.Equal(t, []string{"m2"}, sids(gotM))
			})
		})
	}

	t.Run("a blob that cannot be read fails the selection", func(t *testing.T) {
		s := store.NewMemory()
		sel, err := newReportSelector([]string{"a/b"}, nil, nil)
		require.NoError(t, err)
		f, g := mkFinding("tok_x")
		// A closed SQLite store errors on read; the error must surface, not
		// degrade to an unfiltered or empty report.
		db, err := store.New(store.Config{Path: filepath.Join(t.TempDir(), "closed.db")})
		require.NoError(t, err)
		require.NoError(t, db.Close())
		_, _, _, _, err = applySelection(db, sel, []*types.Finding{f}, []*types.Match{mkMatch("m", types.ComputeBlobID([]byte("x")), g)}, ruleMap)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reading locations of blob")
		_ = s
	})
}

// TestSelectionNotices covers the notice text, order and routing (S-T007,
// S-T013). Notices are constant text plus an integer, so they carry no
// control byte, and they reach stdout only for a human report.
//
// It fails if the host-less notice were emitted for a --path selector
// (C-HNR-NOTICE-PATHONLY), if the order of the two notices swapped, if the
// empty-selection notice were dropped for a path selection, or if a JSON or
// SARIF report received a notice on stdout (C-HNR-NOTICE-JSON,
// C-NOMATCH-JSON, C-NOMATCH-SARIF).
func TestSelectionNotices(t *testing.T) {
	const hnr3 = "Note: 3 location(s) recorded without a host were not selected. Run 'titus report sources' to list them."
	const empty = "No findings matched the selection. Run 'titus report sources' to list the available sources."

	mk := func(repos, ns, paths []string) *reportSelector {
		sel, err := newReportSelector(repos, ns, paths)
		require.NoError(t, err)
		return sel
	}
	tests := []struct {
		name     string
		sel      *reportSelector
		hnr      int
		retained int
		want     []string
	}{
		{"C-UNFILTERED/nil selector", nil, 5, 0, nil},
		{"C-UNFILTERED/inactive selector", mk(nil, nil, nil), 5, 0, nil},
		{"C-HNR-NOTICE-JSON/repo selected with unselected host-less", mk([]string{"github.com/acme/api"}, nil, nil), 3, 2, []string{hnr3}},
		{"C-HNR-NOTICE-SARIF/namespace selected with unselected host-less", mk(nil, []string{"acme/team"}, nil), 3, 1, []string{hnr3}},
		{"C-HNR-NOTICE-PATHONLY/path alone never emits the host-less notice", mk(nil, nil, []string{"a.txt"}), 3, 1, nil},
		{"C-HNR-NOTICE/no unselected host-less location", mk([]string{"acme/api"}, nil, nil), 0, 1, nil},
		{"C-NOMATCH/empty selection", mk([]string{"nobody/nothing"}, nil, nil), 0, 0, []string{empty}},
		{"C-NOMATCH/empty path selection", mk(nil, nil, []string{"no/such/file"}), 3, 0, []string{empty}},
		{"S-T007/both notices in order", mk([]string{"nobody/nothing"}, nil, nil), 3, 0, []string{hnr3, empty}},
		{"S-T007/count is rendered", mk(nil, []string{"x"}, nil), 1, 4, []string{"Note: 1 location(s) recorded without a host were not selected. Run 'titus report sources' to list them."}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, selectionNotices(tc.sel, tc.hnr, tc.retained))
		})
	}

	t.Run("S-T013/routing", func(t *testing.T) {
		notices := []string{hnr3, empty}
		for _, human := range []bool{true, false} {
			name := "json and sarif use stderr"
			if human {
				name = "human uses stdout"
			}
			t.Run(name, func(t *testing.T) {
				var out, errb bytes.Buffer
				cmd := &cobra.Command{}
				cmd.SetOut(&out)
				cmd.SetErr(&errb)

				writeSelectionNotices(cmd, human, notices)

				want := hnr3 + "\n" + empty + "\n"
				if human {
					assert.Equal(t, want, out.String())
					assert.Empty(t, errb.String())
				} else {
					assert.Equal(t, want, errb.String())
					assert.Empty(t, out.String(), "stdout holds only the document for JSON and SARIF")
				}
			})
		}
	})

	t.Run("S-T013/no control bytes", func(t *testing.T) {
		for _, n := range []string{hnr3, empty} {
			for _, b := range []byte(n) {
				assert.False(t, b < 0x20 || b == 0x7f, "control byte %#x in %q", b, n)
			}
		}
		var out bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		writeSelectionNotices(cmd, true, []string{"x\x1b[31m\xe2\x80\xaeevil"})
		assert.NotContains(t, out.String(), "\x1b", "a human notice is sanitized for the terminal")
		assert.NotContains(t, out.String(), "\xe2\x80\xae")
	})

	t.Run("no notices writes nothing", func(t *testing.T) {
		var out, errb bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		cmd.SetErr(&errb)
		writeSelectionNotices(cmd, true, nil)
		assert.Empty(t, out.String())
		assert.Empty(t, errb.String())
	})
}
