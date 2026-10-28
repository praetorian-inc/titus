package main

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Command-level tests of `titus report sources` and `titus report sources
// all`, run in process against datastores seeded through the store API.

type srcDoc struct {
	Scope string `json:"scope"`
	Repos []struct {
		Value        string `json:"value"`
		Kind         string `json:"kind"`
		Host         string `json:"host"`
		HostRecorded bool   `json:"host_recorded"`
	} `json:"repos"`
	Namespaces []struct {
		Value        string `json:"value"`
		HostRecorded bool   `json:"host_recorded"`
	} `json:"namespaces"`
	Paths []struct {
		Value    string `json:"value"`
		Absolute bool   `json:"absolute"`
	} `json:"paths"`
	Unselectable []struct {
		Kind   string `json:"kind"`
		Reason string `json:"reason"`
	} `json:"unselectable"`
}

func (d srcDoc) repoValues() []string {
	var out []string
	for _, r := range d.Repos {
		out = append(out, r.Value)
	}
	return out
}

func (d srcDoc) namespaceValues() []string {
	var out []string
	for _, n := range d.Namespaces {
		out = append(out, n.Value)
	}
	return out
}

func (d srcDoc) pathValues() []string {
	var out []string
	for _, p := range d.Paths {
		out = append(out, p.Value)
	}
	return out
}

// srcRun runs a sources command with --format json and decodes it.
func srcRun(t *testing.T, ds string, all bool, flags ...string) (srcDoc, cliResult) {
	t.Helper()
	sub := []string{"sources"}
	if all {
		sub = append(sub, "all")
	}
	r := runRootSplit(t, reportCmdArgs(ds, sub, append([]string{"--format", "json"}, flags...)...)...)
	require.NoError(t, r.err, "stderr: %s", r.stderr)
	require.True(t, jsonValid(r.stdout), "stdout: %s", r.stdout)
	var d srcDoc
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &d))
	return d, r
}

// C-SOURCES-VALUES: every listed value selects at least one finding.
func TestReportSources_ValuesSelectFindings(t *testing.T) {
	ds := seedDS1(t)
	d, _ := srcRun(t, ds, false)
	assert.Equal(t, "findings", d.Scope)

	wantRepos := []string{
		"github.com/acme/api", "github.com/other/api", "gitlab.example.com/acme/api",
		"github.com/acme/team/api", "gitlab.example.com/acme/team/sub/api",
		"gitlab.example.com/acme/team-other/api", "github.com/acmecorp/api",
	}
	for _, w := range wantRepos {
		assert.Contains(t, d.repoValues(), w)
	}

	for _, v := range d.repoValues() {
		r := runRootSplit(t, reportCmdArgs(ds, nil, "--format", "json", "--repo", v)...)
		require.NoError(t, r.err)
		assert.NotEmpty(t, selDecodeFindings(t, r.stdout), "--repo %q selects", v)
	}
	for _, v := range d.namespaceValues() {
		r := runRootSplit(t, reportCmdArgs(ds, nil, "--format", "json", "--namespace", v)...)
		require.NoError(t, r.err)
		assert.NotEmpty(t, selDecodeFindings(t, r.stdout), "--namespace %q selects", v)
	}
	for _, v := range d.pathValues() {
		r := runRootSplit(t, reportCmdArgs(ds, nil, "--format", "json", "--path", v)...)
		require.NoError(t, r.err)
		assert.NotEmpty(t, selDecodeFindings(t, r.stdout), "--path %q selects", v)
	}

	// No duplicated entry, and no nil list in an empty document.
	seen := map[string]bool{}
	for _, r := range d.Repos {
		key := strings.Join([]string{r.Value, r.Kind, r.Host, map[bool]string{true: "T", false: "F"}[r.HostRecorded]}, "|")
		assert.False(t, seen[key], "duplicate repo entry %s", key)
		seen[key] = true
	}
	assert.True(t, slices.IsSorted(d.repoValues()), "repos are sorted")
}

// C-SOURCES-DETERMINISTIC.
func TestReportSources_Deterministic(t *testing.T) {
	ds := seedDS1(t)
	var first string
	for i := 0; i < 5; i++ {
		_, r := srcRun(t, ds, false)
		if i == 0 {
			first = r.stdout
			continue
		}
		assert.Equal(t, first, r.stdout, "run %d", i)
	}
	h1 := runRootSplit(t, reportCmdArgs(ds, []string{"sources"})...)
	h2 := runRootSplit(t, reportCmdArgs(ds, []string{"sources"})...)
	assert.Equal(t, h1.stdout, h2.stdout)
}

// C-SOURCES-REJECTED: sources follows the findings scope of `report`.
func TestReportSources_RejectedSetting(t *testing.T) {
	ds := seedDS1(t, "B5") // F5 is only at L6
	const l6 = "gitlab.example.com/acme/team-other/api"

	d, _ := srcRun(t, ds, false)
	assert.NotContains(t, d.repoValues(), l6)

	d, _ = srcRun(t, ds, false, "--show-rejected")
	assert.Contains(t, d.repoValues(), l6)
}

// C-SOURCES-HNR and S-T004: host-less values are labeled, never given a host.
func TestReportSources_HostNotRecorded(t *testing.T) {
	ds := seedDS1(t)
	d, _ := srcRun(t, ds, false)

	hnr := map[string]bool{}
	for _, r := range d.Repos {
		if !r.HostRecorded {
			hnr[r.Value] = true
			assert.Empty(t, r.Host, "no host is invented for %q", r.Value)
		}
	}
	assert.Equal(t, map[string]bool{"acme/api": true, "api": true, "team/api": true, "zzz/unrelated": true}, hnr)

	human := runRootSplit(t, reportCmdArgs(ds, []string{"sources"})...)
	require.NoError(t, human.err)
	for _, v := range []string{"acme/api", "api", "team/api", "zzz/unrelated"} {
		found := false
		for _, line := range strings.Split(human.stdout, "\n") {
			if strings.TrimSpace(line) == v+"  (host not recorded)" {
				found = true
			}
		}
		assert.True(t, found, "%q is marked host not recorded in:\n%s", v, human.stdout)
	}
}

// C-SOURCES-DUP-LOCAL: the committed and working-tree copies of a repository
// list the remote once, and each local folder is listed.
func TestReportSources_DuplicateLocalRepos(t *testing.T) {
	ds, roots := seedDS2(t)
	d, _ := srcRun(t, ds, false)

	count := 0
	for _, v := range d.repoValues() {
		if v == "github.com/acme/api" {
			count++
		}
	}
	assert.Equal(t, 1, count, "github.com/acme/api once: %v", d.repoValues())
	assert.Contains(t, d.repoValues(), roots.a)
	assert.Contains(t, d.repoValues(), roots.b)
}

// C-SOURCES-PATHS.
func TestReportSources_Paths(t *testing.T) {
	ds, roots := seedDS2(t)
	d, _ := srcRun(t, ds, false)
	for _, want := range []string{
		"config/app.env", filepath.Join(roots.a, "config", "app.env"),
		"secrets.txt", filepath.Join(roots.x, "secrets.txt"), filepath.Join(roots.y, "secrets.txt"),
		"lib/key.go",
	} {
		assert.Contains(t, d.pathValues(), want)
	}
	for _, p := range d.Paths {
		assert.Equal(t, filepath.IsAbs(p.Value), p.Absolute, "absolute flag of %q", p.Value)
	}
}

// A file recorded by its absolute path has Path == AbsolutePath: the one listed
// value is absolute. A relative file path is listed as relative and its
// resolved path as absolute.
func TestSourceSet_AbsoluteFlag(t *testing.T) {
	t.Run("path equal to absolute path is absolute", func(t *testing.T) {
		o := suFile("/abs/in/t/creds.txt")
		if o.Path != o.AbsolutePath {
			t.Skipf("filepath.Abs rewrites %q on this platform", o.Path)
		}
		ss := newSourceSet()
		ss.add(o)
		got := ss.result(sourcesScopeAll).Paths
		assert.Equal(t, []sourcePath{{Value: "/abs/in/t/creds.txt", Absolute: true}}, got)
	})
	t.Run("relative path is false and resolved path is true", func(t *testing.T) {
		o := suFile("notes.txt")
		ss := newSourceSet()
		ss.add(o)
		got := ss.result(sourcesScopeAll).Paths
		assert.ElementsMatch(t, []sourcePath{
			{Value: "notes.txt", Absolute: false},
			{Value: o.AbsolutePath, Absolute: true},
		}, got)
	})
}

// An archive member is a path, never a repository or namespace: `sources all`
// lists the member path, and that path selects the member's finding.
func TestReportSourcesAll_ArchiveMemberIsAPath(t *testing.T) {
	b := newDSBuilder(t)
	b.finding("ARC")
	b.addProv("ARC", types.ArchiveProvenance{ArchivePath: "a.zip", MemberPath: "t/creds.txt"})
	ds := b.done()

	d, _ := srcRun(t, ds, true)

	assert.NotContains(t, d.repoValues(), "t/creds.txt")
	assert.NotContains(t, d.repoValues(), "a.zip:t/creds.txt")
	assert.NotContains(t, d.namespaceValues(), "t")
	assert.Empty(t, d.Repos, "no archive-derived repository")
	assert.Empty(t, d.Namespaces, "no archive-derived namespace")
	require.Contains(t, d.pathValues(), "a.zip:t/creds.txt")

	r := runRootSplit(t, reportCmdArgs(ds, nil, "--format", "json", "--path", "a.zip:t/creds.txt")...)
	require.NoError(t, r.err, "stderr: %s", r.stderr)
	assert.Len(t, selDecodeFindings(t, r.stdout), 1, "the listed path selects the archive blob's finding")
}

// C-SOURCES-FORMATS and S-T004: human and JSON list the same values; sarif
// and unknown formats are rejected.
func TestReportSources_Formats(t *testing.T) {
	ds := seedDS1(t)
	d, _ := srcRun(t, ds, false)

	human := runRootSplit(t, reportCmdArgs(ds, []string{"sources"})...)
	require.NoError(t, human.err)
	assert.Empty(t, human.stderr)
	for _, h := range []string{"Repositories (--repo)", "Namespaces (--namespace)", "Paths (--path)"} {
		assert.Contains(t, human.stdout, h)
	}
	for _, v := range d.repoValues() {
		assert.Contains(t, human.stdout, "  "+v)
	}
	for _, v := range d.namespaceValues() {
		assert.Contains(t, human.stdout, "  "+v)
	}
	for _, v := range d.pathValues() {
		assert.Contains(t, human.stdout, "  "+v)
	}
	assert.NotContains(t, human.stdout, "github.com/acme/api  (host not recorded)")

	for _, tc := range []struct{ format, msg string }{
		{"sarif", "output format sarif is not supported by the sources commands: use human or json"},
		{"xml", "unknown output format: xml"},
	} {
		for _, all := range []bool{false, true} {
			sub := []string{"sources"}
			if all {
				sub = append(sub, "all")
			}
			r := runRootSplit(t, reportCmdArgs(ds, sub, "--format", tc.format)...)
			require.Error(t, r.err, tc.format)
			assert.Contains(t, r.stderr, tc.msg)
			assert.NotContains(t, r.stdout, "Repositories")
		}
	}
}

// C-ALL-NOFINDINGS.
func TestReportSourcesAll_ListsSourcesWithoutFindings(t *testing.T) {
	ds := seedDS3(t)
	all, _ := srcRun(t, ds, true)
	assert.Equal(t, "all", all.Scope)

	var clean bool
	for _, r := range all.Repos {
		if r.Value == "github.com/acme/clean" {
			clean = true
			assert.Equal(t, "git", r.Kind)
		}
	}
	assert.True(t, clean, "a repository without findings is listed by sources all")

	scoped, _ := srcRun(t, ds, false)
	assert.NotContains(t, scoped.repoValues(), "github.com/acme/clean")

	require.NotEmpty(t, all.Unselectable)
	assert.Equal(t, "no repository or path recorded", all.Unselectable[0].Reason)

	hnr := map[string]bool{}
	for _, r := range all.Repos {
		if !r.HostRecorded {
			hnr[r.Value] = true
		}
	}
	assert.Equal(t, map[string]bool{"acme/api": true, "api": true, "team/api": true, "zzz/unrelated": true}, hnr)

	human := runRootSplit(t, reportCmdArgs(ds, []string{"sources", "all"})...)
	require.NoError(t, human.err)
	assert.Contains(t, human.stdout, "Unselectable records")
	assert.Contains(t, human.stdout, "acme/api  (host not recorded)")
}

// C-ALL-NORECON: sources all lists exactly what the provenance recorded, with
// no host or repository reconstructed.
func TestReportSourcesAll_NoReconstruction(t *testing.T) {
	b := newDSBuilder(t)
	b.finding("N1")
	b.remoteLoc("N1", "github.com", "acme/api", "a.txt")
	b.finding("N2")
	b.hnrLoc("N2", "legacy/repo", "b.txt")
	ds := b.done()

	d, _ := srcRun(t, ds, true)
	// A recorded remote lists its displayed and host-less forms; the legacy
	// record lists its repository as stored and nothing host-qualified.
	assert.Equal(t, []string{"acme/api", "github.com/acme/api", "legacy/repo"}, d.repoValues())
	for _, v := range d.repoValues() {
		assert.NotContains(t, v, "/legacy/repo", "no host is reconstructed for the legacy record: %s", v)
	}
	assert.Equal(t, []string{"a.txt", "b.txt"}, d.pathValues())
	for _, r := range d.Repos {
		if r.Value == "legacy/repo" {
			assert.False(t, r.HostRecorded)
			assert.Empty(t, r.Host)
		}
	}
}

// S-T001: userinfo is redacted in every command, format and host state.
func TestReportSources_RedactsUserinfo(t *testing.T) {
	const raw = "https://user:TOKEN123@github.com/acme/api.git"
	for _, hostSet := range []bool{true, false} {
		b := newDSBuilder(t)
		b.finding("U1")
		if hostSet {
			b.addProv("U1", types.GitProvenance{RepoPath: raw, Host: "github.com", RemoteIdentity: true, BlobPath: "a.txt", Commit: b.nextCommit()})
		} else {
			b.hnrLoc("U1", raw, "a.txt")
		}
		ds := b.done()

		for _, sub := range [][]string{{"sources"}, {"sources", "all"}} {
			for _, format := range []string{"human", "json"} {
				name := strings.Join(sub, "-") + "/" + format + "/" + map[bool]string{true: "host", false: "nohost"}[hostSet]
				t.Run(name, func(t *testing.T) {
					r := runRootSplit(t, reportCmdArgs(ds, sub, "--format", format)...)
					require.NoError(t, r.err)
					for _, out := range []string{r.stdout, r.stderr} {
						assert.NotContains(t, out, "TOKEN123")
						assert.NotContains(t, out, "user:")
					}
					assert.Contains(t, r.stdout, "acme/api")
				})
			}
		}
	}
}

// S-T002: the sources commands list locations only, never matched content.
func TestReportSources_NoMatchOrSnippetContent(t *testing.T) {
	ds := seedDS1(t)
	for _, sub := range [][]string{{"sources"}, {"sources", "all"}} {
		for _, format := range []string{"human", "json"} {
			r := runRootSplit(t, reportCmdArgs(ds, sub, "--format", format)...)
			require.NoError(t, r.err)
			assert.NotContains(t, r.stdout, "sel_B", "no matched secret")
			assert.NotContains(t, r.stdout, "content-B", "no blob content")
			assert.NotContains(t, r.stdout, "Finding ")
			assert.NotContains(t, r.stdout, "Rule:")
			assert.NotContains(t, r.stdout, "Blob:")
		}
	}
}

// S-T007: control and escape bytes never reach the terminal in human output;
// JSON keeps the exact value.
func TestReportSources_SanitizesHumanOutput(t *testing.T) {
	const repo = "acme/ev\x1b[31mil\x07"
	const path = "p\x1b]0;title\x07.txt"
	b := newDSBuilder(t)
	b.finding("S1")
	b.remoteLoc("S1", "github.com", repo, path)
	ds := b.done()

	for _, sub := range [][]string{{"sources"}, {"sources", "all"}} {
		t.Run(strings.Join(sub, "-"), func(t *testing.T) {
			h := runRootSplit(t, reportCmdArgs(ds, sub)...)
			require.NoError(t, h.err)
			for _, bad := range []string{"\x1b", "\x07"} {
				assert.NotContains(t, h.stdout, bad)
			}
			assert.Contains(t, h.stdout, "github.com/acme/ev")

			j := runRootSplit(t, reportCmdArgs(ds, sub, "--format", "json")...)
			require.NoError(t, j.err)
			var d srcDoc
			require.NoError(t, json.Unmarshal([]byte(j.stdout), &d))
			assert.Contains(t, d.repoValues(), "github.com/"+repo)
			assert.Contains(t, d.pathValues(), path)
		})
	}
}

// R16-1: a datastore in the v1.2.11 shape (NULL provenance host, no
// blob_locations rows) is listed with every git source marked host not
// recorded; a blob that never matched appears in sources all only.
func TestReportSourcesAll_LegacyGenerationLabels(t *testing.T) {
	b := newDSBuilder(t)
	b.finding("G1")
	b.hnrLoc("G1", "acme/api", "x.txt")
	b.blob("NOMATCH")
	b.hnrLoc("NOMATCH", "acme/quiet", "q.txt")
	ds := b.done()

	all, allRun := srcRun(t, ds, true)
	assert.Equal(t, []string{"acme/api", "acme/quiet"}, all.repoValues())
	for _, r := range all.Repos {
		assert.False(t, r.HostRecorded, "%s", r.Value)
		assert.Equal(t, "git", r.Kind)
	}
	assert.NotContains(t, allRun.stdout, "(no findings)")
	assert.NotContains(t, allRun.stdout, `"findings"`)

	scoped, _ := srcRun(t, ds, false)
	assert.Equal(t, []string{"acme/api"}, scoped.repoValues())
	assert.NotContains(t, scoped.repoValues(), "acme/quiet")

	h := runRootSplit(t, reportCmdArgs(ds, []string{"sources", "all"})...)
	require.NoError(t, h.err)
	assert.Contains(t, h.stdout, "acme/quiet  (host not recorded)")
	assert.NotContains(t, h.stdout, "(no findings)")
}
