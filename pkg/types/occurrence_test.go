package types

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var jun15 = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

func lineFields(s string) []string { return strings.Split(s, "  ") }

func TestGitProvenance_NewFieldsKeepLegacyJSON(t *testing.T) {
	old := GitProvenance{RepoPath: "acme/api", BlobPath: "config.yml"}
	b, err := json.Marshal(old)
	require.NoError(t, err)
	assert.JSONEq(t, `{"RepoPath":"acme/api","Commit":null,"BlobPath":"config.yml"}`, string(b))

	var decoded GitProvenance
	require.NoError(t, json.Unmarshal([]byte(`{"RepoPath":"acme/api","BlobPath":"config.yml"}`), &decoded))
	assert.Equal(t, old, decoded)
	assert.Equal(t, "git", decoded.Kind())
	assert.Equal(t, "config.yml", decoded.Path())
}

func TestOccurrencesOf_GitPrimaryWhenNoLocations(t *testing.T) {
	p := GitProvenance{
		RepoPath: "github.com/acme/api",
		BlobPath: "config.yml",
		Commit:   &CommitMetadata{CommitID: "7d0e8150aaaa", CommitterTimestamp: jun15},
	}
	got := OccurrencesOf(p)
	require.Len(t, got, 1)
	assert.Equal(t, Occurrence{
		Kind: "git", Repository: "github.com/acme/api", Path: "config.yml",
		Commit: "7d0e8150aaaa", CommitDate: jun15, HostRecorded: true,
	}, got[0])
}

func TestOccurrencesOf_GitOnePerLocation(t *testing.T) {
	p := GitProvenance{
		RepoPath:       "github.com/acme/api",
		RepoRoot:       "/src/api",
		RemoteIdentity: true,
		Locations: []GitLocation{
			{Path: "config.yml", Commit: &CommitMetadata{CommitID: "aaaa111", CommitterTimestamp: jun15}},
			{Path: "backup/config.yml", WorkingTree: true},
		},
	}
	got := OccurrencesOf(p)
	require.Len(t, got, 2)
	// Committed content with a host identity has no absolute path, so it merges across folders.
	assert.Equal(t, Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml",
		Commit: "aaaa111", CommitDate: jun15, HostRecorded: true}, got[0])
	// Working tree content is separated by its absolute folder.
	assert.Equal(t, Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "backup/config.yml",
		AbsolutePath: filepath.Join("/src/api", "backup/config.yml"), WorkingTree: true, HostRecorded: true}, got[1])
}

// S-T003: the host a repository was scanned from reaches every occurrence of
// that provenance (committed and working-tree), so host-aware selectors see it.
// A provenance with no host leaves Host empty rather than inventing one.
func TestOccurrencesOf_GitCopiesHost(t *testing.T) {
	locs := []GitLocation{
		{Path: "config.yml", Commit: &CommitMetadata{CommitID: "aaaa111", CommitterTimestamp: jun15}},
		{Path: "backup/config.yml", WorkingTree: true},
	}
	for _, tt := range []struct {
		name     string
		host     string
		wantHost string
	}{
		{"hosted", "github.com", "github.com"},
		{"self-hosted", "gitlab.example.com", "gitlab.example.com"},
		{"no host stays empty", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := OccurrencesOf(GitProvenance{
				RepoPath: "github.com/acme/api", Host: tt.host, RepoRoot: "/src/api",
				RemoteIdentity: true, Locations: locs,
			})
			require.Len(t, got, len(locs))
			for _, o := range got {
				assert.Equal(t, tt.wantHost, o.Host, "location %s", o.Path)
				assert.True(t, o.HostRecorded)
			}
		})
	}

	// The primary (no Locations) occurrence carries the host too.
	got := OccurrencesOf(GitProvenance{RepoPath: "github.com/acme/api", Host: "github.com", BlobPath: "a.txt", RemoteIdentity: true})
	require.Len(t, got, 1)
	assert.Equal(t, "github.com", got[0].Host)
}

func TestOccurrencesOf_GitRemotelessRepoKeepsAbsolutePath(t *testing.T) {
	// C-FOLDERS-2: two remote-less repos with identical commits must not merge.
	for _, root := range []string{"/x/one", "/x/two"} {
		p := GitProvenance{
			RepoPath: ".", RepoRoot: root,
			Locations: []GitLocation{{Path: "config.yml", Commit: &CommitMetadata{CommitID: "c1"}}},
		}
		got := OccurrencesOf(p)
		require.Len(t, got, 1)
		assert.Equal(t, filepath.Join(root, "config.yml"), got[0].AbsolutePath)
	}
}

func TestOccurrencesOf_File(t *testing.T) {
	got := OccurrencesOf(FileProvenance{FilePath: "e/f/config.yml"})
	require.Len(t, got, 1)
	abs, err := filepath.Abs("e/f/config.yml")
	require.NoError(t, err)
	assert.Equal(t, Occurrence{Kind: "file", Path: "e/f/config.yml", AbsolutePath: abs, HostRecorded: true}, got[0])
}

func TestOccurrencesOf_ExtendedAndArchive(t *testing.T) {
	ext := OccurrencesOf(ExtendedProvenance{Payload: map[string]interface{}{"path": "s3://b/k.env"}})
	require.Len(t, ext, 1)
	assert.Equal(t, Occurrence{Kind: "extended", Path: "s3://b/k.env", HostRecorded: true}, ext[0])

	src := OccurrencesOf(ExtendedProvenance{Payload: map[string]interface{}{"source": "confluence", "path": "SPACE/Page"}})
	require.Len(t, src, 1)
	assert.Equal(t, Occurrence{Kind: "extended", Source: "confluence", Path: "SPACE/Page", HostRecorded: true}, src[0])

	nonString := OccurrencesOf(ExtendedProvenance{Payload: map[string]interface{}{"source": 42, "path": "p"}})
	require.Len(t, nonString, 1)
	assert.Empty(t, nonString[0].Source)
	assert.Empty(t, nonString[0].Repository)

	arc := OccurrencesOf(ArchiveProvenance{ArchivePath: "a.zip", MemberPath: "x/y.txt"})
	require.Len(t, arc, 1)
	assert.Equal(t, Occurrence{Kind: "archive", Path: "a.zip:x/y.txt", HostRecorded: true}, arc[0])
}

func TestMergeOccurrences_LegacyGitRowIsHostNotRecorded(t *testing.T) {
	// C-OLDDS-1: a pre-change datastore has only a provenance row with repo_path acme/api.
	provs := []Provenance{GitProvenance{RepoPath: "acme/api", BlobPath: "config.yml",
		Commit: &CommitMetadata{CommitID: "c1"}}}
	got := MergeOccurrences(nil, provs)
	require.Len(t, got, 1)
	assert.Equal(t, "acme/api", got[0].Repository)
	assert.False(t, got[0].HostRecorded)
	assert.True(t, strings.HasSuffix(FormatLine(got[0], 3, ""), "host not recorded"))
}

func TestMergeOccurrences_LegacyAndRescanShowBoth(t *testing.T) {
	// C-OLDDS-2: legacy acme/api row, then titus github acme/api into the same datastore.
	rows := []Occurrence{{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml",
		Commit: "c1", HostRecorded: true}}
	provs := []Provenance{
		GitProvenance{RepoPath: "acme/api", BlobPath: "config.yml", Commit: &CommitMetadata{CommitID: "c1"}},
		GitProvenance{RepoPath: "github.com/acme/api", BlobPath: "config.yml", Commit: &CommitMetadata{CommitID: "c1"}},
	}
	got := MergeOccurrences(rows, provs)
	require.Len(t, got, 2)
	var labels []string
	for _, o := range got {
		label := o.Repository
		if !o.HostRecorded {
			label += " (host not recorded)"
		}
		labels = append(labels, label)
	}
	assert.Equal(t, []string{"acme/api (host not recorded)", "github.com/acme/api"}, labels)
}

func TestMergeOccurrences_CoveredProvenanceIsNotDuplicated(t *testing.T) {
	rows := []Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", Commit: "c1", HostRecorded: true},
		{Kind: "file", Path: "config.yml", AbsolutePath: "/x/one/config.yml", HostRecorded: true},
	}
	provs := []Provenance{
		GitProvenance{RepoPath: "github.com/acme/api", BlobPath: "config.yml", Commit: &CommitMetadata{CommitID: "c1"}},
		FileProvenance{FilePath: "config.yml"},
	}
	got := MergeOccurrences(rows, provs)
	assert.Len(t, got, 2)
	for _, o := range got {
		assert.True(t, o.HostRecorded)
	}
}

func TestMergeOccurrences_UncoveredNonGitRowsAreKept(t *testing.T) {
	// C-NONGIT-1: two S3 provenance rows and no location rows give two occurrences.
	provs := []Provenance{
		ExtendedProvenance{Payload: map[string]interface{}{"path": "s3://b/one.env"}},
		ExtendedProvenance{Payload: map[string]interface{}{"path": "s3://b/two.env"}},
		FileProvenance{FilePath: "legacy/config.yml"},
	}
	got := MergeOccurrences(nil, provs)
	require.Len(t, got, 3)
	for _, o := range got {
		assert.True(t, o.HostRecorded)
		// A legacy file row has no recorded root; never derive one from the reader's cwd.
		assert.Empty(t, o.AbsolutePath)
	}
}

func TestMergeOccurrences_CloneMergeDropsCommitlessDuplicate(t *testing.T) {
	// C-CLONEMERGE-1: a local --git scan and titus github acme/api share one location.
	rows := []Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", Commit: "c1", CommitDate: jun15, HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", WorkingTree: true,
			AbsolutePath: "/src/api/config.yml", HostRecorded: true},
	}
	got := MergeOccurrences(rows, nil)
	require.Len(t, got, 2)
	repos := map[string]bool{}
	committed := 0
	for _, o := range got {
		repos[o.Repository] = true
		if !o.WorkingTree {
			committed++
			assert.Equal(t, "c1", o.Commit)
		}
	}
	assert.Equal(t, map[string]bool{"github.com/acme/api": true}, repos)
	assert.Equal(t, 1, committed, "locations_for_config.yml")
}

func TestMergeOccurrences_RedactsLegacyUserinfo(t *testing.T) {
	// SEC-5: an old datastore may hold the raw remote URL with credentials.
	provs := []Provenance{GitProvenance{RepoPath: "https://u:SECRET@h/o/r", BlobPath: "a.yml"}}
	got := MergeOccurrences(nil, provs)
	require.Len(t, got, 1)
	assert.NotContains(t, got[0].Repository, "SECRET")
	assert.NotContains(t, got[0].Repository, "u:")
	assert.Equal(t, "https://h/o/r", got[0].Repository)
}

func TestMergeOccurrences_DeduplicatesAndSorts(t *testing.T) {
	a := Occurrence{Kind: "git", Repository: "github.com/acme/web", Path: "a.yml", Commit: "c2", HostRecorded: true}
	b := Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "z.yml", Commit: "c1", HostRecorded: true}
	got := MergeOccurrences([]Occurrence{a, b, a}, nil)
	assert.Equal(t, []Occurrence{b, a}, got)
}

func TestMergeOccurrences_CoveredExtendedRowGetsSourceFromProvenance(t *testing.T) {
	// A stored location row carries no Source (no column); the covering
	// provenance row supplies it on read.
	rows := []Occurrence{{Kind: "extended", Path: "SPACE/Page", HostRecorded: true}}
	provs := []Provenance{ExtendedProvenance{Payload: map[string]interface{}{"source": "confluence", "path": "SPACE/Page"}}}
	got := MergeOccurrences(rows, provs)
	assert.Equal(t, []Occurrence{{Kind: "extended", Source: "confluence", Path: "SPACE/Page", HostRecorded: true}}, got)
}

func TestSortOccurrences_DeterministicOrder(t *testing.T) {
	jun16 := jun15.AddDate(0, 0, 1)
	in := []Occurrence{
		{Kind: "file", Path: "a.yml", AbsolutePath: "/x/a.yml"},
		{Kind: "git", Repository: "r", Path: "p.yml", WorkingTree: true},
		{Kind: "git", Repository: "r", Path: "p.yml", Commit: "c0"},
		{Kind: "git", Repository: "r", Path: "p.yml", Commit: "c2", CommitDate: jun16},
		{Kind: "git", Repository: "r", Path: "p.yml", Commit: "c1", CommitDate: jun15},
		{Kind: "git", Repository: "r", Path: "a.yml", Commit: "c9", CommitDate: jun16},
		{Kind: "git", Repository: "a", Path: "z.yml", Commit: "c9"},
	}
	SortOccurrences(in)
	want := []string{"a/z.yml/c9", "r/a.yml/c9", "r/p.yml/c1", "r/p.yml/c2", "r/p.yml/c0", "r/p.yml/wt", "/a.yml/"}
	var gotKeys []string
	for _, o := range in {
		c := o.Commit
		if o.WorkingTree {
			c = "wt"
		}
		gotKeys = append(gotKeys, o.Repository+"/"+o.Path+"/"+c)
	}
	assert.Equal(t, want, gotKeys)
}

func TestFormatLine_HumanLine1(t *testing.T) {
	o := Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml",
		Commit: "7d0e8150aaaa", CommitDate: time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC), HostRecorded: true}
	assert.Equal(t, []string{"github.com/acme/api", "config.yml:3", "7d0e815", "2026-06-15"},
		lineFields(FormatLine(o, 3, "")))
}

func TestFormatLine_HumanLine2(t *testing.T) {
	o := Occurrence{Kind: "file", Path: "e/f/config.yml", HostRecorded: true}
	assert.Equal(t, []string{"e/f/config.yml:3"}, lineFields(FormatLine(o, 3, "")))
}

func TestFormatLine_WorkingTree(t *testing.T) {
	o := Occurrence{Kind: "git", Path: "backup/config.yml", WorkingTree: true, HostRecorded: true}
	assert.Equal(t, "backup/config.yml:7  working tree", FormatLine(o, 7, ""))

	o.Repository = "github.com/acme/api"
	assert.Equal(t, "github.com/acme/api  backup/config.yml:7  working tree", FormatLine(o, 7, ""))
}

func TestFormatLine_LegacyHostNotRecorded(t *testing.T) {
	o := Occurrence{Kind: "git", Repository: "acme/api", Path: "config.yml",
		Commit: "7d0e8150aaaa", CommitDate: jun15}
	assert.Equal(t, "acme/api  config.yml:3  7d0e815  2026-06-15  host not recorded", FormatLine(o, 3, ""))
}

func TestFormatLine_ExtendedSourceLeads(t *testing.T) {
	o := Occurrence{Kind: "extended", Source: "confluence", Path: "SPACE/Page", HostRecorded: true}
	assert.Equal(t, "confluence  SPACE/Page:4", FormatLine(o, 4, ""))

	o.Source = "conf\x1b[31mluence"
	assert.NotContains(t, FormatLine(o, 4, ""), "\x1b")

	// Repository wins over Source; a sourceless extended line is just the path.
	assert.Equal(t, "SPACE/Page:4", FormatLine(Occurrence{Kind: "extended", Path: "SPACE/Page", HostRecorded: true}, 4, ""))
}

func TestFormatLine_UsesDisplayPath(t *testing.T) {
	o := Occurrence{Kind: "file", Path: "config.yml", AbsolutePath: "/x/one/config.yml", HostRecorded: true}
	assert.Equal(t, "/x/one/config.yml:2", FormatLine(o, 2, "/x/one/config.yml"))
}

func TestFormatLine_SanitizesEveryField(t *testing.T) {
	o := Occurrence{Kind: "git", Repository: "evil\x1b]52;c;x\x07", Path: "a\nb\u202e.yml",
		Commit: "\x1b[31mabcdef0", HostRecorded: true}
	got := FormatLine(o, 1, "")
	assert.NotContains(t, got, "\x1b")
	assert.NotContains(t, got, "\n")
	assert.NotContains(t, got, "\u202e")
}

func TestDisambiguateDisplay_FoldersCollision(t *testing.T) {
	// C-FOLDERS-1: identical config.yml in /x/one and /x/two.
	occs := []Occurrence{
		{Kind: "file", Path: "config.yml", AbsolutePath: "/x/one/config.yml", HostRecorded: true},
		{Kind: "file", Path: "config.yml", AbsolutePath: "/x/two/config.yml", HostRecorded: true},
	}
	assert.Equal(t, []string{"/x/one/config.yml", "/x/two/config.yml"}, DisambiguateDisplay(occs))
}

func TestDisambiguateDisplay_NoCollisionKeepsRelativePath(t *testing.T) {
	occs := []Occurrence{
		{Kind: "file", Path: "config.yml", AbsolutePath: "/x/one/config.yml", HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml",
			AbsolutePath: "/src/api/config.yml", WorkingTree: true, HostRecorded: true},
	}
	assert.Equal(t, []string{"config.yml", "config.yml"}, DisambiguateDisplay(occs))
}

func TestSanitizeDisplay(t *testing.T) {
	cases := []struct{ in, want string }{
		{"café.yml", "café.yml"},
		{"x\x1b[31mRED\x1b[0m.yml", `x\x1b[31mRED\x1b[0m.yml`},
		{"\x1b]8;;http://e\x07", `\x1b]8;;http://e\x07`},
		{"a\nb.yml", `a\x0ab.yml`},
		{"a\tb\r", `a\x09b\x0d`},
		{"del\x7f", `del\x7f`},
		{"\u202eevil.yml", `\u{202e}evil.yml`},
		{"\u2066i\u2069\u200e\u200f\u061c", `\u{2066}i\u{2069}\u{200e}\u{200f}\u{061c}`},
		{"c1\u0085", `c1\u{0085}`},
		{"caf\xe9.yml", `caf\xe9.yml`},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, SanitizeDisplay(c.in), "input %q", c.in)
	}
}

func TestSanitizeDisplay_OutputHasNoControlOrBidi(t *testing.T) {
	var all strings.Builder
	for r := rune(0); r < 0x2100; r++ {
		all.WriteRune(r)
	}
	all.WriteString("\xff\xfe\x80")
	out := SanitizeDisplay(all.String())
	assert.True(t, utf8.ValidString(out))
	for _, r := range out {
		assert.False(t, r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || isBidiControl(r), "rune %U", r)
	}
	assert.Equal(t, out, SanitizeDisplay(out), "idempotent")
}
