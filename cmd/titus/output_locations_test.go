package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/praetorian-inc/titus/pkg/commitlink"
	"github.com/praetorian-inc/titus/pkg/sarif"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var commitDate = time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)

func locationMatch(blob string) *types.Match {
	return &types.Match{
		BlobID:   types.ComputeBlobID([]byte(blob)),
		RuleID:   "np.aws.1",
		RuleName: "AWS API Key",
		Location: types.Location{Source: types.SourceSpan{
			Start: types.SourcePoint{Line: 3, Column: 7},
			End:   types.SourcePoint{Line: 3, Column: 27},
		}},
	}
}

// C-REPORTJSON-1: every location carries exactly the 9 keys (the 7 location
// keys plus commit_url, LAB-7527, and branch, LAB-7529), with nulls for absent
// values (branch is null when none was resolved).
func TestToJSONLocations_EightKeysWithNulls(t *testing.T) {
	occs := []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CommitDate: commitDate, Branch: "feature/login", HostRecorded: true},
		{Kind: "file", Path: "e/f/g/h/config.yml", AbsolutePath: "/a/b/c/d/e/f/g/h/config.yml", HostRecorded: true},
		linkOcc("github.com", "acme/api", "config.yml", linkSHA1),
	}
	data, err := json.Marshal(toJSONLocations(locationMatch("x"), occs))
	require.NoError(t, err)

	var locs []map[string]any
	require.NoError(t, json.Unmarshal(data, &locs))
	require.Len(t, locs, 3)
	wantKeys := []string{"absolute_path", "branch", "commit", "commit_date", "commit_url", "host_recorded", "path", "range", "repository"}
	for _, l := range locs {
		keys := make([]string, 0, len(l))
		for k := range l {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		assert.Equal(t, wantKeys, keys)
	}

	git := locs[0]
	assert.Equal(t, "github.com/acme/api", git["repository"])
	assert.Equal(t, "config.yml", git["path"])
	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", git["commit"])
	assert.Equal(t, "2024-05-01T12:00:00Z", git["commit_date"])
	assert.Equal(t, "feature/login", git["branch"], "CASE-REPORT-1: JSON carries the branch string")
	assert.Nil(t, git["absolute_path"])
	assert.Nil(t, git["commit_url"], "no host recorded on the occurrence, so no link")
	assert.Equal(t, true, git["host_recorded"])
	assert.Equal(t, map[string]any{
		"start": map[string]any{"line": float64(3), "column": float64(7)},
		"end":   map[string]any{"line": float64(3), "column": float64(27)},
	}, git["range"])

	file := locs[1]
	assert.Nil(t, file["repository"])
	assert.Nil(t, file["commit"])
	assert.Nil(t, file["commit_date"])
	assert.Nil(t, file["branch"], "CASE-OMIT-REPORT-1: no branch is null, never \"\" or a placeholder")
	assert.Equal(t, "e/f/g/h/config.yml", file["path"])
	assert.Equal(t, "/a/b/c/d/e/f/g/h/config.yml", file["absolute_path"])
	assert.Nil(t, file["commit_url"])

	linked := locs[2]
	assert.Equal(t, "https://github.com/acme/api/commit/"+linkSHA1, linked["commit_url"])
}

func TestToJSONLocations_NoneIsEmptyArray(t *testing.T) {
	data, err := json.Marshal(toJSONLocations(locationMatch("x"), nil))
	require.NoError(t, err)
	assert.JSONEq(t, `[]`, string(data))
}

func TestToJSONLocations_LegacyHostNotRecorded(t *testing.T) {
	locs := toJSONLocations(locationMatch("x"), []types.Occurrence{{Kind: "git", Repository: "acme/api", Path: "a.yml"}})
	require.Len(t, locs, 1)
	assert.False(t, locs[0].HostRecorded)
}

// SEC-7b: JSON keeps exact bytes; encoding/json escapes them safely.
func TestToJSONLocations_ExactBytesRoundTrip(t *testing.T) {
	paths := []string{"a\nb.yml", "x\x1b[31mRED\x1b[0m.yml", "\u202eevil.yml"}
	occs := make([]types.Occurrence, 0, len(paths))
	for _, p := range paths {
		occs = append(occs, types.Occurrence{Kind: "file", Path: p, HostRecorded: true})
	}
	data, err := json.Marshal(toJSONLocations(locationMatch("x"), occs))
	require.NoError(t, err)
	assert.NotContains(t, string(data), "\x1b", "raw escape byte must be JSON-escaped")

	var back []jsonLocation
	require.NoError(t, json.Unmarshal(data, &back))
	for i, p := range paths {
		assert.Equal(t, p, back[i].Path)
	}
}

func TestMatchLocations_ReadsStore(t *testing.T) {
	s := store.NewMemory()
	m := locationMatch("blob")
	occs := []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/web", Path: "config.yml", Commit: "b", HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", Commit: "a", HostRecorded: true},
	}
	require.NoError(t, s.AddOccurrences(m.BlobID, occs))

	got, err := matchLocations(s, m)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "github.com/acme/api", got[0].Repository, "sorted by repository")
}

// C-SARIF-1: one SARIF result per location, each naming its repository.
func TestWriteSARIF_OneResultPerLocation(t *testing.T) {
	s := store.NewMemory()
	m := locationMatch("blob")
	occs := []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", Commit: "a1", CommitDate: commitDate, HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/web", Path: "config.yml", Commit: "b1", CommitDate: commitDate, HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/api", Path: "deploy/config.yml", Commit: "a2", CommitDate: commitDate, HostRecorded: true},
	}
	require.NoError(t, s.AddOccurrences(m.BlobID, occs))
	rules := []*types.Rule{{ID: "np.aws.1", Name: "AWS API Key"}}
	score := &types.Score{Final: 85, Applied: []types.ScoreModifier{}}

	var buf bytes.Buffer
	require.NoError(t, writeSARIF(&buf, s, rules, []*types.Match{m}, func(*types.Match) *types.Score { return score }))

	var rep sarif.Report
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rep))
	require.Len(t, rep.Runs, 1)
	assert.Len(t, rep.Runs[0].Tool.Driver.Rules, 1)
	results := rep.Runs[0].Results
	require.Len(t, results, 3)

	var uris []string
	repos := map[string]int{}
	fps := map[string]bool{}
	for _, r := range results {
		uris = append(uris, r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		require.NotNil(t, r.Properties)
		require.NotEmpty(t, r.Properties.Repository, "each result names its repository")
		repos[r.Properties.Repository]++
		assert.NotEmpty(t, r.Properties.Commit)
		assert.Equal(t, "error", r.Level)
		fps[r.PartialFingerprints[sarif.LocationFingerprintKey]] = true
	}
	slices.Sort(uris)
	assert.Equal(t, []string{"config.yml", "config.yml", "deploy/config.yml"}, uris)
	assert.Equal(t, map[string]int{"github.com/acme/api": 2, "github.com/acme/web": 1}, repos)
	assert.Len(t, fps, 3)
}

func TestWriteSARIF_NoLocationFallsBackToBlobID(t *testing.T) {
	s := store.NewMemory()
	m := locationMatch("orphan")

	var buf bytes.Buffer
	require.NoError(t, writeSARIF(&buf, s, nil, []*types.Match{m}, nil))

	var rep sarif.Report
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rep))
	require.Len(t, rep.Runs[0].Results, 1)
	assert.Equal(t, m.BlobID.Hex(), rep.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, "warning", rep.Runs[0].Results[0].Level)
}

// Human lines: one per occurrence, colliding lines switch to the absolute
// path, and hostile text is sanitized.
func TestWriteLocationLines(t *testing.T) {
	occs := []types.Occurrence{
		{Kind: "git", Path: "config.yml", AbsolutePath: "/w/one/config.yml", Commit: "abcdef0123", CommitDate: commitDate, HostRecorded: true},
		{Kind: "git", Path: "config.yml", AbsolutePath: "/w/two/config.yml", Commit: "abcdef0123", CommitDate: commitDate, HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/api", Path: "deploy/config.yml", WorkingTree: true, HostRecorded: true},
		{Kind: "git", Repository: "acme/api", Path: "x\x1b[31m.yml"},
	}
	var buf bytes.Buffer
	writeLocationLines(&buf, 3, occs, nil)
	assert.Equal(t, ""+
		"    /w/one/config.yml:3  abcdef0  2024-05-01\n"+
		"    /w/two/config.yml:3  abcdef0  2024-05-01\n"+
		"    github.com/acme/api  deploy/config.yml:3  working tree\n"+
		"    acme/api  x\\x1b[31m.yml:3  host not recorded\n",
		buf.String())
}

// ---------------------------------------------------------------------------
// LAB-7527: commit_url
// ---------------------------------------------------------------------------

const (
	linkSHA1 = "0123456789abcdef0123456789abcdef01234567"
	linkSHA2 = "fedcba9876543210fedcba9876543210fedcba98"
)

// linkOcc returns the committed git occurrence a scan or API enumeration of
// host/repo records, built through the same constructor the stores use.
func linkOcc(host, repo, path, commit string) types.Occurrence {
	return types.OccurrencesOf(types.GitProvenance{
		RepoPath: host + "/" + repo, Host: host, RemoteIdentity: true, BlobPath: path,
		Commit: &types.CommitMetadata{CommitID: commit, CommitterTimestamp: commitDate},
	})[0]
}

// linkWorkingTreeOcc is the working-tree location of host/repo: no commit.
func linkWorkingTreeOcc(host, repo, path string) types.Occurrence {
	return types.OccurrencesOf(types.GitProvenance{
		RepoPath: host + "/" + repo, Host: host, RemoteIdentity: true, BlobPath: path,
		Locations: []types.GitLocation{{Path: path, WorkingTree: true}},
	})[0]
}

// linkNoCommitOcc is a commitless occurrence, as an API enumeration records.
func linkNoCommitOcc(host, repo, path string) types.Occurrence {
	return types.OccurrencesOf(types.GitProvenance{
		RepoPath: host + "/" + repo, Host: host, RemoteIdentity: true, BlobPath: path,
	})[0]
}

// linkLegacyOcc is a row written before hosts were recorded: no host, and
// HostRecorded false as the store reports it.
func linkLegacyOcc() types.Occurrence {
	return types.Occurrence{Kind: "git", Repository: "acme/api", Path: "config.yml", Commit: linkSHA1, CommitDate: commitDate}
}

// linkCases are occurrences paired with the commit link they must produce
// ("" is no link). The same table drives the JSON, human and SARIF tests.
var linkCases = []struct {
	name string
	occ  types.Occurrence
	want string
}{
	{"github.com", linkOcc("github.com", "acme/api", "config.yml", linkSHA1), "https://github.com/acme/api/commit/" + linkSHA1},
	{"gitlab.com host", linkOcc("gitlab.com", "acme/api", "config.yml", linkSHA1), ""},
	{"github.com.evil host", linkOcc("github.com.evil", "acme/api", "config.yml", linkSHA1), ""},
	{"github.example.com host", linkOcc("github.example.com", "acme/api", "config.yml", linkSHA1), ""},
	{"legacy row, host not recorded", linkLegacyOcc(), ""},
	{"no commit", linkNoCommitOcc("github.com", "acme/api", "config.yml"), ""},
	{"working tree", linkWorkingTreeOcc("github.com", "acme/api", "config.yml"), ""},
	{"file kind", types.Occurrence{Kind: "file", Path: "config.yml", AbsolutePath: "/w/config.yml", HostRecorded: true}, ""},
	{"short commit", linkOcc("github.com", "acme/api", "config.yml", "abcdef0123"), ""},
	{"control char in repository", types.Occurrence{
		Kind: "git", Repository: "github.com/acme/ap\x1b[31mi", Host: "github.com", Path: "config.yml",
		Commit: linkSHA1, CommitDate: commitDate, HostRecorded: true,
	}, ""},
}

// Outcome A: commit_url is the exact link for a github.com occurrence and JSON
// null for every case that has none; all 9 keys are always present.
func TestToJSONLocations_CommitURL(t *testing.T) {
	for _, tc := range linkCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(toJSONLocations(locationMatch("x"), []types.Occurrence{tc.occ}))
			require.NoError(t, err)
			var locs []map[string]any
			require.NoError(t, json.Unmarshal(data, &locs))
			require.Len(t, locs, 1)
			require.Len(t, locs[0], 9, "all 9 keys always present")
			got, present := locs[0]["commit_url"]
			require.True(t, present, "commit_url key is always present")
			if tc.want == "" {
				assert.Nil(t, got, "no link is JSON null")
			} else {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

// Outcome B: each location links to its own recorded commit, not a shared one.
func TestToJSONLocations_CommitURLIsPerLocationCommit(t *testing.T) {
	occs := []types.Occurrence{
		linkOcc("github.com", "acme/api", "config.yml", linkSHA1),
		linkOcc("github.com", "acme/api", "config.yml", linkSHA2),
	}
	locs := toJSONLocations(locationMatch("x"), occs)
	require.Len(t, locs, 2)
	require.NotNil(t, locs[0].CommitURL)
	require.NotNil(t, locs[1].CommitURL)
	assert.Equal(t, "https://github.com/acme/api/commit/"+linkSHA1, *locs[0].CommitURL)
	assert.Equal(t, "https://github.com/acme/api/commit/"+linkSHA2, *locs[1].CommitURL)
}

// Outcome C: the link line directly follows its location line, indented 6
// spaces; absent where no link can be built.
func TestWriteLocationLines_CommitLink(t *testing.T) {
	t.Run("link line follows its location line", func(t *testing.T) {
		occs := []types.Occurrence{
			linkOcc("github.com", "acme/api", "a.yml", linkSHA1),
			linkOcc("github.com", "acme/web", "b.yml", linkSHA2),
		}
		var buf bytes.Buffer
		writeLocationLines(&buf, 3, occs, nil)
		assert.Equal(t, ""+
			"    github.com/acme/api  a.yml:3  0123456  2024-05-01\n"+
			"      https://github.com/acme/api/commit/"+linkSHA1+"\n"+
			"    github.com/acme/web  b.yml:3  fedcba9  2024-05-01\n"+
			"      https://github.com/acme/web/commit/"+linkSHA2+"\n",
			buf.String())
	})

	t.Run("no link line", func(t *testing.T) {
		for _, tc := range linkCases {
			if tc.want != "" || tc.occ.Repository == "" {
				continue
			}
			t.Run(tc.name, func(t *testing.T) {
				var buf bytes.Buffer
				writeLocationLines(&buf, 3, []types.Occurrence{tc.occ}, nil)
				assert.Equal(t, 1, strings.Count(buf.String(), "\n"), "only the location line: %q", buf.String())
				assert.NotContains(t, buf.String(), "https://")
			})
		}
	})

	t.Run("control characters never reach the terminal", func(t *testing.T) {
		hostile := types.Occurrence{
			Kind: "git", Repository: "github.com/acme/ap\x1b[31mi", Host: "github.com", Path: "config.yml",
			Commit: linkSHA1, CommitDate: commitDate, HostRecorded: true,
		}
		var buf bytes.Buffer
		writeLocationLines(&buf, 3, []types.Occurrence{hostile}, nil)
		for _, r := range buf.String() {
			assert.False(t, r < 0x20 && r != '\n' || r == 0x7f, "raw control character %q in %q", r, buf.String())
		}
		assert.NotContains(t, buf.String(), "https://", "the core refuses an unsafe repository, so no link line")
		assert.Equal(t, 1, strings.Count(buf.String(), "\n"))
	})

	t.Run("link line carries the location line style", func(t *testing.T) {
		prev := color.NoColor
		color.NoColor = false
		t.Cleanup(func() { color.NoColor = prev })
		style := color.New(color.FgCyan)
		o := linkOcc("github.com", "acme/api", "a.yml", linkSHA1)
		url := "https://github.com/acme/api/commit/" + linkSHA1

		var buf bytes.Buffer
		writeLocationLines(&buf, 3, []types.Occurrence{o}, style)
		lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
		require.Len(t, lines, 2)
		assert.Equal(t, "      "+style.Sprint(url), lines[1])
		assert.Contains(t, lines[1], "\x1b[", "styled")
	})
}

func sarifResultsFor(t *testing.T, occs []types.Occurrence) []sarif.Result {
	t.Helper()
	s := store.NewMemory()
	m := locationMatch("blob")
	require.NoError(t, s.AddOccurrences(m.BlobID, occs))
	var buf bytes.Buffer
	require.NoError(t, writeSARIF(&buf, s, nil, []*types.Match{m}, nil))
	var rep sarif.Report
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rep))
	require.Len(t, rep.Runs, 1)
	return rep.Runs[0].Results
}

// Outcome F: the commit_url property is present for a github occurrence and
// its key is absent (omitempty) otherwise.
func TestWriteSARIF_CommitURLProperty(t *testing.T) {
	for _, tc := range linkCases {
		t.Run(tc.name, func(t *testing.T) {
			s := store.NewMemory()
			m := locationMatch("blob")
			require.NoError(t, s.AddOccurrences(m.BlobID, []types.Occurrence{tc.occ}))
			var buf bytes.Buffer
			require.NoError(t, writeSARIF(&buf, s, nil, []*types.Match{m}, nil))

			var raw struct {
				Runs []struct {
					Results []struct {
						Properties map[string]any `json:"properties"`
					} `json:"results"`
				} `json:"runs"`
			}
			require.NoError(t, json.Unmarshal(buf.Bytes(), &raw))
			require.Len(t, raw.Runs[0].Results, 1)
			props := raw.Runs[0].Results[0].Properties
			got, present := props["commit_url"]
			if tc.want == "" {
				assert.False(t, present, "commit_url key is absent, not empty")
			} else {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

// Outcome F: whether a link exists never changes a result's fingerprint.
func TestWriteSARIF_FingerprintIndependentOfCommitLink(t *testing.T) {
	linked := linkOcc("github.com", "acme/api", "config.yml", linkSHA1)
	unlinked := linked
	unlinked.Host = ""
	require.NotEmpty(t, commitlink.URL(linked))
	require.Empty(t, commitlink.URL(unlinked))

	a := sarifResultsFor(t, []types.Occurrence{linked})
	b := sarifResultsFor(t, []types.Occurrence{unlinked})
	require.Len(t, a, 1)
	require.Len(t, b, 1)
	fp := a[0].PartialFingerprints[sarif.LocationFingerprintKey]
	require.NotEmpty(t, fp)
	assert.Equal(t, fp, b[0].PartialFingerprints[sarif.LocationFingerprintKey])
	assert.NotEmpty(t, a[0].Properties.CommitURL)
	assert.Empty(t, b[0].Properties.CommitURL)
}
