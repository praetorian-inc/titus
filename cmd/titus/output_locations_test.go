package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
	"time"

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

// C-REPORTJSON-1: every location carries exactly the 7 keys, with nulls for
// absent values.
func TestToJSONLocations_SevenKeysWithNulls(t *testing.T) {
	occs := []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CommitDate: commitDate, HostRecorded: true},
		{Kind: "file", Path: "e/f/g/h/config.yml", AbsolutePath: "/a/b/c/d/e/f/g/h/config.yml", HostRecorded: true},
	}
	data, err := json.Marshal(toJSONLocations(locationMatch("x"), occs))
	require.NoError(t, err)

	var locs []map[string]any
	require.NoError(t, json.Unmarshal(data, &locs))
	require.Len(t, locs, 2)
	wantKeys := []string{"absolute_path", "commit", "commit_date", "host_recorded", "path", "range", "repository"}
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
	assert.Nil(t, git["absolute_path"])
	assert.Equal(t, true, git["host_recorded"])
	assert.Equal(t, map[string]any{
		"start": map[string]any{"line": float64(3), "column": float64(7)},
		"end":   map[string]any{"line": float64(3), "column": float64(27)},
	}, git["range"])

	file := locs[1]
	assert.Nil(t, file["repository"])
	assert.Nil(t, file["commit"])
	assert.Nil(t, file["commit_date"])
	assert.Equal(t, "e/f/g/h/config.yml", file["path"])
	assert.Equal(t, "/a/b/c/d/e/f/g/h/config.yml", file["absolute_path"])
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
	paths := []string{"a\nb.yml", "x\x1b[31mRED\x1b[0m.yml", "‮evil.yml"}
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
