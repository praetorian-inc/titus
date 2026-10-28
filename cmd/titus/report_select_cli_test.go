package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/sarif"
)

// Command-level tests of the report selectors (--repo, --namespace, --path).
// Every test runs the real cobra command in process against a datastore that
// was seeded through the store API (report_testkit_test.go). Expected values
// are the plan's (outcome-plan-2.json), written out literally.
//
// Golden provenance (C-UNFILTERED). testdata/report_unfiltered/*.golden are
// the output of the five unfiltered commands on DS1 as produced by base commit
// 5a910ac51f8bf14e64fb8de1dce52daae037eaf6, before any selector code existed.
// They are NOT regenerated with the current code. To reproduce them:
//
//	git -C <titus> worktree add --detach <dir> 5a910ac51f8bf14e64fb8de1dce52daae037eaf6
//	cp report_testkit_test.go <dir>/cmd/titus/ ; delete every line ending in BASEDROP
//	add a test there that runs runRootSplit over seedDS1 for the five argv of
//	selUnfilteredCases and writes r.stdout to <name>.golden
//	GOWORK=off go test ./cmd/titus -run <that test>
//	git -C <titus> worktree remove <dir>

type selJSONLoc struct {
	Repository   *string `json:"repository"`
	Path         string  `json:"path"`
	AbsolutePath *string `json:"absolute_path"`
	Commit       *string `json:"commit"`
	HostRecorded bool    `json:"host_recorded"`
}

type selJSONMatch struct {
	StructuralID string       `json:"StructuralID"`
	BlobID       string       `json:"BlobID"`
	FilePath     string       `json:"file_path"`
	Locations    []selJSONLoc `json:"locations"`
}

type selJSONFinding struct {
	ID      string         `json:"ID"`
	Matches []selJSONMatch `json:"Matches"`
}

func selDecodeFindings(t *testing.T, stdout string) []selJSONFinding {
	t.Helper()
	require.True(t, jsonValid(stdout), "stdout is one valid JSON document: %q", stdout)
	var out []selJSONFinding
	require.NoError(t, json.Unmarshal([]byte(stdout), &out))
	return out
}

// selArgs builds `report <sub> --datastore ds <flags>`.
func selArgs(ds string, sub []string, flags ...string) []string {
	return reportCmdArgs(ds, sub, flags...)
}

// ds2Name names a DS2 location from its JSON form.
func ds2Name(t *testing.T, roots ds2Roots, l selJSONLoc) string {
	t.Helper()
	abs := ""
	if l.AbsolutePath != nil {
		abs = *l.AbsolutePath
	}
	switch {
	case l.Repository == nil && strings.HasPrefix(abs, roots.x):
		return "P3"
	case l.Repository == nil && strings.HasPrefix(abs, roots.y):
		return "P4"
	case l.Repository != nil && l.Path == "config/app.env" && abs == "":
		return "P1"
	case l.Repository != nil && l.Path == "config/app.env" && strings.HasPrefix(abs, roots.a):
		return "P2"
	case l.Repository != nil && l.Path == "lib/key.go" && abs == "":
		return "P5"
	case l.Repository != nil && l.Path == "lib/key.go" && strings.HasPrefix(abs, roots.b):
		return "P6"
	}
	require.Failf(t, "unknown DS2 location", "%+v", l)
	return ""
}

func ds2Names(t *testing.T, roots ds2Roots, stdout string) []string {
	t.Helper()
	var names []string
	for _, f := range selDecodeFindings(t, stdout) {
		for _, m := range f.Matches {
			for _, l := range m.Locations {
				names = append(names, ds2Name(t, roots, l))
			}
		}
	}
	return sortedNames(names...)
}

func selRunOK(t *testing.T, args ...string) cliResult {
	t.Helper()
	r := runRootSplit(t, args...)
	require.NoError(t, r.err, "stderr: %s", r.stderr)
	return r
}

// C-UNION-OVERLAP, C-UNION-MIXED, C-UNION-REPEAT.
func TestReportSelect_UnionCases(t *testing.T) {
	ds := seedDS1(t)
	tests := []struct {
		id    string
		flags []string
		want  []string
	}{
		{"C-UNION-OVERLAP", []string{"--repo", "github.com/acme/api", "--namespace", "github.com/acme"}, []string{"L1", "L4", "L7"}},
		{"C-UNION-MIXED", []string{"--repo", "github.com/other/api", "--path", "deploy.yml"}, []string{"L2", "L3"}},
		{"C-UNION-REPEAT", []string{"--repo", "github.com/other/api", "--repo", "gitlab.example.com/acme/team/sub/api"}, []string{"L2", "L5"}},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			r := selRunOK(t, selArgs(ds, nil, append([]string{"--format", "json"}, tc.flags...)...)...)
			assert.Equal(t, tc.want, reportLocationNames(t, r.stdout))
		})
	}
}

var selUnfilteredCases = []struct {
	name string
	argv []string
}{
	{"report", []string{"report"}},
	{"report_json", []string{"report", "--format", "json"}},
	{"report_sarif", []string{"report", "--format", "sarif"}},
	{"summary", []string{"report", "summary"}},
	{"summary_json", []string{"report", "summary", "--format", "json"}},
}

// C-UNFILTERED (and S-T012: the SARIF golden carries locationFingerprint).
func TestReportSelect_UnfilteredIsUnchanged(t *testing.T) {
	ds := seedDS1(t)
	for _, tc := range selUnfilteredCases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", "report_unfiltered", tc.name+".golden"))
			require.NoError(t, err)
			args := append(append([]string{}, tc.argv...), "--datastore", ds)
			r := selRunOK(t, args...)
			assert.Empty(t, r.stderr)
			assert.Equal(t, string(want), r.stdout)
		})
	}
}

// C-REPO-HOSTLESS, C-REPO-DISPLAYED, C-REPO-ABSFOLDER, C-NOPARSE-HOST,
// C-NS-HOST, C-NS-HOSTLESS, C-NS-BOUNDARY, C-NS-ABSFOLDER.
func TestReportSelect_RepoAndNamespaceCases(t *testing.T) {
	ds1 := seedDS1(t)
	ds2, roots := seedDS2(t)
	tests := []struct {
		id    string
		ds    string
		flags []string
		want  []string
		ds2   bool
	}{
		{"C-REPO-HOSTLESS", ds1, []string{"--repo", "acme/api"}, []string{"L1", "L3", "L7", "L8"}, false},
		{"C-REPO-DISPLAYED", ds1, []string{"--repo", "gitlab.example.com/acme/api"}, []string{"L3", "L7"}, false},
		{"C-NOPARSE-HOST", ds1, []string{"--repo", "github.com/acme/api"}, []string{"L1", "L7"}, false},
		{"C-NS-HOST", ds1, []string{"--namespace", "github.com/acme"}, []string{"L1", "L4", "L7"}, false},
		{"C-NS-HOSTLESS", ds1, []string{"--namespace", "acme"}, []string{"L1", "L3", "L4", "L5", "L6", "L7"}, false},
		{"C-NS-BOUNDARY", ds1, []string{"--namespace", "acme/team"}, []string{"L4", "L5", "L9"}, false},
		{"C-REPO-ABSFOLDER", ds2, []string{"--repo", roots.a}, []string{"P2"}, true},
		{"C-NS-ABSFOLDER", ds2, []string{"--namespace", filepath.Dir(roots.a)}, []string{"P2"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			r := selRunOK(t, selArgs(tc.ds, nil, append([]string{"--format", "json"}, tc.flags...)...)...)
			if tc.ds2 {
				assert.Equal(t, tc.want, ds2Names(t, roots, r.stdout))
				return
			}
			assert.Equal(t, tc.want, reportLocationNames(t, r.stdout))
		})
	}
}

func hnrSelected(t *testing.T, stdout string) []string {
	t.Helper()
	var names []string
	for _, f := range selDecodeFindings(t, stdout) {
		for _, m := range f.Matches {
			for _, l := range m.Locations {
				if !l.HostRecorded {
					names = append(names, ds1Names[*l.Repository+" "+l.Path])
				}
			}
		}
	}
	return sortedNames(names...)
}

// C-HNR-REPO, C-HNR-REPO-SHORT, C-HNR-NS, C-HNR-NS-EMPTY, C-HNR-MARKER,
// C-HNR-NOTICE-* are split between this test and TestReportSelect_HNRNotice.
func TestReportSelect_HostNotRecorded(t *testing.T) {
	ds := seedDS1(t)
	tests := []struct {
		id      string
		flags   []string
		all     []string
		wantHNR []string
	}{
		{"C-HNR-REPO", []string{"--repo", "github.com/acme/api"}, []string{"L1", "L7"}, []string{"L7"}},
		{"C-HNR-REPO-SHORT", []string{"--repo", "acme/api"}, []string{"L1", "L3", "L7", "L8"}, []string{"L7", "L8"}},
		{"C-HNR-NS", []string{"--namespace", "acme/team"}, []string{"L4", "L5", "L9"}, []string{"L9"}},
		{"C-HNR-NS-EMPTY", []string{"--namespace", "github.com"}, []string{"L1", "L2", "L4", "L11"}, []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			r := selRunOK(t, selArgs(ds, nil, append([]string{"--format", "json"}, tc.flags...)...)...)
			assert.Equal(t, tc.all, reportLocationNames(t, r.stdout))
			assert.ElementsMatch(t, tc.wantHNR, hnrSelected(t, r.stdout))
		})
	}

	t.Run("C-HNR-MARKER", func(t *testing.T) {
		flags := []string{"--repo", "github.com/acme/api"}
		t.Run("human", func(t *testing.T) {
			r := selRunOK(t, selArgs(ds, nil, flags...)...)
			var h1 string
			for _, l := range humanLocationLines(r.stdout) {
				if strings.Contains(l, "h1.txt") {
					h1 = l
				}
			}
			require.NotEmpty(t, h1, "L7 is shown")
			assert.Contains(t, h1, "host not recorded")
			assert.NotContains(t, h1, "github.com/acme/api")
			assert.True(t, strings.HasPrefix(h1, "    acme/api  h1.txt"), h1)
		})
		t.Run("json", func(t *testing.T) {
			r := selRunOK(t, selArgs(ds, nil, append([]string{"--format", "json"}, flags...)...)...)
			found := false
			for _, f := range selDecodeFindings(t, r.stdout) {
				for _, m := range f.Matches {
					for _, l := range m.Locations {
						if l.Path == "h1.txt" {
							found = true
							assert.False(t, l.HostRecorded)
							require.NotNil(t, l.Repository)
							assert.Equal(t, "acme/api", *l.Repository)
						}
					}
				}
			}
			assert.True(t, found)
		})
		t.Run("sarif", func(t *testing.T) {
			r := selRunOK(t, selArgs(ds, nil, append([]string{"--format", "sarif"}, flags...)...)...)
			var rep sarif.Report
			require.NoError(t, json.Unmarshal([]byte(r.stdout), &rep))
			require.Len(t, rep.Runs, 1)
			fps := map[string]bool{}
			found := false
			for _, res := range rep.Runs[0].Results {
				require.NotNil(t, res.Properties)
				fp := res.PartialFingerprints[sarif.LocationFingerprintKey]
				assert.NotEmpty(t, fp)
				assert.False(t, fps[fp], "locationFingerprint is unique per location")
				fps[fp] = true
				if res.Locations[0].PhysicalLocation.ArtifactLocation.URI == "h1.txt" {
					found = true
					assert.Equal(t, "acme/api", res.Properties.Repository)
					require.NotNil(t, res.Properties.HostRecorded)
					assert.False(t, *res.Properties.HostRecorded)
				}
			}
			assert.True(t, found)
			assert.Len(t, rep.Runs[0].Results, 2, "L1 and L7")
		})
	})
}

// C-HNR-NOTICE-JSON, C-HNR-NOTICE-SARIF, C-HNR-NOTICE-PATHONLY, S-T013.
func TestReportSelect_HNRNotice(t *testing.T) {
	ds := seedDS1(t)
	const noticeText = "recorded without a host were not selected"

	tests := []struct {
		id     string
		flags  []string
		format string
		want3  bool
	}{
		{"C-HNR-NOTICE-JSON", []string{"--repo", "github.com/acme/api"}, "json", true},
		{"C-HNR-NOTICE-SARIF", []string{"--namespace", "acme/team"}, "sarif", true},
		{"C-HNR-NOTICE-PATHONLY", []string{"--path", "a.txt"}, "json", false},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			r := selRunOK(t, selArgs(ds, nil, append([]string{"--format", tc.format}, tc.flags...)...)...)
			require.True(t, jsonValid(r.stdout), "stdout is one document")
			assert.NotContains(t, r.stdout, noticeText, "stdout holds no notice")
			if !tc.want3 {
				assert.NotContains(t, r.stderr, noticeText)
				return
			}
			assert.Contains(t, r.stderr, "Note: 3 location(s) "+noticeText)
			assert.Contains(t, r.stderr, "titus report sources")
		})
	}

	t.Run("human-notice-on-stdout", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, "--repo", "github.com/acme/api")...)
		assert.Contains(t, r.stdout, "Note: 3 location(s) "+noticeText)
		assert.Empty(t, r.stderr)
	})
}

// C-PATH-ABS-WT, C-PATH-DISPLAYED, C-PATH-IDENTICAL-FOLDERS.
func TestReportSelect_PathCases(t *testing.T) {
	ds, roots := seedDS2(t)
	tests := []struct {
		id   string
		path string
		want []string
	}{
		{"C-PATH-ABS-WT", filepath.Join(roots.a, "config", "app.env"), []string{"P2"}},
		{"C-PATH-DISPLAYED", "config/app.env", []string{"P1", "P2"}},
		{"C-PATH-IDENTICAL-FOLDERS", filepath.Join(roots.x, "secrets.txt"), []string{"P3"}},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			r := selRunOK(t, selArgs(ds, nil, "--format", "json", "--path", tc.path)...)
			assert.Equal(t, tc.want, ds2Names(t, roots, r.stdout))
		})
	}
}

// C-PERLOC-SECOND-STORED, C-PERLOC-SARIF, C-PERLOC-HUMAN, C-ABSENT.
func TestReportSelect_PerLocation(t *testing.T) {
	ds := seedDS1(t)
	flags := []string{"--repo", "github.com/other/api"}

	t.Run("C-PERLOC-SECOND-STORED and C-ABSENT", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, append([]string{"--format", "json"}, flags...)...)...)
		fs := selDecodeFindings(t, r.stdout)
		require.Len(t, fs, 1, "only F1 is reported")
		require.Len(t, fs[0].Matches, 1)
		m := fs[0].Matches[0]
		assert.Equal(t, "sm-B1-1", m.StructuralID, "the finding is F1")
		assert.Equal(t, "settings/app.env", m.FilePath)
		require.Len(t, m.Locations, 1)
		assert.Equal(t, "settings/app.env", m.Locations[0].Path)
		require.NotNil(t, m.Locations[0].Repository)
		assert.Equal(t, "github.com/other/api", *m.Locations[0].Repository)
	})
	t.Run("C-PERLOC-SARIF", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, append([]string{"--format", "sarif"}, flags...)...)...)
		var rep sarif.Report
		require.NoError(t, json.Unmarshal([]byte(r.stdout), &rep))
		require.Len(t, rep.Runs, 1)
		require.Len(t, rep.Runs[0].Results, 1)
		res := rep.Runs[0].Results[0]
		assert.Equal(t, "settings/app.env", res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		assert.Equal(t, "github.com/other/api", res.Properties.Repository)
	})
	t.Run("C-PERLOC-HUMAN", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, flags...)...)
		lines := humanLocationLines(r.stdout)
		require.Len(t, lines, 1)
		assert.Contains(t, lines[0], "github.com/other/api  settings/app.env")
		assert.NotContains(t, r.stdout, "github.com/acme/api")
		assert.NotContains(t, r.stdout, "config/app.env")
	})
}

type selSummaryDoc struct {
	TotalFindings int `json:"total_findings"`
	TotalMatches  int `json:"total_matches"`
}

func selRunSummary(t *testing.T, ds string, flags ...string) (selSummaryDoc, cliResult) {
	t.Helper()
	r := selRunOK(t, selArgs(ds, []string{"summary"}, append([]string{"--format", "json"}, flags...)...)...)
	var s selSummaryDoc
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &s))
	return s, r
}

// C-SUMMARY-NOINFLATE, C-SUMMARY-RETAINED.
func TestReportSelect_SummaryCounts(t *testing.T) {
	ds := seedDS1(t)
	t.Run("C-SUMMARY-NOINFLATE", func(t *testing.T) {
		s, _ := selRunSummary(t, ds, "--namespace", "github.com")
		assert.Equal(t, selSummaryDoc{TotalFindings: 3, TotalMatches: 3}, s)
	})
	t.Run("C-SUMMARY-RETAINED", func(t *testing.T) {
		s, _ := selRunSummary(t, ds, "--repo", "github.com/other/api")
		assert.Equal(t, selSummaryDoc{TotalFindings: 1, TotalMatches: 1}, s)
	})
}

// C-ABBREV-AFTER: a match past the third is abbreviated to location lines
// unfiltered, and shown in full when the selection leaves it as the first.
func TestReportSelect_AbbreviationAfterSelection(t *testing.T) {
	ds, lastBlob := seedDS5(t)
	t.Run("unfiltered abbreviates match 4", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil)...)
		assert.Contains(t, r.stdout, "Match 3/4")
		assert.NotContains(t, r.stdout, "Match 4/4")
		assert.NotContains(t, r.stdout, lastBlob.Hex())
		assert.Contains(t, r.stdout, "github.com/other/api  f4.txt")
	})
	t.Run("C-ABBREV-AFTER", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, "--repo", "github.com/other/api")...)
		assert.Contains(t, r.stdout, "Match 1/1")
		assert.Contains(t, r.stdout, "Blob: "+lastBlob.Hex())
		assert.Contains(t, r.stdout, "sel_shared", "the snippet is shown in full")
		assert.NotContains(t, r.stdout, "Match 2/")
		assert.NotContains(t, r.stdout, "github.com/acme/api")
	})
}

// C-REJECTED.
func TestReportSelect_RejectedFindings(t *testing.T) {
	ds := seedDS1(t, "B3")
	flags := []string{"--format", "json", "--namespace", "github.com/acme"}
	t.Run("hidden by default", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, flags...)...)
		assert.Equal(t, []string{"L1", "L7"}, reportLocationNames(t, r.stdout))
	})
	t.Run("--show-rejected", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, append(flags, "--show-rejected")...)...)
		assert.Equal(t, []string{"L1", "L4", "L7"}, reportLocationNames(t, r.stdout))
	})
}

// S-T006 and R17 item 6: an invalid selector fails before the datastore is
// opened and never falls back to an unfiltered report.
func TestReportSelect_InvalidSelectorNeverUnfiltered(t *testing.T) {
	real := seedDS1(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist.ds")
	tests := []struct {
		id    string
		flags []string
		flag  string
	}{
		{"C-INVALID-EMPTY", []string{"--repo", ""}, "--repo"},
		{"blank-repo", []string{"--repo", "   "}, "--repo"},
		{"empty-namespace", []string{"--namespace", ""}, "--namespace"},
		{"trailing-slash-namespace", []string{"--namespace", "github.com/"}, "--namespace"},
		{"empty-segment-namespace", []string{"--namespace", "a//b"}, "--namespace"},
		{"empty-path", []string{"--path", ""}, "--path"},
	}
	for _, tc := range tests {
		for _, sub := range [][]string{nil, {"summary"}} {
			name := tc.id + "/report"
			if sub != nil {
				name = tc.id + "/summary"
			}
			t.Run(name, func(t *testing.T) {
				r := runRootSplit(t, selArgs(missing, sub, tc.flags...)...)
				require.Error(t, r.err)
				assert.Contains(t, r.stderr, tc.flag)
				assert.NotContains(t, r.stderr, "does-not-exist.ds", "rejected before the datastore opens")
				assert.NotContains(t, r.stdout, "Finding ")
				assert.NotContains(t, r.stdout, "Total:")

				r = runRootSplit(t, selArgs(real, sub, tc.flags...)...)
				require.Error(t, r.err)
				assert.NotContains(t, r.stdout, "Finding ")
				assert.NotContains(t, r.stdout, "Total:")
				assert.NotContains(t, r.stdout, "Rule:")
			})
		}
	}
}

// C-NOMATCH-HUMAN, C-NOMATCH-JSON, C-NOMATCH-SARIF.
func TestReportSelect_NoMatchNotice(t *testing.T) {
	ds := seedDS1(t)
	const notice = "No findings matched the selection."
	flags := []string{"--path", "no/such/file"}

	t.Run("C-NOMATCH-HUMAN", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, flags...)...)
		assert.NotContains(t, r.stdout, "Finding ")
		assert.Contains(t, r.stdout, notice)
		assert.Contains(t, r.stdout, "titus report sources")

		r = selRunOK(t, selArgs(ds, []string{"summary"}, flags...)...)
		assert.Contains(t, r.stdout, "No findings.")
		assert.Contains(t, r.stdout, notice)
		s, jr := selRunSummary(t, ds, flags...)
		assert.Equal(t, selSummaryDoc{}, s)
		assert.Contains(t, jr.stderr, notice)
	})
	t.Run("C-NOMATCH-JSON", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, append([]string{"--format", "json"}, flags...)...)...)
		assert.Empty(t, selDecodeFindings(t, r.stdout))
		assert.NotContains(t, r.stdout, notice)
		assert.Contains(t, r.stderr, notice)
		assert.Contains(t, r.stderr, "titus report sources")
	})
	t.Run("C-NOMATCH-SARIF", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, append([]string{"--format", "sarif"}, flags...)...)...)
		var rep sarif.Report
		require.NoError(t, json.Unmarshal([]byte(r.stdout), &rep))
		require.Len(t, rep.Runs, 1)
		assert.Empty(t, rep.Runs[0].Results)
		assert.Contains(t, r.stderr, notice)
	})
}

// R17 item 4: a repository recorded as typed ("api/") is selected by the
// value the report shows, and values listed by `report sources` select.
func TestReportSelect_RecordedAsTypedEndToEnd(t *testing.T) {
	root := filepath.Join(t.TempDir(), "scan")
	b := newDSBuilder(t)
	b.finding("T1")
	b.localLoc("T1", "api/", filepath.Join(root, "api"), "c.txt")
	ds := b.done()

	const notice = "No findings matched the selection."
	t.Run("--repo api/ selects", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, "--format", "json", "--repo", "api/")...)
		assert.Len(t, selDecodeFindings(t, r.stdout), 1)
	})
	t.Run("--repo api gives the no-match notice", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, "--format", "json", "--repo", "api")...)
		assert.Empty(t, selDecodeFindings(t, r.stdout))
		assert.Contains(t, r.stderr, notice)
	})
	t.Run("--namespace api selects", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, "--format", "json", "--namespace", "api")...)
		assert.Len(t, selDecodeFindings(t, r.stdout), 1)
	})
	t.Run("values copied from sources select", func(t *testing.T) {
		src := selRunOK(t, selArgs(ds, []string{"sources"}, "--format", "json")...)
		var doc struct {
			Repos      []struct{ Value string } `json:"repos"`
			Namespaces []struct{ Value string } `json:"namespaces"`
			Paths      []struct{ Value string } `json:"paths"`
		}
		require.NoError(t, json.Unmarshal([]byte(src.stdout), &doc))
		require.NotEmpty(t, doc.Repos)
		require.NotEmpty(t, doc.Namespaces)
		for _, v := range doc.Repos {
			r := selRunOK(t, selArgs(ds, nil, "--format", "json", "--repo", v.Value)...)
			assert.Len(t, selDecodeFindings(t, r.stdout), 1, "--repo %q", v.Value)
		}
		for _, v := range doc.Namespaces {
			r := selRunOK(t, selArgs(ds, nil, "--format", "json", "--namespace", v.Value)...)
			assert.Len(t, selDecodeFindings(t, r.stdout), 1, "--namespace %q", v.Value)
		}
		for _, v := range doc.Paths {
			r := selRunOK(t, selArgs(ds, nil, "--format", "json", "--path", v.Value)...)
			assert.Len(t, selDecodeFindings(t, r.stdout), 1, "--path %q", v.Value)
		}
	})
}
