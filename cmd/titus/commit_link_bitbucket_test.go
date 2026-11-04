package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bitbucketLinkCases pair occurrences with the commit link they must produce
// ("" is no link). One table drives the JSON and SARIF tests.
var bitbucketLinkCases = []struct {
	name string
	occ  types.Occurrence
	want string
}{
	{"bitbucket.org", linkOcc("bitbucket.org", "acme/api", "config.yml", linkSHA1), "https://bitbucket.org/acme/api/commits/" + linkSHA1},
	{"bitbucket server host", linkOcc("bitbucket.corp.example", "acme/api", "config.yml", linkSHA1), ""},
	{"bitbucket.org.evil lookalike host", linkOcc("bitbucket.org.evil.example", "acme/api", "config.yml", linkSHA1), ""},
	{"no commit", linkNoCommitOcc("bitbucket.org", "acme/api", "config.yml"), ""},
	{"working tree", linkWorkingTreeOcc("bitbucket.org", "acme/api", "config.yml"), ""},
}

// TestScanE2E_BitbucketCommitURL: a --git scan of a repository whose origin is
// on bitbucket.org links its committed location to the HEAD commit, whatever
// the origin spelling; no origin, Bitbucket Server, other hosts and lookalike
// hosts get null.
func TestScanE2E_BitbucketCommitURL(t *testing.T) {
	tests := []struct {
		name, origin string
		linked       bool
	}{
		{"https origin", "https://bitbucket.org/acme/api.git", true},
		{"ssh origin", "git@bitbucket.org:acme/api.git", true},
		{"https origin with userinfo", "https://user@bitbucket.org/acme/api.git", true},
		{"no origin", "", false},
		{"bitbucket server", "https://bitbucket.corp.example/scm/acme/api.git", false},
		{"gitea origin", "https://gitea.example.com/acme/api.git", false},
		{"lookalike host", "https://bitbucket.org.evil.example/acme/api.git", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := filepath.Join(t.TempDir(), "api")
			gitRepoForTest(t, repo, tc.origin, map[string]string{"config.yml": locTestSecret})
			head, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
			require.NoError(t, err)
			sha := strings.TrimSpace(string(head))
			require.Len(t, sha, 40)

			got := scanJSONMatches(t, scanForTest(t, repo, tempDatastore(t), "json", true))
			require.Len(t, got, 1)
			committed := 0
			for _, l := range got[0].Locations {
				if l.Commit == nil {
					assert.Nil(t, l.CommitURL, "a location with no commit has no link")
					continue
				}
				committed++
				assert.Equal(t, strPtr(sha), l.Commit)
				if tc.linked {
					assert.Equal(t, strPtr("https://bitbucket.org/acme/api/commits/"+sha), l.CommitURL)
				} else {
					assert.Nil(t, l.CommitURL)
				}
			}
			assert.Equal(t, 1, committed)
		})
	}
}

// Encoder-level check of the scan JSON output over occurrences built the way
// the stores build them.
func TestOutputMatches_BitbucketCommitURL(t *testing.T) {
	s := store.NewMemory()
	blobID := types.ComputeBlobID([]byte(locTestSecret))
	require.NoError(t, s.AddOccurrences(blobID, []types.Occurrence{
		linkOcc("bitbucket.org", "acme/api", "config.yml", linkSHA1),
	}))
	match := &types.Match{BlobID: blobID, RuleID: locTestRuleID, RuleName: "Synthetic Rule 1"}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	require.NoError(t, outputMatches(cmd, s, []*types.Match{match}))
	got := scanJSONMatches(t, out.Bytes())
	require.Len(t, got, 1)
	require.Len(t, got[0].Locations, 1)
	assert.Equal(t, strPtr("https://bitbucket.org/acme/api/commits/"+linkSHA1), got[0].Locations[0].CommitURL)
}

func TestToJSONLocations_BitbucketCommitURL(t *testing.T) {
	for _, tc := range bitbucketLinkCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(toJSONLocations(locationMatch("x"), []types.Occurrence{tc.occ}))
			require.NoError(t, err)
			var locs []map[string]any
			require.NoError(t, json.Unmarshal(data, &locs))
			require.Len(t, locs, 1)
			got, present := locs[0]["commit_url"]
			require.True(t, present, "commit_url key is always present")
			if tc.want == "" {
				assert.Nil(t, got)
			} else {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestWriteSARIF_BitbucketCommitURLProperty(t *testing.T) {
	for _, tc := range bitbucketLinkCases {
		t.Run(tc.name, func(t *testing.T) {
			results := sarifResultsFor(t, []types.Occurrence{tc.occ})
			require.Len(t, results, 1)
			assert.Equal(t, tc.want, results[0].Properties.CommitURL)
		})
	}
}

func TestWriteLocationLines_BitbucketCommitLink(t *testing.T) {
	var buf bytes.Buffer
	writeLocationLines(&buf, 3, []types.Occurrence{
		linkOcc("bitbucket.org", "acme/api", "a.yml", linkSHA1),
		linkOcc("bitbucket.corp.example", "acme/web", "b.yml", linkSHA2),
	}, nil)
	assert.Equal(t, ""+
		"    bitbucket.org/acme/api  a.yml:3  0123456  2024-05-01\n"+
		"      https://bitbucket.org/acme/api/commits/"+linkSHA1+"\n"+
		"    bitbucket.corp.example/acme/web  b.yml:3  fedcba9  2024-05-01\n",
		buf.String())
}

// The report command reads a datastore: bitbucket.org location links in
// json, sarif and human output; the Bitbucket Server location does not.
func TestReportBitbucketCommitURL(t *testing.T) {
	b := newDSBuilder(t)
	b.finding("BB1")
	b.remoteLoc("BB1", "bitbucket.org", "acme/api", "config.yml")
	b.finding("BB2")
	b.remoteLoc("BB2", "bitbucket.corp.example", "acme/web", "app.env")
	ds := b.done()
	want := "https://bitbucket.org/acme/api/commits/" + "0000000000000000000000000000000000000001"

	t.Run("json", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, "--format", "json")...)
		got := map[string]*string{}
		for _, f := range selDecodeFindings(t, r.stdout) {
			for _, m := range f.Matches {
				for _, l := range m.Locations {
					got[*l.Repository] = l.CommitURL
				}
			}
		}
		assert.Equal(t, map[string]*string{
			"bitbucket.org/acme/api":          strPtr(want),
			"bitbucket.corp.example/acme/web": nil,
		}, got)
	})

	t.Run("sarif", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil, "--format", "sarif")...)
		var rep struct {
			Runs []struct {
				Results []struct {
					Properties map[string]any `json:"properties"`
				} `json:"results"`
			} `json:"runs"`
		}
		require.NoError(t, json.Unmarshal([]byte(r.stdout), &rep))
		require.Len(t, rep.Runs, 1)
		got := map[string]any{}
		for _, res := range rep.Runs[0].Results {
			repo, _ := res.Properties["repository"].(string)
			got[repo] = res.Properties["commit_url"]
		}
		assert.Equal(t, map[string]any{
			"bitbucket.org/acme/api":          want,
			"bitbucket.corp.example/acme/web": nil,
		}, got)
	})

	t.Run("human", func(t *testing.T) {
		r := selRunOK(t, selArgs(ds, nil)...)
		lines := strings.Split(r.stdout, "\n")
		var links []string
		for i, line := range lines {
			if strings.Contains(line, "https://") {
				assert.Equal(t, "      "+want, line, "6-space indent, exact link")
				require.Positive(t, i)
				assert.Contains(t, lines[i-1], "bitbucket.org/acme/api", "link follows its location line")
				links = append(links, line)
			}
		}
		assert.Len(t, links, 1, "only the bitbucket.org location is linked")
	})
}

// AC: no Bitbucket remote scan or enumerator is added.
func TestNoBitbucketSubcommand(t *testing.T) {
	for _, parent := range []*cobra.Command{rootCmd, enumCmd, scanCmd} {
		for _, c := range parent.Commands() {
			assert.NotContains(t, strings.ToLower(c.Name()), "bitbucket", "%s has subcommand %s", parent.Name(), c.Name())
			for _, a := range c.Aliases {
				assert.NotContains(t, strings.ToLower(a), "bitbucket")
			}
		}
	}
}
