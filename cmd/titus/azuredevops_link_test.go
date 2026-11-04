package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/types"
)

// adoLinkCases pair each Azure DevOps clone form with the link it must print.
// Repository identities are the ones repoid records for that clone form. The
// scan, report and enum commands all print through writeLocationLines and
// toJSONLocations, so these two helpers cover every command.
var adoLinkCases = []struct {
	name string
	occ  types.Occurrence
	want string
}{
	{"dev.azure.com", linkOcc("dev.azure.com", "acme/proj/_git/repo", "src/a.go", linkSHA1),
		"https://dev.azure.com/acme/proj/_git/repo/commit/" + linkSHA1},
	{"acme.visualstudio.com", linkOcc("acme.visualstudio.com", "proj/_git/repo", "src/a.go", linkSHA1),
		"https://dev.azure.com/acme/proj/_git/repo/commit/" + linkSHA1},
	{"ssh.dev.azure.com", linkOcc("ssh.dev.azure.com", "v3/acme/proj/repo", "src/a.go", linkSHA1),
		"https://dev.azure.com/acme/proj/_git/repo/commit/" + linkSHA1},
}

// adoNoLinkCases are locations that must not get an Azure DevOps link.
var adoNoLinkCases = []struct {
	name string
	occ  types.Occurrence
}{
	{"non-ADO host", linkOcc("gitea.example.com", "acme/proj/_git/repo", "src/a.go", linkSHA1)},
	{"lookalike host", linkOcc("dev.azure.com.evil", "acme/proj/_git/repo", "src/a.go", linkSHA1)},
	{"commitless ADO location", linkNoCommitOcc("dev.azure.com", "acme/proj/_git/repo", "src/a.go")},
	{"working tree ADO location", linkWorkingTreeOcc("dev.azure.com", "acme/proj/_git/repo", "src/a.go")},
	{"ADO identity without _git", linkOcc("dev.azure.com", "acme/proj/repo", "src/a.go", linkSHA1)},
	{"legacy ADO row, host not recorded", types.Occurrence{
		Kind: "git", Repository: "dev.azure.com/acme/proj/_git/repo", Path: "src/a.go", Commit: linkSHA1, CommitDate: commitDate,
	}},
}

func TestWriteLocationLines_AzureDevOpsCommitLink(t *testing.T) {
	for _, tc := range adoLinkCases {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.occ
			var buf bytes.Buffer
			writeLocationLines(&buf, 3, []types.Occurrence{o}, nil)
			lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
			require.Len(t, lines, 2, "location line then link line: %q", buf.String())
			assert.Equal(t, "    "+o.Repository+"  src/a.go:3  0123456  2024-05-01", lines[0])
			assert.Equal(t, "      "+tc.want, lines[1], "six-space indent, exact URL")
		})
	}

	t.Run("link line follows its own location line among mixed locations", func(t *testing.T) {
		ado := adoLinkCases[0]
		vs := adoLinkCases[1]
		control := adoNoLinkCases[0]
		var buf bytes.Buffer
		writeLocationLines(&buf, 3, []types.Occurrence{ado.occ, control.occ, vs.occ}, nil)
		lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
		require.Len(t, lines, 5, "%q", buf.String())
		assert.Contains(t, lines[0], "dev.azure.com/acme/proj/_git/repo")
		assert.Equal(t, "      "+ado.want, lines[1])
		assert.Contains(t, lines[2], "gitea.example.com/")
		assert.Contains(t, lines[3], "acme.visualstudio.com/proj/_git/repo")
		assert.Equal(t, "      "+vs.want, lines[4])
	})
}

func TestWriteLocationLines_AzureDevOpsNoLink(t *testing.T) {
	for _, tc := range adoNoLinkCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeLocationLines(&buf, 3, []types.Occurrence{tc.occ}, nil)
			assert.Equal(t, 1, strings.Count(buf.String(), "\n"), "only the location line: %q", buf.String())
			assert.NotContains(t, buf.String(), "https://")
		})
	}
}

func TestToJSONLocations_AzureDevOpsCommitURL(t *testing.T) {
	for _, tc := range adoLinkCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(toJSONLocations(locationMatch("x"), []types.Occurrence{tc.occ}))
			require.NoError(t, err)
			var locs []map[string]any
			require.NoError(t, json.Unmarshal(data, &locs))
			require.Len(t, locs, 1)
			assert.Equal(t, tc.want, locs[0]["commit_url"])
			assert.Equal(t, linkSHA1, locs[0]["commit"], "the link carries the recorded commit")
		})
	}
}

func TestToJSONLocations_AzureDevOpsNoLinkIsNull(t *testing.T) {
	for _, tc := range adoNoLinkCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(toJSONLocations(locationMatch("x"), []types.Occurrence{tc.occ}))
			require.NoError(t, err)
			var locs []map[string]any
			require.NoError(t, json.Unmarshal(data, &locs))
			require.Len(t, locs, 1)
			got, present := locs[0]["commit_url"]
			assert.True(t, present, "commit_url key is always present")
			assert.Nil(t, got, "no link is JSON null")
		})
	}
}

// Each location of a blob links its own recorded commit.
func TestToJSONLocations_AzureDevOpsPerLocationCommit(t *testing.T) {
	locs := toJSONLocations(locationMatch("x"), []types.Occurrence{
		linkOcc("dev.azure.com", "acme/proj/_git/repo", "src/a.go", linkSHA1),
		linkOcc("dev.azure.com", "acme/proj/_git/repo", "src/a.go", linkSHA2),
	})
	require.Len(t, locs, 2)
	require.NotNil(t, locs[0].CommitURL)
	require.NotNil(t, locs[1].CommitURL)
	assert.Equal(t, "https://dev.azure.com/acme/proj/_git/repo/commit/"+linkSHA1, *locs[0].CommitURL)
	assert.Equal(t, "https://dev.azure.com/acme/proj/_git/repo/commit/"+linkSHA2, *locs[1].CommitURL)
}
