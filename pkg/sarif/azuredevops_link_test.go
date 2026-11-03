package sarif

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/types"
)

const adoSHA = "7d0e8151234567890abcdef1234567890abcdef1"

func TestAddResultForOccurrence_CommitURL_AzureDevOps(t *testing.T) {
	tests := []struct {
		name, host, repo, want string
	}{
		{"dev.azure.com", "dev.azure.com", "dev.azure.com/acme/proj/_git/repo",
			"https://dev.azure.com/acme/proj/_git/repo/commit/" + adoSHA},
		{"acme.visualstudio.com", "acme.visualstudio.com", "acme.visualstudio.com/proj/_git/repo",
			"https://dev.azure.com/acme/proj/_git/repo/commit/" + adoSHA},
		{"ssh.dev.azure.com", "ssh.dev.azure.com", "ssh.dev.azure.com/v3/acme/proj/repo",
			"https://dev.azure.com/acme/proj/_git/repo/commit/" + adoSHA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReport()
			r.AddResultForOccurrence(occurrenceMatch(), gitOccsForLink(tt.host, tt.repo, adoSHA)[0], nil)
			assert.Equal(t, tt.want, r.Runs[0].Results[0].Properties.CommitURL)
			assert.Equal(t, tt.want, resultPropsJSON(t, r)["commit_url"])
			assert.Equal(t, adoSHA, resultPropsJSON(t, r)["commit"], "the link carries the recorded commit")
		})
	}
}

func TestAddResultForOccurrence_NoCommitURL_AzureDevOps(t *testing.T) {
	const repo = "dev.azure.com/acme/proj/_git/repo"
	wt := gitOccsForLink("dev.azure.com", repo, adoSHA)[0]
	wt.WorkingTree = true
	tests := map[string]types.Occurrence{
		"non-ADO host":        gitOccsForLink("gitea.example.com", "gitea.example.com/acme/proj/_git/repo", adoSHA)[0],
		"lookalike host":      gitOccsForLink("dev.azure.com.evil", "dev.azure.com.evil/acme/proj/_git/repo", adoSHA)[0],
		"two vs labels":       gitOccsForLink("a.b.visualstudio.com", "a.b.visualstudio.com/proj/_git/repo", adoSHA)[0],
		"no commit":           gitOccsForLink("dev.azure.com", repo, "")[0],
		"working tree":        wt,
		"no _git":             gitOccsForLink("dev.azure.com", "dev.azure.com/acme/proj/repo", adoSHA)[0],
		"legacy not recorded": {Kind: "git", Repository: repo, Path: "h1.txt", Commit: adoSHA},
	}
	for name, o := range tests {
		t.Run(name, func(t *testing.T) {
			r := NewReport()
			r.AddResultForOccurrence(occurrenceMatch(), o, nil)
			assert.Empty(t, r.Runs[0].Results[0].Properties.CommitURL)
			assert.NotContains(t, resultPropsJSON(t, r), "commit_url")
		})
	}
}

// Each location of a blob links its own recorded commit.
func TestAddResultForOccurrence_CommitURL_AzureDevOpsPerLocationCommit(t *testing.T) {
	c1, c2 := strings.Repeat("1", 40), strings.Repeat("2", 40)
	r := NewReport()
	for _, o := range gitOccsForLink("dev.azure.com", "dev.azure.com/acme/proj/_git/repo", c1, c2) {
		r.AddResultForOccurrence(occurrenceMatch(), o, nil)
	}
	require.Len(t, r.Runs[0].Results, 2)
	assert.Equal(t, "https://dev.azure.com/acme/proj/_git/repo/commit/"+c1, r.Runs[0].Results[0].Properties.CommitURL)
	assert.Equal(t, "https://dev.azure.com/acme/proj/_git/repo/commit/"+c2, r.Runs[0].Results[1].Properties.CommitURL)
}

// Adding the link must not change the fingerprint code scanning has seen.
func TestAddResultForOccurrence_CommitURL_AzureDevOpsFingerprintInvariant(t *testing.T) {
	linked := gitOccsForLink("dev.azure.com", "dev.azure.com/acme/proj/_git/repo", adoSHA)[0]
	unlinked := linked
	unlinked.Host = ""
	a, b := NewReport(), NewReport()
	a.AddResultForOccurrence(occurrenceMatch(), linked, nil)
	b.AddResultForOccurrence(occurrenceMatch(), unlinked, nil)
	require.NotEmpty(t, a.Runs[0].Results[0].Properties.CommitURL)
	require.Empty(t, b.Runs[0].Results[0].Properties.CommitURL)
	assert.Equal(t, a.Runs[0].Results[0].PartialFingerprints[LocationFingerprintKey],
		b.Runs[0].Results[0].PartialFingerprints[LocationFingerprintKey])
}
