package commitlink

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Every Azure DevOps clone form links to the one canonical commit page.
// Hosts and identities are the ones repoid.NormalizeHost records for each
// clone form (https, ssh, and the legacy visualstudio.com hosts).
func TestURL_AzureDevOps(t *testing.T) {
	tests := []struct {
		name string
		host string
		path string
		sha  string
		want string
	}{
		{"dev.azure.com", "dev.azure.com", "org/proj/_git/repo", sha40,
			"https://dev.azure.com/org/proj/_git/repo/commit/" + sha40},
		{"dev.azure.com sha256 object format", "dev.azure.com", "org/proj/_git/repo", sha64,
			"https://dev.azure.com/org/proj/_git/repo/commit/" + sha64},
		{"project and repo case is preserved", "dev.azure.com", "Org/Proj/_git/My.Repo-2", sha40,
			"https://dev.azure.com/Org/Proj/_git/My.Repo-2/commit/" + sha40},
		{"visualstudio.com org is the subdomain", "acme.visualstudio.com", "proj/_git/repo", sha40,
			"https://dev.azure.com/acme/proj/_git/repo/commit/" + sha40},
		{"visualstudio.com hyphenated org with digits", "my-org2.visualstudio.com", "Proj/_git/Repo", sha64,
			"https://dev.azure.com/my-org2/Proj/_git/Repo/commit/" + sha64},
		{"dev.azure.com project-less", "dev.azure.com", "org/_git/repo", sha40,
			"https://dev.azure.com/org/_git/repo/commit/" + sha40},
		{"visualstudio.com project-less", "acme.visualstudio.com", "_git/repo", sha40,
			"https://dev.azure.com/acme/_git/repo/commit/" + sha40},
		{"visualstudio.com DefaultCollection", "acme.visualstudio.com", "DefaultCollection/proj/_git/repo", sha40,
			"https://dev.azure.com/acme/proj/_git/repo/commit/" + sha40},
		{"visualstudio.com defaultcollection is case-insensitive", "acme.visualstudio.com", "defaultcollection/proj/_git/repo", sha40,
			"https://dev.azure.com/acme/proj/_git/repo/commit/" + sha40},
		{"visualstudio.com DefaultCollection project-less", "acme.visualstudio.com", "DefaultCollection/_git/repo", sha40,
			"https://dev.azure.com/acme/_git/repo/commit/" + sha40},
		{"ssh.dev.azure.com v3 identity", "ssh.dev.azure.com", "v3/org/proj/repo", sha40,
			"https://dev.azure.com/org/proj/_git/repo/commit/" + sha40},
		{"vs-ssh.visualstudio.com v3 identity", "vs-ssh.visualstudio.com", "v3/org/proj/repo", sha40,
			"https://dev.azure.com/org/proj/_git/repo/commit/" + sha40},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, URL(gitOcc(tt.host, tt.host+"/"+tt.path, tt.sha)))
		})
	}
}

// The recorded commit flows through types.OccurrencesOf unchanged, one link
// per location; the working-tree location of the same blob has none.
func TestURL_AzureDevOps_FromOccurrencesOf(t *testing.T) {
	c1, c2 := strings.Repeat("1", 40), strings.Repeat("2", 40)
	occs := types.OccurrencesOf(types.GitProvenance{
		RepoPath: "dev.azure.com/org/proj/_git/repo", Host: "dev.azure.com", RemoteIdentity: true, BlobPath: "a.env",
		Locations: []types.GitLocation{
			{Path: "a.env", Commit: &types.CommitMetadata{CommitID: c1}},
			{Path: "b.env", Commit: &types.CommitMetadata{CommitID: c2}},
			{Path: "c.env", WorkingTree: true},
		},
	})
	require.Len(t, occs, 3)
	assert.Equal(t, "https://dev.azure.com/org/proj/_git/repo/commit/"+c1, URL(occs[0]))
	assert.Equal(t, "https://dev.azure.com/org/proj/_git/repo/commit/"+c2, URL(occs[1]))
	assert.Equal(t, "", URL(occs[2]), "working-tree location has no link")
}

func TestURL_AzureDevOps_NoLink(t *testing.T) {
	wt := gitOcc("dev.azure.com", "dev.azure.com/org/proj/_git/repo", sha40)
	wt.WorkingTree = true
	tests := []struct {
		name string
		occ  types.Occurrence
	}{
		// Not an Azure DevOps host.
		{"github host with ado-shaped path", gitOcc("github.com", "github.com/org/proj/_git/repo", sha40)},
		{"gitea host", gitOcc("gitea.example.com", "gitea.example.com/org/proj/_git/repo", sha40)},
		{"bitbucket host", gitOcc("bitbucket.org", "bitbucket.org/org/proj/_git/repo", sha40)},
		{"ado server on-prem", gitOcc("tfs.corp.example", "tfs.corp.example/DefaultCollection/proj/_git/repo", sha40)},
		{"unregistered host naming dev.azure.com in the path", gitOcc("evil.com", "evil.com/dev.azure.com/org/proj/_git/repo", sha40)},

		// Lookalike hosts.
		{"suffix lookalike dev.azure.com.evil", gitOcc("dev.azure.com.evil", "dev.azure.com.evil/org/proj/_git/repo", sha40)},
		{"prefix lookalike evildev.azure.com", gitOcc("evildev.azure.com", "evildev.azure.com/org/proj/_git/repo", sha40)},
		{"subdomain of dev.azure.com", gitOcc("a.dev.azure.com", "a.dev.azure.com/org/proj/_git/repo", sha40)},
		{"bare visualstudio.com has no org label", gitOcc("visualstudio.com", "visualstudio.com/proj/_git/repo", sha40)},
		{"two labels before visualstudio.com", gitOcc("a.b.visualstudio.com", "a.b.visualstudio.com/proj/_git/repo", sha40)},
		{"visualstudio.com.evil", gitOcc("visualstudio.com.evil", "visualstudio.com.evil/proj/_git/repo", sha40)},
		{"acme.visualstudio.com.evil", gitOcc("acme.visualstudio.com.evil", "acme.visualstudio.com.evil/proj/_git/repo", sha40)},
		{"notvisualstudio.com", gitOcc("notvisualstudio.com", "notvisualstudio.com/proj/_git/repo", sha40)},
		{"evilvisualstudio.com", gitOcc("evilvisualstudio.com", "evilvisualstudio.com/proj/_git/repo", sha40)},
		{"ssh.dev.azure.com.evil", gitOcc("ssh.dev.azure.com.evil", "ssh.dev.azure.com.evil/v3/org/proj/repo", sha40)},
		{"port in host", gitOcc("dev.azure.com:443", "dev.azure.com:443/org/proj/_git/repo", sha40)},
		{"uppercase host", gitOcc("DEV.AZURE.COM", "DEV.AZURE.COM/org/proj/_git/repo", sha40)},

		// Host and repository disagree.
		{"repository from another host", gitOcc("dev.azure.com", "gitlab.com/org/proj/_git/repo", sha40)},
		{"repository host only prefixed by dev.azure.com", gitOcc("dev.azure.com", "dev.azure.com.evil/org/proj/_git/repo", sha40)},
		{"repository without host prefix", gitOcc("dev.azure.com", "org/proj/_git/repo", sha40)},
		{"repository is host prefix only", gitOcc("dev.azure.com", "dev.azure.com/", sha40)},
		{"visualstudio.com repository from another org host", gitOcc("acme.visualstudio.com", "other.visualstudio.com/proj/_git/repo", sha40)},

		// Wrong shape for the host.
		{"dev.azure.com DefaultCollection is not a dev.azure.com segment", gitOcc("dev.azure.com", "dev.azure.com/org/DefaultCollection/proj/_git/repo", sha40)},
		{"dev.azure.com without _git", gitOcc("dev.azure.com", "dev.azure.com/org/proj/repo", sha40)},
		{"dev.azure.com _git in the wrong segment", gitOcc("dev.azure.com", "dev.azure.com/_git/org/proj/repo", sha40)},
		{"dev.azure.com org only", gitOcc("dev.azure.com", "dev.azure.com/org", sha40)},
		{"dev.azure.com extra segment", gitOcc("dev.azure.com", "dev.azure.com/org/proj/_git/repo/extra", sha40)},
		{"dev.azure.com _git without repo", gitOcc("dev.azure.com", "dev.azure.com/org/proj/_git", sha40)},
		{"visualstudio.com DefaultCollection with extra segments", gitOcc("acme.visualstudio.com", "acme.visualstudio.com/DefaultCollection/proj/_git/repo/extra", sha40)},
		{"visualstudio.com 4 segments without DefaultCollection", gitOcc("acme.visualstudio.com", "acme.visualstudio.com/other/proj/_git/repo", sha40)},
		{"visualstudio.com DefaultCollection without repo", gitOcc("acme.visualstudio.com", "acme.visualstudio.com/DefaultCollection/proj/_git", sha40)},
		{"visualstudio.com _git without repo", gitOcc("acme.visualstudio.com", "acme.visualstudio.com/proj/_git", sha40)},
		{"visualstudio.com without _git", gitOcc("acme.visualstudio.com", "acme.visualstudio.com/proj/repo", sha40)},
		{"visualstudio.com extra segment", gitOcc("acme.visualstudio.com", "acme.visualstudio.com/proj/_git/repo/extra", sha40)},
		{"visualstudio.com with the dev.azure.com org segment", gitOcc("acme.visualstudio.com", "acme.visualstudio.com/org/proj/_git/repo", sha40)},
		{"ssh without v3", gitOcc("ssh.dev.azure.com", "ssh.dev.azure.com/v2/org/proj/repo", sha40)},
		{"ssh with https-style path", gitOcc("ssh.dev.azure.com", "ssh.dev.azure.com/org/proj/_git/repo", sha40)},
		{"ssh missing repo", gitOcc("ssh.dev.azure.com", "ssh.dev.azure.com/v3/org/proj", sha40)},
		{"ssh extra segment", gitOcc("ssh.dev.azure.com", "ssh.dev.azure.com/v3/org/proj/repo/extra", sha40)},
		{"vs-ssh without v3", gitOcc("vs-ssh.visualstudio.com", "vs-ssh.visualstudio.com/proj/_git/repo", sha40)},
		{"vs-ssh missing repo", gitOcc("vs-ssh.visualstudio.com", "vs-ssh.visualstudio.com/v3/org/proj", sha40)},

		// Org label outside [a-z0-9-] (the host charset allows '_').
		{"org label with underscore", gitOcc("ac_me.visualstudio.com", "ac_me.visualstudio.com/proj/_git/repo", sha40)},

		// Commit is not a recorded full commit.
		{"no commit", gitOcc("dev.azure.com", "dev.azure.com/org/proj/_git/repo", "")},
		{"abbreviated commit", gitOcc("dev.azure.com", "dev.azure.com/org/proj/_git/repo", sha40[:7])},
		{"uppercase commit", gitOcc("dev.azure.com", "dev.azure.com/org/proj/_git/repo", strings.ToUpper(sha40))},
		{"41 char commit", gitOcc("dev.azure.com", "dev.azure.com/org/proj/_git/repo", sha40+"a")},
		{"63 char commit", gitOcc("dev.azure.com", "dev.azure.com/org/proj/_git/repo", sha64[:63])},
		{"non-hex commit", gitOcc("dev.azure.com", "dev.azure.com/org/proj/_git/repo", strings.Repeat("g", 40))},
		{"commit on visualstudio.com is checked too", gitOcc("acme.visualstudio.com", "acme.visualstudio.com/proj/_git/repo", sha40[:7])},
		{"commit on ssh is checked too", gitOcc("ssh.dev.azure.com", "ssh.dev.azure.com/v3/org/proj/repo", sha40[:7])},
		{"working tree even with a commit", wt},

		// Not a git location, or a row that never recorded its host.
		{"kind file", types.Occurrence{Kind: "file", Host: "dev.azure.com", Repository: "dev.azure.com/org/proj/_git/repo", Commit: sha40, HostRecorded: true}},
		{"kind extended", types.Occurrence{Kind: "extended", Host: "dev.azure.com", Repository: "dev.azure.com/org/proj/_git/repo", Commit: sha40, HostRecorded: true}},
		{"kind archive", types.Occurrence{Kind: "archive", Host: "dev.azure.com", Repository: "dev.azure.com/org/proj/_git/repo", Commit: sha40, HostRecorded: true}},
		{"legacy row: host not recorded", types.Occurrence{Kind: "git", Repository: "dev.azure.com/org/proj/_git/repo", Path: "a.env", Commit: sha40}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, "", URL(tt.occ))
		})
	}
}

// Project and repository names that repoid or the core's segment rule refuse
// never reach an Azure DevOps link, on any host form.
func TestURL_AzureDevOps_UnsafeSegmentsNoLink(t *testing.T) {
	bad := map[string]string{
		"bang":            "pro!j",
		"space":           "my proj",
		"percent-encoded": "my%20proj",
		"at sign":         "a@b",
		"query":           "a?b",
		"fragment":        "a#b",
		"backslash":       `a\b`,
		"colon":           "a:b",
		"escape sequence": "a\x1b[2Jb",
		"newline":         "a\nb",
		"nul":             "a\x00b",
		"dot-dot":         "..",
		"dot":             ".",
		"non-ascii":       "pröj",
	}
	for name, seg := range bad {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, "", URL(gitOcc("dev.azure.com", "dev.azure.com/org/"+seg+"/_git/repo", sha40)), "project")
			assert.Equal(t, "", URL(gitOcc("dev.azure.com", "dev.azure.com/org/proj/_git/"+seg, sha40)), "repo")
			assert.Equal(t, "", URL(gitOcc("acme.visualstudio.com", "acme.visualstudio.com/"+seg+"/_git/repo", sha40)), "visualstudio.com project")
			assert.Equal(t, "", URL(gitOcc("ssh.dev.azure.com", "ssh.dev.azure.com/v3/org/"+seg+"/repo", sha40)), "ssh project")
			assert.Equal(t, "", URL(gitOcc("ssh.dev.azure.com", "ssh.dev.azure.com/v3/org/proj/"+seg, sha40)), "ssh repo")
		})
	}
}
