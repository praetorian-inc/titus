package commitlink

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/types"
)

const (
	sha40 = "7d0e8151234567890abcdef1234567890abcdef1"
	sha64 = "7d0e8151234567890abcdef1234567890abcdef17d0e8151234567890abcdef1"
)

// gitOcc is a committed git occurrence as types.OccurrencesOf produces it for
// a remote-identified repository: Host is the recorded host, Repository is
// "host/owner/repo", Commit is the full hash.
func gitOcc(host, repo, commit string) types.Occurrence {
	return types.Occurrence{Kind: "git", Host: host, Repository: repo, Path: "config/app.env", Commit: commit, HostRecorded: true}
}

func TestURL_GitHubCommit(t *testing.T) {
	assert.Equal(t, "https://github.com/acme/api/commit/"+sha40,
		URL(gitOcc("github.com", "github.com/acme/api", sha40)))
	assert.Equal(t, "https://github.com/acme/api/commit/"+sha64,
		URL(gitOcc("github.com", "github.com/acme/api", sha64)), "sha256 object format")
	assert.Equal(t, "https://github.com/Acme_Org/my.repo-2/commit/"+sha40,
		URL(gitOcc("github.com", "github.com/Acme_Org/my.repo-2", sha40)), "allowed segment characters pass")
}

// Real provenance (as the store rebuilds it) flows through OccurrencesOf and
// yields one link per location, each with its own recorded commit.
func TestURL_FromOccurrencesOfMultiLocationBlob(t *testing.T) {
	c1, c2 := strings.Repeat("1", 40), strings.Repeat("2", 40)
	occs := types.OccurrencesOf(types.GitProvenance{
		RepoPath: "github.com/acme/api", Host: "github.com", RemoteIdentity: true, BlobPath: "a.env",
		Locations: []types.GitLocation{
			{Path: "a.env", Commit: &types.CommitMetadata{CommitID: c1}},
			{Path: "b.env", Commit: &types.CommitMetadata{CommitID: c2}},
			{Path: "c.env", WorkingTree: true},
		},
	})
	require.Len(t, occs, 3)
	assert.Equal(t, "https://github.com/acme/api/commit/"+c1, URL(occs[0]))
	assert.Equal(t, "https://github.com/acme/api/commit/"+c2, URL(occs[1]))
	assert.Equal(t, "", URL(occs[2]), "working-tree location has no link")
}

func TestURL_NoLink(t *testing.T) {
	wt := gitOcc("github.com", "github.com/acme/api", sha40)
	wt.WorkingTree = true
	tests := []struct {
		name string
		occ  types.Occurrence
	}{
		{"unregistered example host", gitOcc("example.invalid", "example.invalid/acme/api", sha40)},
		{"self-hosted enterprise", gitOcc("ghe.example.com", "ghe.example.com/acme/api", sha40)},
		{"github.example.com", gitOcc("github.example.com", "github.example.com/acme/api", sha40)},
		{"suffix lookalike github.com.evil", gitOcc("github.com.evil", "github.com.evil/acme/api", sha40)},
		{"prefix lookalike evilgithub.com", gitOcc("evilgithub.com", "evilgithub.com/acme/api", sha40)},
		{"port", gitOcc("github.com:443", "github.com:443/acme/api", sha40)},
		{"uppercase host", gitOcc("GITHUB.COM", "GITHUB.COM/acme/api", sha40)},
		{"www subdomain", gitOcc("www.github.com", "www.github.com/acme/api", sha40)},
		{"empty host with github-looking repository", gitOcc("", "github.com/acme/api", sha40)},
		{"host/repository mismatch", gitOcc("github.com", "gitlab.com/acme/api", sha40)},
		{"repository without host prefix", gitOcc("github.com", "acme/api", sha40)},
		{"repository is host prefix only", gitOcc("github.com", "github.com/", sha40)},
		{"host only a prefix of the repository host", gitOcc("github.com", "github.comx/acme/api", sha40)},
		{"no commit", gitOcc("github.com", "github.com/acme/api", "")},
		{"working tree even with commit", wt},
		{"legacy row: host not recorded", types.Occurrence{Kind: "git", Repository: "acme/api", Path: "h1.txt", Commit: sha40}},
		{"kind file", types.Occurrence{Kind: "file", Host: "github.com", Repository: "github.com/acme/api", Commit: sha40, HostRecorded: true}},
		{"kind extended", types.Occurrence{Kind: "extended", Host: "github.com", Repository: "github.com/acme/api", Commit: sha40, HostRecorded: true}},
		{"kind archive", types.Occurrence{Kind: "archive", Host: "github.com", Repository: "github.com/acme/api", Commit: sha40, HostRecorded: true}},
		{"zero value", types.Occurrence{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, "", URL(tt.occ))
		})
	}
}

func TestURL_RejectsUnsafeRepositoryPaths(t *testing.T) {
	for name, path := range map[string]string{
		"dot-dot":         "acme/..",
		"dot":             "./api",
		"empty segment":   "acme//api",
		"leading slash":   "/acme/api",
		"trailing slash":  "acme/api/",
		"space":           "acme/my api",
		"percent-encoded": "acme/%2e%2e",
		"query":           "acme/api?x=1",
		"fragment":        "acme/api#frag",
		"userinfo":        "user@evil/api",
		"backslash":       `acme\api`,
		"newline":         "acme/api\nrm",
		"escape sequence": "acme/api\x1b[2J",
		"carriage return": "acme/api\r",
		"nul":             "acme/api\x00",
		"non-ascii":       "acme/apï",
		"bidi override":   "acme/‮api",
		"colon":           "acme:evil/api",
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, "", URL(gitOcc("github.com", "github.com/"+path, sha40)))
		})
	}
}

func TestURL_RejectsCommitsThatAreNotFullLowercaseHex(t *testing.T) {
	for name, c := range map[string]string{
		"uppercase":      strings.ToUpper(sha40),
		"mixed case":     sha40[:39] + "A",
		"short 7":        sha40[:7],
		"abbreviated 12": sha40[:12],
		"41 chars":       sha40 + "a",
		"63 chars":       sha64[:63],
		"non-hex":        strings.Repeat("g", 40),
		"leading space":  " " + sha40[:39],
		"trailing space": sha40[:39] + " ",
		"padded":         " " + sha40,
		"path-injecting": "../../../x" + strings.Repeat("a", 30),
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, "", URL(gitOcc("github.com", "github.com/acme/api", c)))
		})
	}
}

func TestRegister_PanicsOnEmptyHost(t *testing.T) {
	assert.PanicsWithValue(t, "commitlink: register with empty host", func() {
		register("", func(string, string) string { return "x" })
	})
}

func TestRegister_PanicsOnDuplicateHost(t *testing.T) {
	before := len(hosts)
	assert.PanicsWithValue(t, "commitlink: duplicate host github.com", func() {
		register("github.com", func(string, string) string { return "x" })
	})
	assert.Len(t, hosts, before, "a rejected registration must not change the registry")
	assert.Equal(t, "https://github.com/acme/api/commit/"+sha40,
		URL(gitOcc("github.com", "github.com/acme/api", sha40)), "original builder survives")
}

// A second host needs only a register call: the core does the safety checks
// and hands the builder a validated path and commit. The test host is removed
// afterwards so it never reaches other tests. Not parallel: it mutates the
// package registry.
func TestRegister_NewHostNeedsNoCoreChange(t *testing.T) {
	const host = "forge.test-only.invalid"
	called := false
	var gotPath, gotSHA string
	register(host, func(path, sha string) string {
		called = true
		gotPath, gotSHA = path, sha
		return "https://" + host + "/" + path + "/-/commit/" + sha
	})
	t.Cleanup(func() { delete(hosts, host) })

	assert.Equal(t, "https://"+host+"/group/sub/repo/-/commit/"+sha40, URL(gitOcc(host, host+"/group/sub/repo", sha40)))
	assert.Equal(t, "group/sub/repo", gotPath)
	assert.Equal(t, sha40, gotSHA)

	// Core validation still guards the new host: the builder is not reached.
	called = false
	assert.Equal(t, "", URL(gitOcc(host, host+"/group/../repo", sha40)))
	assert.Equal(t, "", URL(gitOcc(host, host+"/group/repo", strings.ToUpper(sha40))))
	assert.Equal(t, "", URL(types.Occurrence{Kind: "git", WorkingTree: true, Host: host, Repository: host + "/g/r", Commit: sha40}))
	assert.False(t, called, "builder is never called for an input the core rejects")
}

func TestRegister_BuilderMayRefuseItsOwnShape(t *testing.T) {
	const host = "refuses.test-only.invalid"
	register(host, func(string, string) string { return "" })
	t.Cleanup(func() { delete(hosts, host) })
	assert.Equal(t, "", URL(gitOcc(host, host+"/a/b", sha40)))
}

func TestRegisteredTestHostsDoNotLeak(t *testing.T) {
	for _, h := range []string{"forge.test-only.invalid", "refuses.test-only.invalid"} {
		assert.NotContains(t, hosts, h)
	}
}
