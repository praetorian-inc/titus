package explore

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/types"
)

const (
	linkSHA1 = "7d0e8151234567890abcdef1234567890abcdef1"
	linkSHA2 = "1111111111111111111111111111111111111111"
)

// linkOccs builds occurrences the way types.OccurrencesOf does for a
// remote-identified git repository.
func linkOccs(t *testing.T, host, repo, path string, commit string, wt bool) types.Occurrence {
	t.Helper()
	loc := types.GitLocation{Path: path, WorkingTree: wt}
	if commit != "" {
		loc.Commit = &types.CommitMetadata{CommitID: commit}
	}
	occs := types.OccurrencesOf(types.GitProvenance{
		RepoPath: repo, Host: host, RemoteIdentity: true, BlobPath: path,
		Locations: []types.GitLocation{loc},
	})
	require.Len(t, occs, 1)
	return occs[0]
}

func TestRenderLocations_CommitLinkFollowsItsLocationLine(t *testing.T) {
	gh := linkOccs(t, "github.com", "github.com/acme/api", "a.env", linkSHA1, false)
	gl := linkOccs(t, "gitlab.com", "gitlab.com/acme/api", "b.env", linkSHA2, false)
	m := matchWith(12, gh, gl)
	_, body := locationBlock(t, plainLines(m, nil, 500))
	exp := expectedLines(m.Occurrences, 12)
	assert.Equal(t, []string{exp[0], "    https://github.com/acme/api/commit/" + linkSHA1, exp[1]}, body)
}

func TestRenderLocations_NoCommitLink(t *testing.T) {
	legacy := types.Occurrence{Kind: "git", Repository: "acme/api", Path: "y.env", Commit: linkSHA1}
	tests := map[string]types.Occurrence{
		"gitlab":       linkOccs(t, "gitlab.com", "gitlab.com/acme/api", "a.env", linkSHA1, false),
		"no commit":    linkOccs(t, "github.com", "github.com/acme/api", "a.env", "", false),
		"working tree": linkOccs(t, "github.com", "github.com/acme/api", "a.env", "", true),
		"legacy":       legacy,
	}
	for name, o := range tests {
		t.Run(name, func(t *testing.T) {
			m := matchWith(3, o)
			_, body := locationBlock(t, plainLines(m, nil, 500))
			assert.Equal(t, expectedLines(m.Occurrences, 3), body)
			assert.NotContains(t, strings.Join(body, "\n"), "https://")
		})
	}
}

func TestRenderLocations_HiddenLocationShowsNoCommitLink(t *testing.T) {
	api := linkOccs(t, "github.com", "github.com/acme/api", "a.env", linkSHA1, false)
	web := linkOccs(t, "github.com", "github.com/acme/web", "c.js", linkSHA2, false)
	m := matchWith(4, api, web)
	_, body := locationBlock(t, plainLines(m, map[string]bool{"github.com/acme/web": true}, 500))
	joined := strings.Join(body, "\n")
	assert.Contains(t, joined, "https://github.com/acme/web/commit/"+linkSHA2)
	assert.NotContains(t, joined, "acme/api")
}

func TestRenderLocations_CommitLinkHardWrapsIntact(t *testing.T) {
	o := linkOccs(t, "github.com", "github.com/acme/api", "a.env", linkSHA1, false)
	m := matchWith(1, o)
	const width = 40
	_, body := locationBlock(t, plainLines(m, nil, width))
	url := "https://github.com/acme/api/commit/" + linkSHA1
	require.Greater(t, len(body), 2)
	// The location line wraps too, so the link is the tail of the joined rows.
	var rows []string
	for _, l := range body {
		rest := strings.TrimLeft(l, " ")
		assert.LessOrEqual(t, len(rest), width-6, l)
		rows = append(rows, rest)
	}
	assert.True(t, strings.HasSuffix(strings.Join(rows, ""), url), "wrapped rows %q lose link text", rows)
	assert.NotEqual(t, url, strings.Join(rows, ""), "link is wrapped, not a single row")
}

func TestRenderLocations_CommitLinkTerminalSafety(t *testing.T) {
	o := linkOccs(t, "github.com", "github.com/acme/ap\x1b[2Ji", "a.env", linkSHA1, false)
	m := matchWith(1, o)
	raw := strings.Join(renderMatchDetails(m, nil, 500), "\n")
	assert.NotContains(t, raw, "\x1b[2J")
	_, body := locationBlock(t, plainLines(m, nil, 500))
	assert.NotContains(t, strings.Join(body, "\n"), "https://", "unsafe path is refused, not printed")
}

func TestRenderLocations_CommitLinkDoesNotMutateOccurrences(t *testing.T) {
	o := linkOccs(t, "github.com", "github.com/acme/api", "a.env", linkSHA1, false)
	m := matchWith(1, o)
	before := slices.Clone(m.Occurrences)
	_ = plainLines(m, nil, 60)
	assert.Equal(t, before, m.Occurrences)
}
