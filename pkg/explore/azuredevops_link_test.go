package explore

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/types"
)

const (
	adoRepo = "dev.azure.com/acme/proj/_git/repo"
	adoURL  = "https://dev.azure.com/acme/proj/_git/repo/commit/"
)

func TestRenderLocations_AzureDevOpsCommitLinkFollowsItsLocationLine(t *testing.T) {
	ado := linkOccs(t, "dev.azure.com", adoRepo, "a.env", linkSHA1, false)
	gl := linkOccs(t, "gitlab.com", "gitlab.com/acme/api", "b.env", linkSHA2, false)
	vs := linkOccs(t, "acme.visualstudio.com", "acme.visualstudio.com/proj/_git/repo", "c.env", linkSHA2, false)
	m := matchWith(12, ado, gl, vs)
	_, body := locationBlock(t, plainLines(m, nil, 500))
	exp := expectedLines(m.Occurrences, 12)
	assert.Equal(t, []string{
		exp[0], "    " + adoURL + linkSHA1,
		exp[1],
		exp[2], "    " + adoURL + linkSHA2,
	}, body)
}

func TestRenderLocations_AzureDevOpsSSHCommitLink(t *testing.T) {
	o := linkOccs(t, "ssh.dev.azure.com", "ssh.dev.azure.com/v3/acme/proj/repo", "a.env", linkSHA1, false)
	m := matchWith(5, o)
	_, body := locationBlock(t, plainLines(m, nil, 500))
	assert.Equal(t, []string{expectedLines(m.Occurrences, 5)[0], "    " + adoURL + linkSHA1}, body)
}

func TestRenderLocations_AzureDevOpsNoCommitLink(t *testing.T) {
	tests := map[string]types.Occurrence{
		"lookalike host": linkOccs(t, "dev.azure.com.evil", "dev.azure.com.evil/acme/proj/_git/repo", "a.env", linkSHA1, false),
		"no commit":      linkOccs(t, "dev.azure.com", adoRepo, "a.env", "", false),
		"working tree":   linkOccs(t, "dev.azure.com", adoRepo, "a.env", "", true),
		"project-less":   linkOccs(t, "dev.azure.com", "dev.azure.com/acme/_git/repo", "a.env", linkSHA1, false),
		"legacy": {
			Kind: "git", Repository: adoRepo, Path: "a.env", Commit: linkSHA1,
		},
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

// A location hidden by the facet selection shows neither its line nor its link.
func TestRenderLocations_AzureDevOpsHiddenLocationShowsNoCommitLink(t *testing.T) {
	api := linkOccs(t, "dev.azure.com", "dev.azure.com/acme/proj/_git/api", "a.env", linkSHA1, false)
	web := linkOccs(t, "dev.azure.com", "dev.azure.com/acme/proj/_git/web", "c.js", linkSHA2, false)
	m := matchWith(4, api, web)
	_, body := locationBlock(t, plainLines(m, map[string]bool{"dev.azure.com/acme/proj/_git/web": true}, 500))
	joined := strings.Join(body, "\n")
	assert.Contains(t, joined, "https://dev.azure.com/acme/proj/_git/web/commit/"+linkSHA2)
	assert.NotContains(t, joined, "_git/api")
}

// At a narrow pane the URL hard-wraps; no text is lost.
func TestRenderLocations_AzureDevOpsCommitLinkHardWrapsIntact(t *testing.T) {
	o := linkOccs(t, "dev.azure.com", adoRepo, "a.env", linkSHA1, false)
	m := matchWith(1, o)
	const width = 40
	_, body := locationBlock(t, plainLines(m, nil, width))
	url := adoURL + linkSHA1
	require.Greater(t, len(body), 2)
	var rows []string
	for _, l := range body {
		rest := strings.TrimLeft(l, " ")
		assert.LessOrEqual(t, len(rest), width-6, l)
		rows = append(rows, rest)
	}
	assert.True(t, strings.HasSuffix(strings.Join(rows, ""), url), "wrapped rows %q lose link text", rows)
	assert.NotEqual(t, url, strings.Join(rows, ""), "link is wrapped, not a single row")
}
