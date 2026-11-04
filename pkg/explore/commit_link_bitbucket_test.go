package explore

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderLocations_BitbucketCommitLinkFollowsItsLocationLine(t *testing.T) {
	bb := linkOccs(t, "bitbucket.org", "bitbucket.org/acme/api", "a.env", linkSHA1, false)
	gl := linkOccs(t, "gitea.example.com", "gitea.example.com/acme/api", "b.env", linkSHA2, false)
	m := matchWith(12, bb, gl)
	_, body := locationBlock(t, plainLines(m, nil, 500))
	exp := expectedLines(m.Occurrences, 12)
	assert.Equal(t, []string{exp[0], "    https://bitbucket.org/acme/api/commits/" + linkSHA1, exp[1]}, body)
}

func TestRenderLocations_NoBitbucketCommitLink(t *testing.T) {
	tests := map[string]struct {
		host, repo, commit string
		wt                 bool
	}{
		"working tree":     {"bitbucket.org", "bitbucket.org/acme/api", "", true},
		"no commit":        {"bitbucket.org", "bitbucket.org/acme/api", "", false},
		"bitbucket server": {"bitbucket.corp.example", "bitbucket.corp.example/acme/api", linkSHA1, false},
		"lookalike host":   {"bitbucket.org.evil.example", "bitbucket.org.evil.example/acme/api", linkSHA1, false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			m := matchWith(3, linkOccs(t, tc.host, tc.repo, "a.env", tc.commit, tc.wt))
			_, body := locationBlock(t, plainLines(m, nil, 500))
			assert.Equal(t, expectedLines(m.Occurrences, 3), body)
			assert.NotContains(t, strings.Join(body, "\n"), "https://")
		})
	}
}
