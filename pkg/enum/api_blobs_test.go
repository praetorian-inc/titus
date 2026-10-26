package enum

import (
	"bytes"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-github/v57/github"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// credURL returns srv's URL + suffix with userinfo u:secret, so any message
// that echoed a request URL would leak the fake credential.
func credURL(t *testing.T, srv *httptest.Server, suffix string) string {
	t.Helper()
	u, err := url.Parse(srv.URL + suffix)
	require.NoError(t, err)
	u.User = url.UserPassword("u", "secret")
	return u.String()
}

func gitlabEnumWithCreds(t *testing.T, srv *httptest.Server, cfg GitLabConfig, warn *bytes.Buffer) *GitLabEnumerator {
	t.Helper()
	c, err := gitlab.NewClient("", gitlab.WithBaseURL(credURL(t, srv, "/api/v4")))
	require.NoError(t, err)
	e := &GitLabEnumerator{client: c, config: cfg}
	if warn != nil {
		e.warn = warn
	}
	return e
}

func githubEnumWithCreds(t *testing.T, srv *httptest.Server, cfg GitHubConfig, warn *bytes.Buffer) *GitHubEnumerator {
	t.Helper()
	c := github.NewClient(nil)
	u, err := url.Parse(credURL(t, srv, "/api/v3/"))
	require.NoError(t, err)
	c.BaseURL = u
	if cfg.Owner == "" && cfg.Org == "" && cfg.User == "" {
		cfg.Owner, cfg.Repo = "acme", "api"
	}
	e := &GitHubEnumerator{client: c, config: cfg}
	if warn != nil {
		e.warn = warn
	}
	return e
}
