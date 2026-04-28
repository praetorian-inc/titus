package accessibility

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Regex pattern tests
// ---------------------------------------------------------------------------

func TestGitlabRepoPattern_ParsesURLs(t *testing.T) {
	cases := []struct {
		url   string
		path  string
		match bool
	}{
		{"https://gitlab.com/owner/repo.git", "owner/repo", true},
		{"git@gitlab.com:owner/repo.git", "owner/repo", true},
		{"https://gitlab.com/group/subgroup/repo", "group/subgroup/repo", true},
		{"https://github.com/owner/repo", "", false},
		{"https://bitbucket.org/workspace/repo", "", false},
	}
	for _, c := range cases {
		m := gitlabRepoPattern.FindStringSubmatch(c.url)
		if c.match {
			require.NotNil(t, m, "expected match for %q", c.url)
			assert.Equal(t, c.path, m[1])
		} else {
			assert.Nil(t, m, "expected no match for %q", c.url)
		}
	}
}

func TestBitbucketRepoPattern_ParsesURLs(t *testing.T) {
	cases := []struct {
		url       string
		workspace string
		repo      string
		match     bool
	}{
		{"https://bitbucket.org/myteam/myrepo.git", "myteam", "myrepo", true},
		{"git@bitbucket.org:myteam/myrepo.git", "myteam", "myrepo", true},
		{"https://bitbucket.org/myteam/myrepo", "myteam", "myrepo", true},
		{"https://github.com/owner/repo", "", "", false},
		{"https://gitlab.com/owner/repo", "", "", false},
	}
	for _, c := range cases {
		m := bitbucketRepoPattern.FindStringSubmatch(c.url)
		if c.match {
			require.NotNil(t, m, "expected match for %q", c.url)
			assert.Equal(t, c.workspace, m[1])
			assert.Equal(t, c.repo, m[2])
		} else {
			assert.Nil(t, m, "expected no match for %q", c.url)
		}
	}
}

// ---------------------------------------------------------------------------
// gitlabRepoIsPrivate — via mock HTTP server + base URL override
// ---------------------------------------------------------------------------

func TestGitlabRepoIsPrivate_PublicRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"visibility":"public"}`))
	}))
	defer srv.Close()

	orig := gitlabAPIBase
	gitlabAPIBase = srv.URL
	defer func() { gitlabAPIBase = orig }()

	isPrivate, err := gitlabRepoIsPrivate("owner/repo", "")
	require.NoError(t, err)
	assert.False(t, isPrivate, "public GitLab repo should not be private")
}

func TestGitlabRepoIsPrivate_PrivateRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"visibility":"private"}`))
	}))
	defer srv.Close()

	orig := gitlabAPIBase
	gitlabAPIBase = srv.URL
	defer func() { gitlabAPIBase = orig }()

	isPrivate, err := gitlabRepoIsPrivate("owner/repo", "")
	require.NoError(t, err)
	assert.True(t, isPrivate, "private GitLab repo should be private")
}

func TestGitlabRepoIsPrivate_InternalTreatedAsPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"visibility":"internal"}`))
	}))
	defer srv.Close()

	orig := gitlabAPIBase
	gitlabAPIBase = srv.URL
	defer func() { gitlabAPIBase = orig }()

	isPrivate, err := gitlabRepoIsPrivate("owner/repo", "")
	require.NoError(t, err)
	assert.True(t, isPrivate, "internal GitLab repo should be treated as private")
}

func TestGitlabRepoIsPrivate_404TreatedAsPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	orig := gitlabAPIBase
	gitlabAPIBase = srv.URL
	defer func() { gitlabAPIBase = orig }()

	isPrivate, err := gitlabRepoIsPrivate("owner/repo", "")
	require.NoError(t, err)
	assert.True(t, isPrivate, "GitLab 404 should be treated as private")
}

func TestGitlabRepoIsPrivate_401TreatedAsPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	orig := gitlabAPIBase
	gitlabAPIBase = srv.URL
	defer func() { gitlabAPIBase = orig }()

	isPrivate, err := gitlabRepoIsPrivate("owner/repo", "")
	require.NoError(t, err)
	assert.True(t, isPrivate, "GitLab 401 should be treated as private")
}

func TestGitlabRepoIsPrivate_TokenSentAsPrivateToken(t *testing.T) {
	var capturedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedToken = r.Header.Get("PRIVATE-TOKEN")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"visibility":"public"}`))
	}))
	defer srv.Close()

	orig := gitlabAPIBase
	gitlabAPIBase = srv.URL
	defer func() { gitlabAPIBase = orig }()

	_, err := gitlabRepoIsPrivate("owner/repo", "my-gitlab-token")
	require.NoError(t, err)
	assert.Equal(t, "my-gitlab-token", capturedToken, "PRIVATE-TOKEN header should be set")
}

func TestGitlabRepoIsPrivate_PathEncoding(t *testing.T) {
	var capturedRequestURI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// r.RequestURI is the raw, unmodified URI received on the wire.
		// r.URL.Path is the decoded form (slashes), so we check RequestURI.
		capturedRequestURI = r.RequestURI
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"visibility":"public"}`))
	}))
	defer srv.Close()

	orig := gitlabAPIBase
	gitlabAPIBase = srv.URL
	defer func() { gitlabAPIBase = orig }()

	_, err := gitlabRepoIsPrivate("group/subgroup/repo", "")
	require.NoError(t, err)
	assert.Equal(t, "/api/v4/projects/group%2Fsubgroup%2Frepo", capturedRequestURI,
		"nested group path should be URL-encoded with %%2F separators on the wire and include /api/v4/ prefix")
}

func TestGitlabRepoIsPrivate_SimplePathIncludesAPIPrefix(t *testing.T) {
	var capturedRequestURI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRequestURI = r.RequestURI
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"visibility":"public"}`))
	}))
	defer srv.Close()

	orig := gitlabAPIBase
	gitlabAPIBase = srv.URL
	defer func() { gitlabAPIBase = orig }()

	_, err := gitlabRepoIsPrivate("owner/repo", "")
	require.NoError(t, err)
	assert.Equal(t, "/api/v4/projects/owner%2Frepo", capturedRequestURI,
		"simple owner/repo path must include /api/v4/ prefix to hit the API, not the web UI")
}

func TestGitlabRepoIsPrivate_UnexpectedStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	orig := gitlabAPIBase
	gitlabAPIBase = srv.URL
	defer func() { gitlabAPIBase = orig }()

	_, err := gitlabRepoIsPrivate("owner/repo", "")
	assert.Error(t, err, "unexpected HTTP status should return an error")
}

// ---------------------------------------------------------------------------
// bitbucketRepoIsPrivate — via mock HTTP server + base URL override
// ---------------------------------------------------------------------------

func TestBitbucketRepoIsPrivate_PublicRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"is_private":false}`))
	}))
	defer srv.Close()

	orig := bitbucketAPIBase
	bitbucketAPIBase = srv.URL
	defer func() { bitbucketAPIBase = orig }()

	isPrivate, err := bitbucketRepoIsPrivate("myteam", "myrepo", "")
	require.NoError(t, err)
	assert.False(t, isPrivate, "public Bitbucket repo should not be private")
}

func TestBitbucketRepoIsPrivate_PrivateRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"is_private":true}`))
	}))
	defer srv.Close()

	orig := bitbucketAPIBase
	bitbucketAPIBase = srv.URL
	defer func() { bitbucketAPIBase = orig }()

	isPrivate, err := bitbucketRepoIsPrivate("myteam", "myrepo", "")
	require.NoError(t, err)
	assert.True(t, isPrivate, "private Bitbucket repo should be private")
}

func TestBitbucketRepoIsPrivate_404TreatedAsPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	orig := bitbucketAPIBase
	bitbucketAPIBase = srv.URL
	defer func() { bitbucketAPIBase = orig }()

	isPrivate, err := bitbucketRepoIsPrivate("myteam", "myrepo", "")
	require.NoError(t, err)
	assert.True(t, isPrivate, "Bitbucket 404 should be treated as private")
}

func TestBitbucketRepoIsPrivate_403TreatedAsPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	orig := bitbucketAPIBase
	bitbucketAPIBase = srv.URL
	defer func() { bitbucketAPIBase = orig }()

	isPrivate, err := bitbucketRepoIsPrivate("myteam", "myrepo", "")
	require.NoError(t, err)
	assert.True(t, isPrivate, "Bitbucket 403 should be treated as private")
}

func TestBitbucketRepoIsPrivate_TokenSentAsBearerAuth(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"is_private":false}`))
	}))
	defer srv.Close()

	orig := bitbucketAPIBase
	bitbucketAPIBase = srv.URL
	defer func() { bitbucketAPIBase = orig }()

	_, err := bitbucketRepoIsPrivate("myteam", "myrepo", "my-bb-token")
	require.NoError(t, err)
	assert.Equal(t, "Bearer my-bb-token", capturedAuth, "Authorization header should be Bearer token")
}

func TestBitbucketRepoIsPrivate_UnexpectedStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	orig := bitbucketAPIBase
	bitbucketAPIBase = srv.URL
	defer func() { bitbucketAPIBase = orig }()

	_, err := bitbucketRepoIsPrivate("myteam", "myrepo", "")
	assert.Error(t, err, "unexpected HTTP status should return an error")
}

// ---------------------------------------------------------------------------
// Resolve — mode string handling
// ---------------------------------------------------------------------------

func TestResolve_PublicModeReturnsPublic(t *testing.T) {
	result := Resolve("public", "", "")
	assert.Equal(t, Public, result)
}

func TestResolve_PrivateModeReturnsPrivate(t *testing.T) {
	result := Resolve("private", "", "")
	assert.Equal(t, Private, result)
}

func TestResolve_CaseInsensitive(t *testing.T) {
	assert.Equal(t, Public, Resolve("PUBLIC", "", ""))
	assert.Equal(t, Private, Resolve("PRIVATE", "", ""))
}
