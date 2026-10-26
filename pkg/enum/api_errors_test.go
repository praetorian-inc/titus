package enum

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Listing and setup errors of the hosting-API enumerators must not carry the
// request URL or base-URL credentials, and must still wrap ctx errors.

// newFailingAPIServer serves fixture JSON, except that a request whose path
// has failPrefix gets status (after onFail runs, when set).
func newFailingAPIServer(t *testing.T, failPrefix string, status int, onFail func()) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var fails atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, failPrefix) {
			fails.Add(1)
			if onFail != nil {
				onFail()
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"message":"denied"}`))
			return
		}
		switch {
		case strings.HasPrefix(p, "/api/v3/repos/acme/api"):
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "api", "full_name": "acme/api", "default_branch": "main", "owner": map[string]any{"login": "acme"}})
		case strings.HasPrefix(p, "/api/v4/projects/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 7, "path_with_namespace": "grp/api", "default_branch": "main"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &fails
}

func discardBlob([]byte, types.BlobID, types.Provenance) error { return nil }

type listingCase struct {
	name       string
	failPrefix string
	run        func(t *testing.T, ctx context.Context, srv *httptest.Server) error
}

func listingCases() []listingCase {
	gh := func(cfg GitHubConfig) func(*testing.T, context.Context, *httptest.Server) error {
		return func(t *testing.T, ctx context.Context, srv *httptest.Server) error {
			return githubEnumWithCreds(t, srv, cfg, nil).Enumerate(ctx, discardBlob)
		}
	}
	gl := func(cfg GitLabConfig) func(*testing.T, context.Context, *httptest.Server) error {
		return func(t *testing.T, ctx context.Context, srv *httptest.Server) error {
			return gitlabEnumWithCreds(t, srv, cfg, nil).Enumerate(ctx, discardBlob)
		}
	}
	return []listingCase{
		{"github/getting repository", "/api/v3/repos/acme/api", gh(GitHubConfig{Owner: "acme", Repo: "api"})},
		{"github/listing org repositories", "/api/v3/orgs/acme/repos", gh(GitHubConfig{Org: "acme"})},
		{"github/listing user repositories", "/api/v3/users/acme/repos", gh(GitHubConfig{User: "acme"})},
		{"github/getting tree", "/api/v3/repos/acme/api/git/trees/", gh(GitHubConfig{Owner: "acme", Repo: "api"})},
		{"gitlab/getting project", "/api/v4/projects/grp", gl(GitLabConfig{Project: "grp/api"})},
		{"gitlab/listing group projects", "/api/v4/groups/grp/projects", gl(GitLabConfig{Group: "grp"})},
		{"gitlab/listing user projects", "/api/v4/users/acme/projects", gl(GitLabConfig{User: "acme"})},
		{"gitlab/listing tree", "/api/v4/projects/7/repository/tree", gl(GitLabConfig{Project: "grp/api"})},
	}
}

func TestAPIEnumerators_ListingErrorHasNoURLOrCredential(t *testing.T) {
	for _, tc := range listingCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv, fails := newFailingAPIServer(t, tc.failPrefix, http.StatusForbidden, nil)
			err := tc.run(t, context.Background(), srv)
			require.Error(t, err)
			require.Positive(t, fails.Load(), "the failing endpoint was not reached")
			msg := err.Error()
			assert.Contains(t, msg, "403")
			assert.NotContains(t, msg, "secret")
			assert.NotContains(t, msg, "u:")
			assert.NotContains(t, msg, strings.TrimPrefix(srv.URL, "http://"))
			assert.NotContains(t, msg, "http")
			assert.NotContains(t, msg, "/api/")
		})
	}
}

func TestAPIEnumerators_ListingCancelReturnsCtxErr(t *testing.T) {
	for _, tc := range listingCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			srv, fails := newFailingAPIServer(t, tc.failPrefix, http.StatusInternalServerError, cancel)
			err := tc.run(t, ctx, srv)
			// The failing request cancels ctx: the enumerator must stop with
			// ctx's error and send no retry, whatever its backoff.
			require.ErrorIs(t, err, context.Canceled)
			assert.Equal(t, int32(1), fails.Load(), "no retry after cancel")
			assert.NotContains(t, err.Error(), "secret")
		})
	}
}

func TestAPIEnumerators_SetupErrorHasNoCredential(t *testing.T) {
	const bad = "https://u:secret@git.example.test:notaport/"
	t.Run("github", func(t *testing.T) {
		_, err := NewGitHubEnumerator(GitHubConfig{BaseURL: bad, Owner: "acme", Repo: "api"})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "secret")
		assert.NotContains(t, err.Error(), "git.example.test")
	})
	t.Run("gitlab", func(t *testing.T) {
		_, err := NewGitLabEnumerator(GitLabConfig{BaseURL: bad, Project: "grp/api"})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "secret")
		assert.NotContains(t, err.Error(), "git.example.test")
	})
}

// countingRT counts the raw-file response-body bytes the client reads.
type countingRT struct{ n atomic.Int64 }

type countingBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (b countingBody) Read(p []byte) (int, error) {
	k, err := b.ReadCloser.Read(p)
	b.n.Add(int64(k))
	return k, err
}

func (rt *countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if resp != nil && resp.Body != nil && strings.HasSuffix(r.URL.Path, "/raw") {
		resp.Body = countingBody{resp.Body, &rt.n}
	}
	return resp, err
}

// A raw file far over MaxFileSize is read at most limit+1 bytes (the
// client's deferred drain included), skipped, and warned; a small file in the
// same project is still reported.
func TestGitLabEnumerator_RawReadIsBounded(t *testing.T) {
	const limit = 1000
	big := strings.Repeat("a", 4<<20) // 4 MiB
	srv := newGitLabTreeServer(t, []apiEntry{
		{sha: strings.Repeat("1", 40), path: "big.txt", content: big},
		{sha: strings.Repeat("2", 40), path: "small.txt", content: "token-small"},
	}, nil)
	rt := &countingRT{}
	c, err := gitlab.NewClient("", gitlab.WithBaseURL(credURL(t, srv, "/api/v4")), gitlab.WithHTTPClient(&http.Client{Transport: rt}))
	require.NoError(t, err)
	var warn bytes.Buffer
	e := &GitLabEnumerator{client: c, config: GitLabConfig{Project: "grp/api", Config: Config{MaxFileSize: limit}}, warn: &warn}

	calls := collectBlobs(t, func(cb blobCallback) error { return e.Enumerate(context.Background(), cb) })

	assert.Equal(t, map[string][]string{"token-small": {"small.txt"}}, pathsByContent(t, calls))
	read := rt.n.Load() - int64(len("token-small"))
	assert.LessOrEqual(t, read, int64(limit+1), "raw body bytes read for big.txt")
	assert.Contains(t, warn.String(), "big.txt")
	assert.Contains(t, warn.String(), "size limit")
	assert.NotContains(t, warn.String(), "secret")
}

func TestCappedBuffer(t *testing.T) {
	t.Run("WriteTo source over limit stops", func(t *testing.T) {
		stopped := 0
		c := &cappedBuffer{limit: 10, stop: func() { stopped++ }}
		// *strings.Reader has WriteTo, so io.Copy uses Write, not ReadFrom.
		_, err := io.Copy(c, strings.NewReader(strings.Repeat("a", 11)))
		require.ErrorIs(t, err, errOverSizeLimit)
		assert.Equal(t, 1, stopped)
		assert.LessOrEqual(t, c.buf.Len(), 10)
	})
	t.Run("at limit keeps everything", func(t *testing.T) {
		stopped := 0
		c := &cappedBuffer{limit: 10, stop: func() { stopped++ }}
		_, err := io.Copy(c, strings.NewReader(strings.Repeat("a", 10)))
		require.NoError(t, err)
		assert.Equal(t, 10, c.buf.Len())
		assert.Zero(t, stopped)
	})
	t.Run("ReadFrom over limit stops", func(t *testing.T) {
		stopped := 0
		c := &cappedBuffer{limit: 10, stop: func() { stopped++ }}
		_, err := io.Copy(c, io.LimitReader(strings.NewReader(strings.Repeat("a", 1<<16)), 1<<16))
		require.ErrorIs(t, err, errOverSizeLimit)
		assert.Equal(t, 1, stopped)
		assert.LessOrEqual(t, c.buf.Len(), 11)
	})
	t.Run("no limit keeps everything", func(t *testing.T) {
		stopped := 0
		c := &cappedBuffer{stop: func() { stopped++ }}
		_, err := io.Copy(c, io.LimitReader(strings.NewReader(strings.Repeat("a", 1<<16)), 1<<16))
		require.NoError(t, err)
		assert.Equal(t, 1<<16, c.buf.Len())
		assert.Zero(t, stopped)
	})
}
