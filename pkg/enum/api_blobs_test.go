package enum

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-github/v57/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Blob grouping and per-blob fetch behavior of the hosting-API enumerators.

// apiEntry is one tree entry served by the fixtures. status, when set, is
// the HTTP status returned for the content fetch of path.
type apiEntry struct {
	sha, path, content string
	status             int
	size               int // GitHub tree size; 0 means len(content)
	encoding           string
}

func entryAt(entries []apiEntry, p string) (apiEntry, bool) {
	i := slices.IndexFunc(entries, func(e apiEntry) bool { return e.path == p })
	if i < 0 {
		return apiEntry{}, false
	}
	return entries[i], true
}

// newGitLabTreeServer serves project 7 ("grp/api") with the given tree.
// onRaw, when set, runs before every raw-file response.
func newGitLabTreeServer(t *testing.T, entries []apiEntry, onRaw func()) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/api/v4/projects/7/repository/tree"):
			var nodes []map[string]any
			for _, e := range entries {
				nodes = append(nodes, map[string]any{"id": e.sha, "name": path.Base(e.path), "type": "blob", "path": e.path})
			}
			_ = json.NewEncoder(w).Encode(nodes)
		case strings.HasPrefix(p, "/api/v4/projects/7/repository/files/") && strings.HasSuffix(p, "/raw"):
			if onRaw != nil {
				onRaw()
			}
			fp := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v4/projects/7/repository/files/"), "/raw")
			e, ok := entryAt(entries, fp)
			if !ok {
				http.NotFound(w, r)
				return
			}
			if e.status != 0 {
				w.WriteHeader(e.status)
				_, _ = w.Write([]byte(`{"message":"denied"}`))
				return
			}
			_, _ = w.Write([]byte(e.content))
		case strings.HasPrefix(p, "/api/v4/projects/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 7, "path_with_namespace": "grp/api", "default_branch": "main"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

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

// newGitHubTreeServer serves acme/api with the given tree. onContents, when
// set, runs before every contents response.
func newGitHubTreeServer(t *testing.T, entries []apiEntry, onContents func()) *httptest.Server {
	t.Helper()
	repo := map[string]any{"name": "api", "full_name": "acme/api", "default_branch": "main", "owner": map[string]any{"login": "acme"}}
	base := "/api/v3/repos/acme/api"
	mux := http.NewServeMux()
	mux.HandleFunc(base, func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(repo) })
	mux.HandleFunc(base+"/git/trees/main", func(w http.ResponseWriter, _ *http.Request) {
		var tree []map[string]any
		for _, e := range entries {
			tree = append(tree, map[string]any{"path": e.path, "type": "blob", "sha": e.sha, "size": cmp.Or(e.size, len(e.content))})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": "root", "tree": tree, "truncated": false})
	})
	mux.HandleFunc(base+"/contents/", func(w http.ResponseWriter, r *http.Request) {
		if onContents != nil {
			onContents()
		}
		e, ok := entryAt(entries, strings.TrimPrefix(r.URL.Path, base+"/contents/"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		if e.status != 0 {
			w.WriteHeader(e.status)
			_, _ = w.Write([]byte(`{"message":"denied"}`))
			return
		}
		body := map[string]any{"type": "file", "path": e.path, "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(e.content))}
		if e.encoding != "" {
			body["encoding"], body["content"] = e.encoding, ""
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
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

func pathsByContent(t *testing.T, calls []blobCall) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, c := range calls {
		out[c.content] = locationPaths(gitProv(t, c.prov))
	}
	return out
}

// An entry without a SHA is grouped by its path. That path key must never
// merge with a real SHA key, even when the path spells that SHA, and two
// SHA-less entries never merge with each other.
func TestAPIEnumerators_PathKeyNeverMergesWithSHA(t *testing.T) {
	shaB := blobSHA("token-B")
	entries := []apiEntry{
		{sha: "", path: shaB, content: "token-A"},
		{sha: shaB, path: "b.txt", content: "token-B"},
		{sha: "", path: "c.txt", content: "token-C"},
		{sha: "", path: "d.txt", content: "token-D"},
	}
	want := map[string][]string{"token-A": {shaB}, "token-B": {"b.txt"}, "token-C": {"c.txt"}, "token-D": {"d.txt"}}

	t.Run("gitlab", func(t *testing.T) {
		e := gitlabEnumWithCreds(t, newGitLabTreeServer(t, entries, nil), GitLabConfig{Project: "grp/api"}, nil)
		calls := collectBlobs(t, func(cb blobCallback) error { return e.Enumerate(context.Background(), cb) })
		assert.Equal(t, want, pathsByContent(t, calls))
	})
	t.Run("github", func(t *testing.T) {
		e := githubEnumWithCreds(t, newGitHubTreeServer(t, entries, nil), GitHubConfig{}, nil)
		calls := collectBlobs(t, func(cb blobCallback) error { return e.Enumerate(context.Background(), cb) })
		assert.Equal(t, want, pathsByContent(t, calls))
	})
}

// A fetch that fails because the context was cancelled must return
// ctx.Err(), even for the last blob of the tree.
func TestAPIEnumerators_FetchCancelReturnsCtxErr(t *testing.T) {
	entries := []apiEntry{{sha: blobSHA("token-X"), path: "x.txt", content: "token-X", status: http.StatusInternalServerError}}
	noCall := func(t *testing.T) blobCallback {
		return func([]byte, types.BlobID, types.Provenance) error {
			t.Error("callback called for a blob whose fetch failed")
			return nil
		}
	}

	t.Run("gitlab", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		e := gitlabEnumWithCreds(t, newGitLabTreeServer(t, entries, cancel), GitLabConfig{Project: "grp/api"}, &bytes.Buffer{})
		require.ErrorIs(t, e.Enumerate(ctx, noCall(t)), context.Canceled)
	})
	t.Run("github", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		e := githubEnumWithCreds(t, newGitHubTreeServer(t, entries, cancel), GitHubConfig{}, &bytes.Buffer{})
		require.ErrorIs(t, e.Enumerate(ctx, noCall(t)), context.Canceled)
	})
}

// Any other per-blob fetch failure is warned, not dropped silently, and the
// warning carries no URL or credential and escapes control characters.
// Enumeration continues with the next blob.
func TestAPIEnumerators_FetchErrorWarnedWithoutURL(t *testing.T) {
	entries := []apiEntry{
		{sha: blobSHA("token-F"), path: "deny\x1b.txt", content: "token-F", status: http.StatusForbidden},
		{sha: blobSHA("token-G"), path: "ok.txt", content: "token-G"},
	}
	check := func(t *testing.T, srvURL, warn, wantID string, calls []blobCall) {
		t.Helper()
		assert.Equal(t, map[string][]string{"token-G": {"ok.txt"}}, pathsByContent(t, calls))
		assert.Contains(t, warn, wantID)
		assert.Contains(t, warn, `deny\x1b.txt`)
		assert.Contains(t, warn, "403")
		assert.NotContains(t, warn, "\x1b")
		assert.NotContains(t, warn, "secret")
		assert.NotContains(t, warn, strings.TrimPrefix(srvURL, "http://"))
		assert.NotContains(t, warn, "http")
	}

	t.Run("gitlab", func(t *testing.T) {
		var warn bytes.Buffer
		srv := newGitLabTreeServer(t, entries, nil)
		e := gitlabEnumWithCreds(t, srv, GitLabConfig{Project: "grp/api"}, &warn)
		calls := collectBlobs(t, func(cb blobCallback) error { return e.Enumerate(context.Background(), cb) })
		check(t, srv.URL, warn.String(), "gitlab.com/grp/api", calls)
	})
	t.Run("github", func(t *testing.T) {
		var warn bytes.Buffer
		srv := newGitHubTreeServer(t, entries, nil)
		e := githubEnumWithCreds(t, srv, GitHubConfig{}, &warn)
		calls := collectBlobs(t, func(cb blobCallback) error { return e.Enumerate(context.Background(), cb) })
		check(t, srv.URL, warn.String(), "github.com/acme/api", calls)
	})
}

// GitHub's contents API returns no inline content (encoding "none") for
// files over 1 MB. That must be a warned skip, not an empty blob reported
// at the file's paths.
func TestGitHubEnumerator_NoInlineContentWarnedNotEmptyBlob(t *testing.T) {
	var warn bytes.Buffer
	entries := []apiEntry{{sha: blobSHA("token-BIG"), path: "big.txt", content: "token-BIG", encoding: "none"}}
	e := githubEnumWithCreds(t, newGitHubTreeServer(t, entries, nil), GitHubConfig{}, &warn)
	calls := collectBlobs(t, func(cb blobCallback) error { return e.Enumerate(context.Background(), cb) })
	assert.Empty(t, calls)
	assert.Contains(t, warn.String(), "big.txt")
}

// The size limit holds per fetched blob even when the tree under-reports the
// entry's size; a blob within the limit is still reported.
func TestGitHubEnumerator_SizeLimitAppliesToFetchedContent(t *testing.T) {
	entries := []apiEntry{
		{sha: blobSHA("token-LONGER-THAN-LIMIT"), path: "l.txt", content: "token-LONGER-THAN-LIMIT", size: 1},
		{sha: blobSHA("ok"), path: "s.txt", content: "ok"},
	}
	e := githubEnumWithCreds(t, newGitHubTreeServer(t, entries, nil), GitHubConfig{Config: Config{MaxFileSize: 5}}, &bytes.Buffer{})
	calls := collectBlobs(t, func(cb blobCallback) error { return e.Enumerate(context.Background(), cb) })
	assert.Equal(t, map[string][]string{"ok": {"s.txt"}}, pathsByContent(t, calls))
}
