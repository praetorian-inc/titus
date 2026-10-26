package enum

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-github/v57/github"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

// --- fixtures -------------------------------------------------------------

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(cmd.Environ(),
		"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return strings.TrimSpace(string(out))
}

// makeRemoteFixture creates <root>/<owner>/<name>.git as a working repository
// holding files, committed once. It returns the commit hash.
func makeRemoteFixture(t *testing.T, root, owner, name string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(root, owner, name+".git")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	gitIn(t, dir, "init", "--quiet", "-b", "main")
	for p, c := range files {
		full := filepath.Join(dir, p)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(c), 0o644))
	}
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "--quiet", "-m", "init")
	return gitIn(t, dir, "rev-parse", "HEAD")
}

// redirectHTTPSToLocal makes "https://u:secret@github.com/" resolve to root,
// so a token-bearing https CloneURL clones a local fixture with no network.
func redirectHTTPSToLocal(t *testing.T, root string) {
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "url.file://"+root+"/.insteadOf")
	t.Setenv("GIT_CONFIG_VALUE_0", "https://u:secret@github.com/")
}

type blobCall struct {
	content string
	blobID  types.BlobID
	prov    types.Provenance
}

// collectBlobs records every callback of run. The filesystem enumerator calls
// back from parallel readers, so recording is serialized.
func collectBlobs(t *testing.T, run func(cb blobCallback) error) []blobCall {
	t.Helper()
	var mu sync.Mutex
	var calls []blobCall
	require.NoError(t, run(func(c []byte, id types.BlobID, p types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, blobCall{string(c), id, p})
		return nil
	}))
	return calls
}

// isDotGit reports whether p is under .git/: filesystem mode walks the
// clone's .git directory too (pre-existing behavior).
func isDotGit(p types.Provenance) bool {
	gp, ok := p.(types.GitProvenance)
	return ok && strings.HasPrefix(gp.BlobPath, ".git/")
}

func withoutDotGit(calls []blobCall) []blobCall {
	return slices.DeleteFunc(calls, func(c blobCall) bool { return isDotGit(c.prov) })
}

func locationPaths(gp types.GitProvenance) []string {
	var out []string
	for _, l := range gp.Locations {
		out = append(out, l.Path)
	}
	return out
}

func gitProv(t *testing.T, p types.Provenance) types.GitProvenance {
	t.Helper()
	gp, ok := p.(types.GitProvenance)
	require.True(t, ok, "provenance is %T, want types.GitProvenance", p)
	return gp
}

// requireContentBlobIDs checks that each reported blob ID is the hash of the
// reported content.
func requireContentBlobIDs(t *testing.T, calls []blobCall) {
	t.Helper()
	for _, c := range calls {
		require.Equal(t, types.ComputeBlobID([]byte(c.content)), c.blobID, "blob ID of %q", c.content)
	}
}

// occurrenceStrings lists the stored occurrences of id as "repo path".
func occurrenceStrings(t *testing.T, s store.Store, id types.BlobID) []string {
	t.Helper()
	occs, err := s.GetOccurrences(id)
	require.NoError(t, err)
	var got []string
	for _, o := range occs {
		got = append(got, o.Repository+" "+o.Path)
	}
	slices.Sort(got)
	return got
}

// --- GitHub API -----------------------------------------------------------

type fakeGHRepo struct {
	owner, name string
	files       map[string]string // path -> content
}

func blobSHA(content string) string {
	id := types.ComputeBlobID([]byte(content))
	return fmt.Sprintf("%x", id[:])
}

func newFakeGitHub(t *testing.T, repos []fakeGHRepo, contentHits *atomic.Int32) *httptest.Server {
	t.Helper()
	repoJSON := func(r fakeGHRepo) map[string]any {
		return map[string]any{
			"name": r.name, "full_name": r.owner + "/" + r.name, "default_branch": "main",
			"owner":     map[string]any{"login": r.owner},
			"clone_url": "https://u:secret@github.example.com/" + r.owner + "/" + r.name + ".git",
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/orgs/acme/repos", func(w http.ResponseWriter, _ *http.Request) {
		var out []map[string]any
		for _, r := range repos {
			out = append(out, repoJSON(r))
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	for _, r := range repos {
		base := "/api/v3/repos/" + r.owner + "/" + r.name
		mux.HandleFunc(base, func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(repoJSON(r))
		})
		mux.HandleFunc(base+"/git/trees/main", func(w http.ResponseWriter, _ *http.Request) {
			var entries []map[string]any
			for _, p := range slices.Sorted(maps.Keys(r.files)) {
				entries = append(entries, map[string]any{"path": p, "type": "blob", "sha": blobSHA(r.files[p]), "size": len(r.files[p])})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "root", "tree": entries, "truncated": false})
		})
		mux.HandleFunc(base+"/contents/", func(w http.ResponseWriter, req *http.Request) {
			contentHits.Add(1)
			p := strings.TrimPrefix(req.URL.Path, base+"/contents/")
			c, ok := r.files[p]
			if !ok {
				http.NotFound(w, req)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type": "file", "encoding": "base64", "path": p,
				"content": base64.StdEncoding.EncodeToString([]byte(c)),
			})
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func githubEnumFor(t *testing.T, srv *httptest.Server, cfg GitHubConfig) *GitHubEnumerator {
	t.Helper()
	c := github.NewClient(nil)
	u, err := url.Parse(srv.URL + "/api/v3/")
	require.NoError(t, err)
	c.BaseURL = u
	return &GitHubEnumerator{client: c, config: cfg}
}

func provByContent(t *testing.T, calls []blobCall) map[string]types.GitProvenance {
	t.Helper()
	out := map[string]types.GitProvenance{}
	for _, c := range calls {
		out[c.content] = gitProv(t, c.prov)
	}
	return out
}

// --- GitLab API -----------------------------------------------------------

func newFakeGitLab(t *testing.T, fullPath string, files map[string]string, rawHits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/api/v4/projects/7/repository/tree"):
			var nodes []map[string]any
			for _, fp := range slices.Sorted(maps.Keys(files)) {
				nodes = append(nodes, map[string]any{"id": blobSHA(files[fp]), "name": filepath.Base(fp), "type": "blob", "path": fp})
			}
			_ = json.NewEncoder(w).Encode(nodes)
		case strings.HasPrefix(p, "/api/v4/projects/7/repository/files/") && strings.HasSuffix(p, "/raw"):
			rawHits.Add(1)
			fp := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v4/projects/7/repository/files/"), "/raw")
			c, ok := files[fp]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(c))
		case strings.HasPrefix(p, "/api/v4/projects/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": 7, "path_with_namespace": fullPath, "default_branch": "main",
				"http_url_to_repo": "https://oauth2:secret@gitlab.example.com/" + fullPath + ".git",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}
