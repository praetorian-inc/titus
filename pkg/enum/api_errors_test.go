package enum

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
