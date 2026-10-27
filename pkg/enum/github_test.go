package enum

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGitHubEnumerator_Construction tests that we can create a GitHub enumerator.
func TestGitHubEnumerator_Construction(t *testing.T) {
	config := GitHubConfig{
		Token: "test-token",
		Owner: "owner",
		Repo:  "repo",
		Config: Config{
			MaxFileSize: 10 * 1024 * 1024,
		},
	}

	enumerator, err := NewGitHubEnumerator(config)
	if err != nil {
		t.Fatalf("failed to create GitHub enumerator: %v", err)
	}

	if enumerator == nil {
		t.Fatal("enumerator is nil")
	}
}

// TestGitHubEnumerator_Interface verifies GitHubEnumerator implements Enumerator.
func TestGitHubEnumerator_Interface(t *testing.T) {
	config := GitHubConfig{
		Token: "test-token",
		Owner: "owner",
		Repo:  "repo",
		Config: Config{
			MaxFileSize: 10 * 1024 * 1024,
		},
	}

	enumerator, err := NewGitHubEnumerator(config)
	if err != nil {
		t.Fatalf("failed to create GitHub enumerator: %v", err)
	}

	// Verify it implements Enumerator interface
	var _ Enumerator = enumerator
}

// TestGitHubEnumerator_TokenOptional tests that token is optional (unauthenticated access allowed).
func TestGitHubEnumerator_TokenOptional(t *testing.T) {
	config := GitHubConfig{
		Token: "",
		Owner: "owner",
		Repo:  "repo",
	}

	enumerator, err := NewGitHubEnumerator(config)
	if err != nil {
		t.Fatalf("expected no error with empty token, got: %v", err)
	}
	if enumerator == nil {
		t.Fatal("expected non-nil enumerator")
	}
}

// TestGitHubEnumerator_RequiresTarget tests that owner/org/user is required.
func TestGitHubEnumerator_RequiresTarget(t *testing.T) {
	config := GitHubConfig{
		Token: "test-token",
		// No Owner, Org, or User specified
	}

	enumerator, err := NewGitHubEnumerator(config)
	if err != nil {
		t.Fatalf("construction should succeed, enumeration should fail: %v", err)
	}

	// Should fail during enumeration
	ctx := context.Background()
	err = enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		return nil
	})

	if err == nil {
		t.Fatal("expected error when no owner/org/user specified, got nil")
	}
}

func TestGitHubEnumerator_RemoteIdentityOneCallbackPerBlob(t *testing.T) {
	repo := fakeGHRepo{"acme", "api", map[string]string{"a.txt": "token-DUP", "b/c.txt": "token-DUP", "d.txt": "token-ONE"}}
	for _, tc := range []struct{ baseURL, want string }{
		{"", "github.com/acme/api"},
		{"https://github.example.com", "github.example.com/acme/api"},
		{"https://GitHub.Example.com:8443/", "github.example.com/acme/api"},
	} {
		t.Run(tc.want+tc.baseURL, func(t *testing.T) {
			var hits atomic.Int32
			srv := newFakeGitHub(t, []fakeGHRepo{repo}, &hits)
			e := githubEnumFor(t, srv, GitHubConfig{BaseURL: tc.baseURL, Owner: "acme", Repo: "api"})
			calls := collectBlobs(t, func(cb blobCallback) error { return e.Enumerate(context.Background(), cb) })

			require.Len(t, calls, 2, "one callback per distinct blob")
			requireContentBlobIDs(t, calls)
			byContent := provByContent(t, calls)
			dup := byContent["token-DUP"]
			assert.Equal(t, tc.want, dup.RepoPath)
			assert.True(t, dup.RemoteIdentity)
			assert.Empty(t, dup.RepoRoot)
			assert.Equal(t, []string{"a.txt", "b/c.txt"}, locationPaths(dup))
			assert.Equal(t, "a.txt", dup.BlobPath)
			assert.Equal(t, []string{"d.txt"}, locationPaths(byContent["token-ONE"]))
			assert.EqualValues(t, 2, hits.Load(), "content fetched once per blob")
			assert.NotContains(t, fmt.Sprintf("%+v", calls), "secret")
		})
	}
}

func TestGitHubEnumerator_ListRepoURLsNameHasNoCredential(t *testing.T) {
	var hits atomic.Int32
	srv := newFakeGitHub(t, []fakeGHRepo{{"acme", "api", map[string]string{"a": "b"}}}, &hits)
	e := githubEnumFor(t, srv, GitHubConfig{BaseURL: "https://github.example.com", Org: "acme"})
	repos, err := e.ListRepoURLs(context.Background())
	require.NoError(t, err)
	require.Len(t, repos, 1)
	assert.Equal(t, "acme/api", repos[0].Name)
}

func TestGitHubEnumerator_SameBlobTwoRepos(t *testing.T) {
	var hits atomic.Int32
	srv := newFakeGitHub(t, []fakeGHRepo{
		{"acme", "api", map[string]string{"k.txt": "token-SHARED"}},
		{"acme", "web", map[string]string{"conf/k.txt": "token-SHARED"}},
	}, &hits)
	e := githubEnumFor(t, srv, GitHubConfig{Org: "acme"})
	s := store.NewMemory()
	var ids []types.BlobID
	require.NoError(t, e.Enumerate(context.Background(), func(_ []byte, id types.BlobID, p types.Provenance) error {
		ids = append(ids, id)
		return s.AddOccurrences(id, types.OccurrencesOf(p))
	}))
	require.Len(t, ids, 2)
	require.Equal(t, ids[0], ids[1], "same content, same blob")
	assert.Equal(t, []string{"github.com/acme/api k.txt", "github.com/acme/web conf/k.txt"}, occurrenceStrings(t, s, ids[0]))
}

func TestAPIRepoIdentity(t *testing.T) {
	tests := []struct {
		name, baseURL, defaultHost, fullPath, want string
	}{
		{"default host", "", "github.com", "acme/api", "github.com/acme/api"},
		{"enterprise github host", "https://github.example.com", "github.com", "acme/api", "github.example.com/acme/api"},
		{"self-managed gitlab host", "https://gitlab.example.com", "gitlab.com", "acme/api", "gitlab.example.com/acme/api"},
		{"invalid path falls back to sanitized typed name", "https://", "github.com", "acme/api\x1b", `acme/api\x1b`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, apiRepoIdentity(tt.baseURL, tt.defaultHost, tt.fullPath))
		})
	}
}
