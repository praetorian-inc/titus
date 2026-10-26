package enum

import (
	"context"
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
