package enum

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloneEnumerator_EmptyRepos(t *testing.T) {
	e := NewCloneEnumerator(nil, Config{})
	var count int
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestCloneEnumerator_InvalidURL(t *testing.T) {
	repos := []RepoInfo{
		{Name: "invalid/repo", CloneURL: "https://github.com/nonexistent-user-xyz123/nonexistent-repo-xyz123.git"},
	}
	e := NewCloneEnumerator(repos, Config{MaxFileSize: 10 * 1024 * 1024})

	var count int
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestCloneEnumerator_LocalRepo(t *testing.T) {
	tmpDir := t.TempDir()
	repoDir := filepath.Join(tmpDir, "test-repo")
	require.NoError(t, os.MkdirAll(repoDir, 0o755))

	cmds := [][]string{
		{"git", "init", repoDir},
		{"git", "-C", repoDir, "config", "user.email", "test@test.com"},
		{"git", "-C", repoDir, "config", "user.name", "Test"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		require.NoError(t, cmd.Run(), "failed running: %v", args)
	}

	testFile := filepath.Join(repoDir, "secret.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("this is a test file with content"), 0o644))

	cmd := exec.Command("git", "-C", repoDir, "add", ".")
	require.NoError(t, cmd.Run())
	cmd = exec.Command("git", "-C", repoDir, "commit", "-m", "initial commit")
	require.NoError(t, cmd.Run())

	repos := []RepoInfo{
		{Name: "test/repo", CloneURL: "file://" + repoDir},
	}
	e := NewCloneEnumerator(repos, Config{MaxFileSize: 10 * 1024 * 1024})

	var mu sync.Mutex
	var blobs []string
	var provenances []types.Provenance
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
		blobs = append(blobs, string(content))
		provenances = append(provenances, prov)
		return nil
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(blobs), 1, "should enumerate at least one blob")

	for _, prov := range provenances {
		gp, ok := prov.(types.GitProvenance)
		if ok {
			assert.Equal(t, "test/repo", gp.RepoPath, "provenance should use repo name, not temp path")
		}
	}
}

func TestCloneEnumerator_GitMode(t *testing.T) {
	tmpDir := t.TempDir()
	repoDir := filepath.Join(tmpDir, "test-repo")
	require.NoError(t, os.MkdirAll(repoDir, 0o755))

	cmds := [][]string{
		{"git", "init", repoDir},
		{"git", "-C", repoDir, "config", "user.email", "test@test.com"},
		{"git", "-C", repoDir, "config", "user.name", "Test"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		require.NoError(t, cmd.Run(), "failed running: %v", args)
	}

	testFile := filepath.Join(repoDir, "secret.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("this is a test file"), 0o644))

	cmd := exec.Command("git", "-C", repoDir, "add", ".")
	require.NoError(t, cmd.Run())
	cmd = exec.Command("git", "-C", repoDir, "commit", "-m", "initial commit")
	require.NoError(t, cmd.Run())

	repos := []RepoInfo{
		{Name: "test/repo", CloneURL: "file://" + repoDir},
	}
	e := NewCloneEnumerator(repos, Config{MaxFileSize: 10 * 1024 * 1024})
	e.Git = true

	var mu sync.Mutex
	var blobs []string
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
		blobs = append(blobs, string(content))
		// In git mode, provenance should be GitProvenance
		gp, ok := prov.(types.GitProvenance)
		assert.True(t, ok, "git mode should produce GitProvenance")
		if ok {
			assert.Equal(t, "test/repo", gp.RepoPath)
		}
		return nil
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(blobs), 1)
}

func TestCloneEnumerator_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	repos := []RepoInfo{
		{Name: "test/repo", CloneURL: "https://github.com/octocat/Hello-World.git"},
	}
	e := NewCloneEnumerator(repos, Config{})

	err := e.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		return nil
	})
	assert.ErrorIs(t, err, context.Canceled)
}

// --- clone ----------------------------------------------------------------

func TestCloneEnumerator_SameBlobTwoRepos(t *testing.T) {
	root := t.TempDir()
	makeRemoteFixture(t, root, "acme", "api", map[string]string{"k.txt": "token-SHARED"})
	makeRemoteFixture(t, root, "acme", "web", map[string]string{"conf/k.txt": "token-SHARED"})
	redirectHTTPSToLocal(t, root)

	for _, gitMode := range []bool{false, true} {
		t.Run(fmt.Sprintf("git=%v", gitMode), func(t *testing.T) {
			e := NewCloneEnumerator([]RepoInfo{
				{Name: "acme/api", CloneURL: fakeCredURL("https", "github.com/acme/api.git")},
				{Name: "acme/web", CloneURL: fakeCredURL("https", "github.com/acme/web.git")},
			}, Config{})
			e.Git = gitMode
			s := store.NewMemory()
			var mu sync.Mutex // filesystem mode calls back from parallel readers
			var ids []types.BlobID
			require.NoError(t, e.Enumerate(context.Background(), func(_ []byte, id types.BlobID, p types.Provenance) error {
				if isDotGit(p) {
					return nil
				}
				mu.Lock()
				ids = append(ids, id)
				mu.Unlock()
				return s.AddOccurrences(id, types.OccurrencesOf(p))
			}))
			require.Len(t, ids, 2)
			require.Equal(t, ids[0], ids[1], "same content, same blob")
			assert.Equal(t, []string{"github.com/acme/api k.txt", "github.com/acme/web conf/k.txt"}, occurrenceStrings(t, s, ids[0]))
		})
	}
}
