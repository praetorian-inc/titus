package explore

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

// End to end: real repository -> enumerator -> store -> Explore pane.

func exploreGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_AUTHOR_DATE=2024-01-02T03:04:05Z", "GIT_COMMITTER_DATE=2024-01-02T03:04:05Z")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
}

// exploreLines scans repo's whole history into a SQLite store, as titus scan
// does, and returns the Explore pane's location lines for the secret blob.
func exploreLines(t *testing.T, repo, secret string) []string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	s, err := store.NewSQLite(filepath.Join(t.TempDir(), "ds.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	e := enum.NewGitEnumerator(enum.Config{Root: repo})
	e.WalkAll = true
	id := types.ComputeBlobID([]byte(secret))
	seen := false
	require.NoError(t, e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		if string(content) != secret {
			return nil
		}
		seen = true
		require.NoError(t, s.AddBlob(blobID, int64(len(content))))
		require.NoError(t, s.AddProvenance(blobID, prov))
		return s.AddOccurrences(blobID, types.OccurrencesOf(prov))
	}))
	require.True(t, seen, "the secret blob was enumerated")

	row := buildMatchRow(&types.Match{BlobID: id, StructuralID: "m1"}, s)
	row.Location.Source.Start.Line = 1
	_, body := locationBlock(t, plainLines(row, nil, 500))
	return body
}

const exploreSecret = "token: synthetic_1_AbCd1234\n"

func exploreCommitFile(t *testing.T, repo, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644))
	exploreGit(t, repo, "add", "-A")
	exploreGit(t, repo, "commit", "-q", "--no-gpg-sign", "-m", name)
}

func TestExploreEndToEnd_CASE_EXPLORE_1_BranchOnLocationLine(t *testing.T) {
	repo := t.TempDir()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	exploreGit(t, repo, "init", "-q", "-b", "main")
	exploreCommitFile(t, repo, "config.yml", exploreSecret)
	exploreGit(t, repo, "checkout", "-q", "-b", "feature/login") // the commit is on main and feature/login

	lines := exploreLines(t, repo, exploreSecret)
	require.Len(t, lines, 1)
	assert.True(t, strings.HasSuffix(lines[0], "  2024-01-02  branch feature/login"), lines[0])
	assert.NotContains(t, lines[0], "branch main")
}

func TestExploreEndToEnd_CASE_OMIT_EXPLORE_1_DetachedOrphanHasNoBranch(t *testing.T) {
	repo := t.TempDir()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	exploreGit(t, repo, "init", "-q", "-b", "main")
	exploreCommitFile(t, repo, "base.txt", "base\n")
	exploreGit(t, repo, "checkout", "-q", "--detach")
	exploreCommitFile(t, repo, "config.yml", exploreSecret)

	lines := exploreLines(t, repo, exploreSecret)
	require.Len(t, lines, 1)
	assert.NotContains(t, lines[0], "branch")
	assert.True(t, strings.HasSuffix(lines[0], "  2024-01-02"), lines[0])
}
