package enum

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// addDetachedWorktree runs git worktree add --detach path from dir. It
// returns the combined output and the error instead of failing, so a caller
// can skip when the filesystem rejects the path.
func addDetachedWorktree(dir, path string) ([]byte, error) {
	cmd := exec.Command("git", "worktree", "add", "--detach", path)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PALATINE_TREE_ADD=1")
	return cmd.CombinedOutput()
}

// linkedWorktreeRepo is a main checkout and a linked worktree that share
// history up to base, then diverge: the worktree's detached HEAD has one
// commit no ref reaches, and the main branch has one the worktree never
// sees.
type linkedWorktreeRepo struct {
	main, linked                   string
	baseCommit, wtCommit, mainOnly string
}

const (
	wtBaseContent     = "WT_BASE=shared-history\n"
	wtDetachedSecret  = "WT_DETACHED_SECRET=ghp_example\n"
	wtMainOnlySecret  = "WT_MAIN_ONLY_SECRET=ghp_example\n"
	wtForgedSecret    = "WT_FORGED_SECRET=ghp_example\n"
	wtLegitHeadSecret = "WT_LEGIT_HEAD_SECRET=ghp_example\n"
)

func newLinkedWorktreeRepo(t *testing.T) linkedWorktreeRepo {
	t.Helper()
	r := linkedWorktreeRepo{main: t.TempDir(), linked: filepath.Join(t.TempDir(), "wt")}
	initGitRepo(t, r.main)
	writeFile(t, filepath.Join(r.main, "base.txt"), wtBaseContent)
	r.baseCommit = commitAt(t, r.main, "base", "2026-01-01T00:00:00Z")
	if out, err := addDetachedWorktree(r.main, r.linked); err != nil {
		t.Fatalf("git worktree add: %v\n%s", err, out)
	}
	writeFile(t, filepath.Join(r.linked, "wt.txt"), wtDetachedSecret)
	r.wtCommit = commitAt(t, r.linked, "wt", "2026-01-02T00:00:00Z")
	writeFile(t, filepath.Join(r.main, "main-only.txt"), wtMainOnlySecret)
	r.mainOnly = commitAt(t, r.main, "main only", "2026-01-03T00:00:00Z")

	// Fixture shape: no ref reaches the worktree commit, and the worktree
	// HEAD does not reach the main-only commit.
	if refs := gitOutput(t, r.main, "for-each-ref", "--contains", r.wtCommit); refs != "" {
		t.Fatalf("fixture: refs reach the worktree commit: %q", refs)
	}
	if gitOutput(t, r.linked, "rev-parse", "HEAD") != r.wtCommit {
		t.Fatal("fixture: the linked worktree HEAD is not the worktree commit")
	}
	return r
}

// R4-2: scanning from the linked worktree, both walks use the common
// directory: every blob is found, including the one only the main branch
// reaches, each with its commit, and nothing is reported as missing.
func TestGitHistory_ScanFromLinkedWorktreeUsesCommonDir(t *testing.T) {
	skipIfNoGit(t)
	r := newLinkedWorktreeRepo(t)
	want := map[string]blobProv{
		wtBaseContent:    {Paths: "base.txt", Commits: r.baseCommit},
		wtDetachedSecret: {Paths: "wt.txt", Commits: r.wtCommit},
		wtMainOnlySecret: {Paths: "main-only.txt", Commits: r.mainOnly},
	}
	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			got, warn := walkAllProv(t, r.linked, walk)
			for content, w := range want {
				g, ok := got[content]
				if !ok {
					t.Errorf("%q was not scanned (warnings %q)", content, warn)
					continue
				}
				if g != w {
					t.Errorf("%q provenance = %+v, want %+v", content, g, w)
				}
			}
			if strings.Contains(warn, missingObjectsWarning) {
				t.Errorf("warnings = %q, want no %q", warn, missingObjectsWarning)
			}
			if strings.Contains(warn, indexUnavailableWarning) {
				t.Errorf("warnings = %q, want no %q", warn, indexUnavailableWarning)
			}
		})
	}
}
