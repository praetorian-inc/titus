package enum

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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

var missingCountRE = regexp.MustCompile(`titus: (\d+) ` + missingObjectsWarning)

// missingCount returns the count in the missing-objects warning, or 0 when
// there is none.
func missingCount(t *testing.T, warn string) int {
	t.Helper()
	m := missingCountRE.FindAllStringSubmatch(warn, -1)
	if len(m) == 0 {
		return 0
	}
	if len(m) > 1 {
		t.Errorf("more than one missing-objects warning: %q", warn)
	}
	n, err := strconv.Atoi(m[0][1])
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// R4-1: a secret committed only on a linked worktree's detached HEAD is
// reached by rev-list --all. Scanning the main checkout, both walks report
// it at wt.txt with its commit; go-git must not drop it silently.
func TestGitHistory_LinkedWorktreeDetachedHeadFromMain(t *testing.T) {
	skipIfNoGit(t)
	r := newLinkedWorktreeRepo(t)
	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			prov, warn := walkProv(t, r.main, walk, wtDetachedSecret)
			if got := locPaths(prov.Locations); strings.Join(got, ",") != "wt.txt" {
				t.Fatalf("locations = %q, want [wt.txt] (warnings %q)", got, warn)
			}
			if c := prov.Locations[0].Commit; c == nil || c.CommitID != r.wtCommit {
				t.Errorf("wt.txt commit = %v, want %s (warnings %q)", c, r.wtCommit, warn)
			}
			if prov.LocationsTruncated {
				t.Errorf("wt.txt is marked as possibly missing locations (warnings %q)", warn)
			}
			if strings.Contains(warn, missingObjectsWarning) || strings.Contains(warn, indexUnavailableWarning) {
				t.Errorf("warnings = %q, want none about missing objects or the index", warn)
			}
		})
	}
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

// R4-3: a worktree path holding a newline and "HEAD <id>" makes
// git worktree list --porcelain print a forged HEAD line. The forged id
// names a commit that exists but no ref or HEAD reaches, so it must not
// become a tip, and its blob must not be scanned. The worktree's real
// detached HEAD must still be a tip.
func TestGitHistory_WorktreePathCannotForgeHeadTip(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "base.txt"), wtBaseContent)
	base := commitAt(t, dir, "base", "2026-01-01T00:00:00Z")

	// A commit that exists but nothing points at.
	tree := gitInput(t, dir, []byte("100644 blob "+hashBlob(t, dir, wtForgedSecret)+"\tforged.txt\n"), "mktree")
	forged := gitInput(t, dir, []byte("forged\n"), "commit-tree", tree, "-p", base)

	linked := filepath.Join(t.TempDir(), "wt\nHEAD "+forged)
	if out, err := addDetachedWorktree(dir, linked); err != nil {
		t.Skipf("cannot create a worktree path with a newline here: %v\n%s", err, out)
	}
	writeFile(t, filepath.Join(linked, "legit.txt"), wtLegitHeadSecret)
	legit := commitAt(t, linked, "legit", "2026-01-02T00:00:00Z")

	// Fixture shape: the porcelain output really carries the forged line,
	// and nothing else reaches the forged commit.
	porcelain := gitOutput(t, dir, "worktree", "list", "--porcelain")
	if !slices.Contains(strings.Split(porcelain, "\n"), "HEAD "+forged) {
		t.Skipf("this git does not print the path unquoted, so the line cannot be forged:\n%s", porcelain)
	}
	if all := gitOutput(t, dir, "rev-list", "--all"); strings.Contains(all, forged) {
		t.Fatal("fixture: rev-list --all reaches the forged commit")
	}

	tips, err := resolveRefTips(context.Background(), dir)
	if err != nil {
		t.Fatalf("resolveRefTips: %v", err)
	}
	if slices.Contains(tips.commits, forged) {
		t.Errorf("tips = %q, include the forged id %s", tips.commits, forged)
	}
	if !slices.Contains(tips.commits, legit) {
		t.Errorf("tips = %q, want the worktree's real HEAD %s", tips.commits, legit)
	}

	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			seen, warn := runWalkWarn(t, dir, walk)
			if seen[wtForgedSecret] {
				t.Errorf("the blob of the forged commit was scanned (warnings %q)", warn)
			}
			if !seen[wtLegitHeadSecret] {
				t.Errorf("the blob of the worktree's real HEAD was not scanned (warnings %q)", warn)
			}
		})
	}
}

// R4-5: one missing tree that a ref names directly and a tagged tree holds
// as a subtree is one missing object on both walks.
func TestGitHistory_MissingTreeViaRefAndSubtreeCountedOnce(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "base.txt"), "base\n")
	commitAt(t, dir, "base", "2026-01-01T00:00:00Z")

	const (
		lost    = "LOST=under-a-missing-tree\n"
		sibling = "SIBLING=beside-the-missing-tree\n"
	)
	sub := gitInput(t, dir, []byte("100644 blob "+hashBlob(t, dir, lost)+"\tlost.env\n"), "mktree")
	tree := gitInput(t, dir, []byte("040000 tree "+sub+"\ta\n100644 blob "+hashBlob(t, dir, sibling)+"\tb.env\n"), "mktree")
	runGit(t, dir, "update-ref", "refs/tags/tt", tree)
	runGit(t, dir, "update-ref", "refs/tags/direct", sub)
	if err := os.Remove(filepath.Join(dir, ".git", "objects", sub[:2], sub[2:])); err != nil {
		t.Fatalf("fixture: remove tree object: %v", err)
	}

	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			seen, warn := runWalkWarn(t, dir, walk)
			if !seen[sibling] {
				t.Errorf("the tagged tree's other entry was not scanned (warnings %q)", warn)
			}
			if n := missingCount(t, warn); n != 1 {
				t.Errorf("missing-object count = %d, want 1 (warnings %q)", n, warn)
			}
		})
	}
}
