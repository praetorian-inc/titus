package enum

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Contents unique to the round-8 fixtures.
const (
	r8OtherHeadSecret = "R8_OTHER_HEAD_SECRET=ghp_example\n"
	r8MainHeadSecret  = "R8_MAIN_HEAD_SECRET=ghp_example\n"
	r8MixedCaseSecret = "R8_MIXED_CASE_SECRET=ghp_example\n"
)

const r8PackedHeader = "# pack-refs with: peeled fully-peeled sorted \n"

// r8Repo is an r6Repo (main commits main.txt at mainCommit, worktree "wt"
// is linked) plus a second linked worktree "wy" detached at mainCommit.
// otherCommit holds other.txt and is reached by no common ref; it is held
// only by a refs/worktree/pk line in the common packed-refs, and the
// worktree "wt" HEAD is "ref: refs/worktree/pk" with no loose pk of its own.
type r8Repo struct {
	r6Repo
	other, common, otherCommit string
}

func newR8Repo(t *testing.T, content string) r8Repo {
	t.Helper()
	r7SkipIfGitOlder(t, 2, 20)
	r := r8Repo{r6Repo: newR6Repo(t, content), other: filepath.Join(t.TempDir(), "wy")}
	if out, err := addDetachedWorktree(r.main, r.other); err != nil {
		t.Fatalf("git worktree add: %v\n%s", err, out)
	}
	writeFile(t, filepath.Join(r.linked, "other.txt"), content)
	r.otherCommit = commitAt(t, r.linked, "other", "2026-01-02T00:00:00Z")
	r.common = gitOutput(t, r.main, "rev-parse", "--absolute-git-dir")
	writeFile(t, filepath.Join(r.common, "packed-refs"), r8PackedHeader+r.otherCommit+" refs/worktree/pk\n")
	writeFile(t, filepath.Join(linkedGitDir(t, r.linked), "HEAD"), "ref: refs/worktree/pk\n")

	requireNoSharedRefContains(t, r.main, r.otherCommit)
	if _, err := os.Lstat(filepath.Join(r.common, "worktrees", "wt", "refs", "worktree", "pk")); err == nil {
		t.Fatal("fixture: worktree wt has a loose refs/worktree/pk")
	}
	return r
}

// requireNoSharedRefContains fails unless no branch or tag reaches commit,
// so only a worktree HEAD can make it a tip. (for-each-ref from main also
// lists the packed per-worktree line, which is why the namespaces are
// named.)
func requireNoSharedRefContains(t *testing.T, dir, commit string) {
	t.Helper()
	if refs := gitOutput(t, dir, "for-each-ref", "--contains", commit, "refs/heads", "refs/tags", "refs/remotes"); refs != "" {
		t.Fatalf("fixture: shared refs reach %s: %q", commit, refs)
	}
}

// writeRefFile writes content at name, creating its parent directories.
func writeRefFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, name, content)
}

// requireWorktreeHead skips unless git worktree list --porcelain, run from
// dir, resolves some worktree's HEAD to commit through branch ref: the
// worktree HEAD git itself reports, which every walk takes as a tip.
func requireWorktreeHead(t *testing.T, dir, commit, ref string) {
	t.Helper()
	porcelain := gitOutput(t, dir, "worktree", "list", "--porcelain")
	if !strings.Contains(porcelain, "HEAD "+commit+"\nbranch "+ref) {
		t.Skipf("this git does not resolve the worktree HEAD %s to the packed %s:\n%s", ref, commit, porcelain)
	}
}

// R8-1: another worktree's HEAD is a symref to refs/worktree/pk, a
// per-worktree name with no loose file in that worktree, so git falls back
// to the common packed-refs line and the HEAD is otherCommit (git worktree
// list --porcelain reports it). A loose copy of pk elsewhere names a
// different commit and must not shadow the packed line for this worktree:
//
//   - r8ay: the loose pk is in the scanned linked worktree wy;
//   - r8b: the loose pk is main's own, in the common dir, scanning from main.
//
// At 384308a go-git took the missing loose file as an unborn branch and
// dropped other.txt with no marker (main.txt@ only); the native walk
// reported it. Both walks must report both locations, unmarked.
func TestGitHistory_OtherWorktreeHeadFallsBackToPackedRef(t *testing.T) {
	for _, tc := range []struct {
		name  string
		loose func(r r8Repo) string // the gitdir that holds the loose pk
		scan  func(r r8Repo) string
	}{
		{"r8ay loose pk in scanned linked worktree", func(r r8Repo) string { return linkedGitDir(t, r.other) }, func(r r8Repo) string { return r.other }},
		{"r8b loose pk in common dir scanned from main", func(r r8Repo) string { return r.common }, func(r r8Repo) string { return r.main }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newR8Repo(t, r8OtherHeadSecret)
			writeRefFile(t, filepath.Join(tc.loose(r), "refs", "worktree", "pk"), r.mainCommit+"\n")
			dir := tc.scan(r)
			requireWorktreeHead(t, dir, r.otherCommit, "refs/worktree/pk")

			assertCompleteLocs(t, dir, r8OtherHeadSecret,
				[]string{"main.txt@" + r.mainCommit, "other.txt@" + r.otherCommit})
		})
	}
}

// R8-1 variant: the main checkout's HEAD is the symref to the packed-only
// refs/worktree/pk, and the scan runs from a linked worktree whose own loose
// pk names another commit. go-git reads the main HEAD from the common dir;
// the linked worktree's loose pk must not stand in for it, and the packed
// line must be found.
func TestGitHistory_MainHeadFromLinkedFallsBackToPackedRef(t *testing.T) {
	r7SkipIfGitOlder(t, 2, 20)
	r := newR6Repo(t, r8MainHeadSecret)
	runGit(t, r.main, "checkout", "-q", "--detach")
	writeFile(t, filepath.Join(r.main, "other.txt"), r8MainHeadSecret)
	otherCommit := commitAt(t, r.main, "other", "2026-01-02T00:00:00Z")
	common := gitOutput(t, r.main, "rev-parse", "--absolute-git-dir")
	writeFile(t, filepath.Join(common, "packed-refs"), r8PackedHeader+otherCommit+" refs/worktree/pk\n")
	writeFile(t, filepath.Join(common, "HEAD"), "ref: refs/worktree/pk\n")
	writeRefFile(t, filepath.Join(linkedGitDir(t, r.linked), "refs", "worktree", "pk"), r.mainCommit+"\n")

	requireNoSharedRefContains(t, r.linked, otherCommit)
	if _, err := os.Lstat(filepath.Join(common, "refs", "worktree", "pk")); err == nil {
		t.Fatal("fixture: main has a loose refs/worktree/pk")
	}
	requireWorktreeHead(t, r.linked, otherCommit, "refs/worktree/pk")

	assertCompleteLocs(t, r.linked, r8MainHeadSecret,
		[]string{"main.txt@" + r.mainCommit, "other.txt@" + otherCommit})
}

// R8-2: a worktree HEAD of "ref: My_Ref" (mixed case, not root ref syntax).
// git 2.50 takes it as unborn; parseSymref rejects the name, and go-git
// counts it as a HEAD it could not read: the finding is marked and a
// warning printed. That over-reports, which the contract allows; a silent
// skip would not be. main.txt is still reported on every walk.
func TestGitHistory_WorktreeHeadMixedCaseSymrefIsMarked(t *testing.T) {
	r, wtCommit := r7PseudorefRepo(t, r8MixedCaseSecret, "ref: My_Ref\n")
	// The HEAD no longer parses, so git cannot name the gitdir; it is
	// worktrees/wt under the common dir.
	common := gitOutput(t, r.main, "rev-parse", "--absolute-git-dir")
	writeFile(t, filepath.Join(common, "worktrees", "wt", "My_Ref"), wtCommit+"\n")
	mainLoc := "main.txt@" + r.mainCommit

	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			prov, warn := walkProv(t, r.main, walk, r8MixedCaseSecret)
			if got := locSet(prov); !strings.Contains(strings.Join(got, " "), mainLoc) {
				t.Errorf("locations = %q, missing %s", got, mainLoc)
			}
			if name != "go-git" {
				return
			}
			if !prov.LocationsTruncated {
				t.Errorf("ref: My_Ref was skipped silently: want the finding marked (locations %q, warnings %q)", locSet(prov), warn)
			}
			if !strings.Contains(warn, "could not read the HEAD") {
				t.Errorf("warnings = %q, want the unread-HEAD warning", warn)
			}
		})
	}
}
