package enum

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Contents unique to the round-6 fixtures, so each finding's blob is found
// by content alone.
const (
	r6SymrefHeadSecret  = "R6_SYMREF_HEAD_SECRET=ghp_example\n"
	r6WorktreeRefSecret = "R6_WORKTREE_REF_SECRET=ghp_example\n"
	r6DanglingSecret    = "R6_DANGLING_HEAD_SECRET=ghp_example\n"
)

// locAt is one expected location of a blob: its path in a commit.
type locAt struct{ path, commit string }

// locSet returns the locations of prov as sorted "path@commit" strings, with
// "-" for a location that has no commit.
func locSet(prov types.GitProvenance) []string {
	out := make([]string, len(prov.Locations))
	for i, l := range prov.Locations {
		c := "-"
		if l.Commit != nil {
			c = l.Commit.CommitID
		}
		out[i] = l.Path + "@" + c
	}
	slices.Sort(out)
	return out
}

// reachableLocs keeps the candidates whose commit git rev-list --all, run
// from dir, reaches: the locations a complete scan of dir must report.
func reachableLocs(t *testing.T, dir string, candidates ...locAt) []string {
	t.Helper()
	all := strings.Fields(gitOutput(t, dir, "rev-list", "--all"))
	var out []string
	for _, c := range candidates {
		if slices.Contains(all, c.commit) {
			out = append(out, c.path+"@"+c.commit)
		}
	}
	slices.Sort(out)
	return out
}

// assertCompleteLocs runs every walk over dir and requires the blob with
// content at exactly want, every location with its commit, the finding not
// marked as possibly missing locations, and no warning that something was
// left out.
func assertCompleteLocs(t *testing.T, dir, content string, want []string) {
	t.Helper()
	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			prov, warn := walkProv(t, dir, walk, content)
			if got := locSet(prov); !slices.Equal(got, want) {
				t.Errorf("locations = %q, want %q (git rev-list --all reaches these) (truncated %v, warnings %q)", got, want, prov.LocationsTruncated, warn)
			}
			if prov.LocationsTruncated {
				t.Errorf("marked as possibly missing locations, want unmarked (warnings %q)", warn)
			}
			if n := missingCount(t, warn); n != 0 {
				t.Errorf("warnings = %q, want no missing-objects warning", warn)
			}
			if strings.Contains(warn, "could not read the HEAD") {
				t.Errorf("warnings = %q, want no unreadable-HEAD warning", warn)
			}
		})
	}
}

// r6Repo is a main checkout whose main branch commits content at main.txt,
// and a linked worktree detached at that commit.
type r6Repo struct{ main, linked, mainCommit string }

func newR6Repo(t *testing.T, content string) r6Repo {
	t.Helper()
	skipIfNoGit(t)
	r := r6Repo{main: t.TempDir(), linked: filepath.Join(t.TempDir(), "wt")}
	initGitRepo(t, r.main)
	writeFile(t, filepath.Join(r.main, "main.txt"), content)
	r.mainCommit = commitAt(t, r.main, "main", "2026-01-01T00:00:00Z")
	if out, err := addDetachedWorktree(r.main, r.linked); err != nil {
		t.Fatalf("git worktree add: %v\n%s", err, out)
	}
	return r
}

// R6-1, repro A: the linked worktree's HEAD is a symbolic ref to
// refs/worktree/w, a per-worktree ref that lives in the worktree's own git
// dir, not the common one. The commit it names holds the blob at other.txt.
// git rev-list --all from the worktree reaches it, so a scan from there
// must report other.txt with its commit.
//
// From the main checkout, git is inconsistent with itself. git worktree
// list in porcelain mode resolves the worktree's HEAD in that worktree's
// ref store and prints HEAD <commit> with branch refs/worktree/w, but
// rev-list --all (checked on git 2.50.1) looks the symref up in the main
// ref store, warns "ignoring dangling symref worktrees/<id>/HEAD", and
// skips it. The commit is the worktree's real HEAD, and every worktree
// HEAD is a tip (R4-1, R5-1), so the scan from main must report other.txt
// too: the same set as from the worktree, never fewer than rev-list --all
// from main reaches. The native walk takes its worktree HEADs from the
// porcelain list and already does this; go-git must agree with it.
func TestGitHistory_WorktreeHeadSymrefToPerWorktreeRef(t *testing.T) {
	r := newR6Repo(t, r6SymrefHeadSecret)
	writeFile(t, filepath.Join(r.linked, "other.txt"), r6SymrefHeadSecret)
	wtCommit := commitAt(t, r.linked, "other", "2026-01-02T00:00:00Z")
	runGit(t, r.linked, "update-ref", "refs/worktree/w", wtCommit)
	runGit(t, r.linked, "symbolic-ref", "HEAD", "refs/worktree/w")

	// Fixture shape: no common ref reaches the commit, the worktree HEAD
	// is the symbolic ref, and git from the worktree reaches the commit.
	if refs := gitOutput(t, r.main, "for-each-ref", "--contains", wtCommit); refs != "" {
		t.Fatalf("fixture: common refs reach the worktree commit: %q", refs)
	}
	if sym := gitOutput(t, r.linked, "symbolic-ref", "HEAD"); sym != "refs/worktree/w" {
		t.Fatalf("fixture: worktree HEAD is %q, want refs/worktree/w", sym)
	}
	cands := []locAt{{"main.txt", r.mainCommit}, {"other.txt", wtCommit}}
	fromLinked := reachableLocs(t, r.linked, cands...)
	if len(fromLinked) != 2 {
		t.Fatalf("fixture: rev-list --all from the worktree reaches %q, want both", fromLinked)
	}
	fromMain := reachableLocs(t, r.main, cands...)
	if !slices.Contains(fromMain, "main.txt@"+r.mainCommit) {
		t.Fatalf("fixture: rev-list --all from main reaches %q, want main.txt", fromMain)
	}
	if porcelain := gitOutput(t, r.main, "worktree", "list", "--porcelain"); !strings.Contains(porcelain, "HEAD "+wtCommit+"\nbranch refs/worktree/w") {
		t.Fatalf("fixture: worktree list from main does not resolve the worktree HEAD to %s:\n%s", wtCommit, porcelain)
	}

	t.Run("from linked", func(t *testing.T) {
		assertCompleteLocs(t, r.linked, r6SymrefHeadSecret, fromLinked)
	})
	t.Run("from main", func(t *testing.T) {
		assertCompleteLocs(t, r.main, r6SymrefHeadSecret, fromLinked)
	})
}

// R6-1, repro B and the bisect namespace: the linked worktree commits the
// blob at wtref.txt, keeps that commit only under a per-worktree ref, then
// detaches HEAD back at the main commit. git rev-list --all from the
// worktree walks its own per-worktree refs, so a scan from there must
// report wtref.txt with its commit. From the main checkout another
// worktree's private refs are not walked by git, so neither walk may
// report the location there either: parity with rev-list --all.
func TestGitHistory_PerWorktreeRefKeepsCommit(t *testing.T) {
	for _, ref := range []string{"refs/worktree/keep", "refs/bisect/bad"} {
		t.Run(ref, func(t *testing.T) {
			r := newR6Repo(t, r6WorktreeRefSecret)
			writeFile(t, filepath.Join(r.linked, "wtref.txt"), r6WorktreeRefSecret)
			wtCommit := commitAt(t, r.linked, "wtref", "2026-01-02T00:00:00Z")
			runGit(t, r.linked, "update-ref", ref, wtCommit)
			runGit(t, r.linked, "checkout", "-q", "--detach", r.mainCommit)

			// Fixture shape: only the per-worktree ref reaches the commit.
			if refs := gitOutput(t, r.main, "for-each-ref", "--contains", wtCommit); refs != "" {
				t.Fatalf("fixture: common refs reach the worktree commit: %q", refs)
			}
			if head := gitOutput(t, r.linked, "rev-parse", "HEAD"); head != r.mainCommit {
				t.Fatalf("fixture: worktree HEAD is %s, want %s", head, r.mainCommit)
			}
			cands := []locAt{{"main.txt", r.mainCommit}, {"wtref.txt", wtCommit}}
			fromLinked := reachableLocs(t, r.linked, cands...)
			if len(fromLinked) != 2 {
				t.Fatalf("fixture: rev-list --all from the worktree reaches %q, want both", fromLinked)
			}

			t.Run("from linked", func(t *testing.T) {
				assertCompleteLocs(t, r.linked, r6WorktreeRefSecret, fromLinked)
			})
			t.Run("from main", func(t *testing.T) {
				assertCompleteLocs(t, r.main, r6WorktreeRefSecret, reachableLocs(t, r.main, cands...))
			})
		})
	}
}

// R6-1 controls: a linked worktree whose HEAD is a symbolic ref to a ref
// that does not exist. The worktree first commits the blob at lost.txt,
// then its HEAD file is overwritten, so that commit is left unreachable.
//
// Why no mark is required, including for the per-worktree target (case 4
// of the round-6 brief): git treats both HEADs as unborn. Checked on git
// 2.50.1: git status in the worktree says "No commits yet", the porcelain
// worktree list prints the null id followed by a branch line naming the
// missing ref (the same shape as an unborn main, which the R5 heuristic
// does not count), and rev-list --all, from the worktree or from main,
// lists only the main commit. The fixture re-checks the rev-list part at
// runtime. A scan that reports main.txt alone therefore drops no location
// git would reach, so the contract ("every location reaches output, or the
// finding is marked") requires no mark, and marking here would be a false
// positive: it would flag every finding in a repository with an ordinary
// unborn worktree. Both walks must agree on that, from either checkout.
func TestGitHistory_WorktreeHeadSymrefToMissingRefIsUnborn(t *testing.T) {
	for _, target := range []string{"refs/worktree/gone", "refs/heads/nonexistent"} {
		t.Run(target, func(t *testing.T) {
			r := newR6Repo(t, r6DanglingSecret)
			writeFile(t, filepath.Join(r.linked, "lost.txt"), r6DanglingSecret)
			lostCommit := commitAt(t, r.linked, "lost", "2026-01-02T00:00:00Z")
			writeFile(t, filepath.Join(linkedGitDir(t, r.linked), "HEAD"), "ref: "+target+"\n")

			// Fixture shape: git sees an unborn HEAD and reaches nothing
			// beyond the main commit, from either checkout.
			cands := []locAt{{"main.txt", r.mainCommit}, {"lost.txt", lostCommit}}
			want := []string{"main.txt@" + r.mainCommit}
			for _, dir := range []string{r.linked, r.main} {
				if got := reachableLocs(t, dir, cands...); !slices.Equal(got, want) {
					t.Fatalf("fixture: rev-list --all from %s reaches %q, want %q", dir, got, want)
				}
			}
			if porcelain := gitOutput(t, r.main, "worktree", "list", "--porcelain"); !strings.Contains(porcelain, "branch "+target) {
				t.Fatalf("fixture: worktree list does not show the unborn branch %s:\n%s", target, porcelain)
			}

			t.Run("from linked", func(t *testing.T) {
				assertCompleteLocs(t, r.linked, r6DanglingSecret, want)
			})
			t.Run("from main", func(t *testing.T) {
				assertCompleteLocs(t, r.main, r6DanglingSecret, want)
			})
		})
	}
}
