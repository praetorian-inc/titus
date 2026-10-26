package enum

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Contents unique to the round-7 fixtures, so each finding's blob is found
// by content alone.
const (
	r7PackedRefSecret = "R7_PACKED_WORKTREE_REF_SECRET=ghp_example\n"
	r7PseudorefSecret = "R7_PSEUDOREF_HEAD_SECRET=ghp_example\n"
	r7BadSymrefSecret = "R7_BAD_SYMREF_HEAD_SECRET=ghp_example\n"
	r7CountSecret     = "R7_WORKTREE_COUNT_SECRET=ghp_example\n"
)

// r7SkipIfGitOlder skips unless git is at least major.minor. Per-worktree
// refs (refs/worktree/*) need git 2.20.
func r7SkipIfGitOlder(t *testing.T, major, minor int) {
	t.Helper()
	skipIfNoGit(t)
	out, err := exec.Command("git", "version").Output()
	if err != nil {
		t.Skipf("git version: %v", err)
	}
	m := regexp.MustCompile(`git version (\d+)\.(\d+)`).FindStringSubmatch(string(out))
	if m == nil {
		t.Skipf("cannot parse %q", out)
	}
	maj, _ := strconv.Atoi(m[1])
	mnr, _ := strconv.Atoi(m[2])
	if maj < major || (maj == major && mnr < minor) {
		t.Skipf("git %d.%d is older than %d.%d", maj, mnr, major, minor)
	}
}

// assertCompleteOrMarked runs every walk over dir and enforces the
// location contract on the blob with content: either every location in want
// is reported with its commit (more is acceptable: over-reporting loses
// nothing), or the finding is marked as possibly missing locations and a
// warning says so. always must be reported in both cases: those locations
// are reached through ordinary common refs.
func assertCompleteOrMarked(t *testing.T, dir, content string, want, always []string) {
	t.Helper()
	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			prov, warn := walkProv(t, dir, walk, content)
			got := locSet(prov)
			for _, a := range always {
				if !slices.Contains(got, a) {
					t.Errorf("locations = %q, missing %s (truncated %v, warnings %q)", got, a, prov.LocationsTruncated, warn)
				}
			}
			if prov.LocationsTruncated {
				if strings.TrimSpace(warn) == "" {
					t.Errorf("marked as possibly missing locations with no warning saying why")
				}
				return
			}
			for _, w := range want {
				if !slices.Contains(got, w) {
					t.Errorf("location %s silently dropped: locations = %q, want %q, and the finding is not marked (warnings %q)", w, got, want, warn)
				}
			}
		})
	}
}

// F1: a per-worktree ref held only in the common packed-refs. git pack-refs
// never writes refs/worktree/* there (it leaves per-worktree refs loose), but
// git reads it: a worktree with no loose refs/worktree/pk falls back to the
// common packed-refs line, so rev-list --all from the worktree reaches the
// commit (checked on git 2.50.1 at runtime below). Such a line comes from a
// hand edit, a third-party tool, or an old git. The go-git walk drops every
// common-store per-worktree name in a linked worktree and adds back only the
// worktree's loose refs, so other.txt was lost with no marker (repro
// sec-r6/k7wt). From the worktree both walks must report other.txt with its
// commit, or mark the finding.
func TestGitHistory_PackedPerWorktreeRefKeepsCommit(t *testing.T) {
	r7SkipIfGitOlder(t, 2, 20)
	r := newR6Repo(t, r7PackedRefSecret)
	writeFile(t, filepath.Join(r.linked, "other.txt"), r7PackedRefSecret)
	pkCommit := commitAt(t, r.linked, "other", "2026-01-02T00:00:00Z")
	runGit(t, r.linked, "checkout", "-q", "--detach", r.mainCommit)

	common := gitOutput(t, r.main, "rev-parse", "--absolute-git-dir")
	if _, err := os.Stat(filepath.Join(common, "packed-refs")); err == nil {
		t.Fatal("fixture: a packed-refs file already exists")
	}
	writeFile(t, filepath.Join(common, "packed-refs"),
		"# pack-refs with: peeled fully-peeled sorted \n"+pkCommit+" refs/worktree/pk\n")

	// Fixture shape: refs/worktree/pk is not loose in either git dir, the
	// worktree HEAD is the main commit, and git from the worktree reaches
	// the packed-only commit.
	for _, gd := range []string{common, linkedGitDir(t, r.linked)} {
		if _, err := os.Lstat(filepath.Join(gd, "refs", "worktree", "pk")); err == nil {
			t.Fatalf("fixture: a loose refs/worktree/pk exists in %s", gd)
		}
	}
	if head := gitOutput(t, r.linked, "rev-parse", "HEAD"); head != r.mainCommit {
		t.Fatalf("fixture: worktree HEAD is %s, want %s", head, r.mainCommit)
	}
	cands := []locAt{{"main.txt", r.mainCommit}, {"other.txt", pkCommit}}
	fromLinked := reachableLocs(t, r.linked, cands...)
	if len(fromLinked) != 2 {
		t.Skipf("this git does not read a per-worktree ref from the common packed-refs: rev-list --all from the worktree reaches %q", fromLinked)
	}
	mainLoc := []string{"main.txt@" + r.mainCommit}

	t.Run("from linked", func(t *testing.T) {
		assertCompleteOrMarked(t, r.linked, r7PackedRefSecret, fromLinked, mainLoc)
	})
	// Control: from main the packed line is main's own per-worktree ref,
	// which go-git lists itself.
	t.Run("from main", func(t *testing.T) {
		assertCompleteOrMarked(t, r.main, r7PackedRefSecret, reachableLocs(t, r.main, cands...), mainLoc)
	})
}

// r7PseudorefRepo is an r6Repo whose linked worktree commits content at
// other.txt, then has its git dir hold MY_REF naming that commit and its
// HEAD file overwritten with head. No ref reaches the commit.
func r7PseudorefRepo(t *testing.T, content, head string) (r r6Repo, wtCommit string) {
	t.Helper()
	r7SkipIfGitOlder(t, 2, 20)
	r = newR6Repo(t, content)
	writeFile(t, filepath.Join(r.linked, "other.txt"), content)
	wtCommit = commitAt(t, r.linked, "other", "2026-01-02T00:00:00Z")
	gd := linkedGitDir(t, r.linked)
	writeFile(t, filepath.Join(gd, "MY_REF"), wtCommit+"\n")
	writeFile(t, filepath.Join(gd, "HEAD"), head)
	if refs := gitOutput(t, r.main, "for-each-ref", "--contains", wtCommit); refs != "" {
		t.Fatalf("fixture: common refs reach the worktree commit: %q", refs)
	}
	return r, wtCommit
}

// F2: a linked worktree whose HEAD is "ref: MY_REF", a one-level ALL_CAPS
// name outside refs/ that git's refname_is_safe accepts, held in the
// worktree's git dir (repro sec-r6/p7). git worktree list --porcelain from
// main resolves it (HEAD <commit>, branch MY_REF), and the native walk takes
// worktree HEADs from that list, so it reports other.txt. rev-list --all
// from main omits it (git looks the symref up in the wrong store, as in
// R6-1). go-git's parseSymref requires refs/, and readHeadFile then
// returned found=false, bad=false: the HEAD was skipped with no marker. From
// main both walks must report other.txt with its commit, or mark.
func TestGitHistory_WorktreeHeadSymrefToPseudoref(t *testing.T) {
	r, wtCommit := r7PseudorefRepo(t, r7PseudorefSecret, "ref: MY_REF\n")

	porcelain := gitOutput(t, r.main, "worktree", "list", "--porcelain")
	if !strings.Contains(porcelain, "HEAD "+wtCommit+"\nbranch MY_REF") {
		t.Skipf("this git does not resolve a worktree HEAD symref to MY_REF:\n%s", porcelain)
	}
	want := []string{"main.txt@" + r.mainCommit, "other.txt@" + wtCommit}
	assertCompleteOrMarked(t, r.main, r7PseudorefSecret, want, want[:1])
}

// F2b: a linked worktree whose HEAD is "ref: bad name\x01", which neither
// parseSymref nor git accepts. Expected behavior is set by what git and the
// native walk do (checked on git 2.50.1): rev-list --all from main succeeds
// and silently omits the worktree, and worktree list --porcelain prints the
// null id with no branch line. The native walk reads that null HEAD as a
// worktree HEAD it could not read and marks every finding (LocationsTruncated,
// "could not read the HEAD" warning). A commit the worktree held is no longer
// reachable through any name git resolves, but a scanner cannot tell what the
// corrupt HEAD meant, so it must not claim completeness: go-git must mark
// too, rather than silently skip as fe6721a did (found=false, bad=false).
func TestGitHistory_WorktreeHeadSymrefMalformedIsMarkedR7(t *testing.T) {
	r, wtCommit := r7PseudorefRepo(t, r7BadSymrefSecret, "ref: bad name\x01\n")

	// Fixture shape: git skips the worktree and reports its HEAD as null.
	cands := []locAt{{"main.txt", r.mainCommit}, {"other.txt", wtCommit}}
	mainLoc := []string{"main.txt@" + r.mainCommit}
	if got := reachableLocs(t, r.main, cands...); !slices.Equal(got, mainLoc) {
		t.Fatalf("fixture: rev-list --all from main reaches %q, want %q", got, mainLoc)
	}
	porcelain := gitOutput(t, r.main, "worktree", "list", "--porcelain")
	if !regexp.MustCompile(`/wt\nHEAD 0{40}(\n\n|\n?$)`).MatchString(porcelain) {
		t.Skipf("this git does not print the malformed worktree HEAD as a bare null id:\n%s", porcelain)
	}

	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			prov, warn := walkProv(t, r.main, walk, r7BadSymrefSecret)
			if got := locSet(prov); !slices.Contains(got, mainLoc[0]) {
				t.Errorf("locations = %q, missing %s", got, mainLoc[0])
			}
			if !prov.LocationsTruncated {
				t.Errorf("a worktree HEAD git would use but cannot be read was skipped silently: want the finding marked as possibly missing locations (locations %q, warnings %q)", locSet(prov), warn)
			}
			if strings.TrimSpace(warn) == "" {
				t.Errorf("no warning that a worktree HEAD could not be read")
			}
		})
	}
}

var r7WorktreeCountRE = regexp.MustCompile(`(\d+) linked git worktrees?`)

// F3: the lost-worktree warning counted per-worktree refs as if each were a
// worktree. With exactly one linked worktree it printed "could not read the
// HEAD of 2 (or 3) linked git worktrees" (repro sec-r6/l7wt). The marker is
// right, the count is not. The wording is changing, so this only requires
// the marker, a warning, and that no "N linked git worktrees" phrase claims
// more than the one that exists. Scanned from the linked worktree on go-git:
// in the bad-HEAD case git itself fails (rev-list --all: fatal: bad object),
// so the native walk returns an error, which is visible and out of scope.
func TestGitHistory_WorktreeWarningCountR7(t *testing.T) {
	for _, tc := range []struct {
		name, head string
		refs       map[string]string
	}{
		// sec-r6/l7wt: a symref loop a -> b -> a, HEAD fine.
		{"ref loop", "", map[string]string{"a": "ref: refs/worktree/b\n", "b": "ref: refs/worktree/a\n"}},
		// One bad per-worktree ref, and a HEAD through a self-looping one.
		{"bad ref and bad HEAD", "ref: refs/worktree/a\n", map[string]string{"a": "ref: refs/worktree/a\n", "b": "garbage\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r7SkipIfGitOlder(t, 2, 20)
			r := newR6Repo(t, r7CountSecret)
			gd := linkedGitDir(t, r.linked)
			if err := os.MkdirAll(filepath.Join(gd, "refs", "worktree"), 0o755); err != nil {
				t.Fatal(err)
			}
			for n, c := range tc.refs {
				writeFile(t, filepath.Join(gd, "refs", "worktree", n), c)
			}
			if tc.head != "" {
				writeFile(t, filepath.Join(gd, "HEAD"), tc.head)
			}
			if n := strings.Count(gitOutput(t, r.main, "worktree", "list", "--porcelain"), "worktree "); n != 2 {
				t.Fatalf("fixture: %d worktrees, want main and one linked", n)
			}

			prov, warn := walkProv(t, r.linked, enumWalks["go-git"], r7CountSecret)
			if !prov.LocationsTruncated {
				t.Errorf("bad per-worktree refs did not mark the finding (warnings %q)", warn)
			}
			if strings.TrimSpace(warn) == "" {
				t.Fatal("no warning for the unread per-worktree refs")
			}
			for _, m := range r7WorktreeCountRE.FindAllStringSubmatch(warn, -1) {
				if n, _ := strconv.Atoi(m[1]); n > 1 {
					t.Errorf("warning claims %d linked git worktrees, only 1 exists: %q", n, warn)
				}
			}
		})
	}
}
