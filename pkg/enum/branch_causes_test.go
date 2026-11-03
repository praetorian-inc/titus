package enum

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every fixture is a real git repository built with the git binary. Corrupt
// and missing objects are made by editing the object store of such a
// repository, which is how a damaged clone arises.

// --- remote names containing "/" ---------------------------------------------

// addRemote configures a remote by writing its config keys directly. Newer git
// refuses `git remote add a/b` when "a" exists (a remote name that is a
// subset of another), yet such a config is still readable, so the fixture
// bypasses the porcelain to stay independent of the git version.
func addRemote(t *testing.T, dir, name string) {
	t.Helper()
	runGit(t, dir, "config", "remote."+name+".url", "https://example.invalid/"+strings.ReplaceAll(name, "/", "-")+".git")
	runGit(t, dir, "config", "remote."+name+".fetch", "+refs/heads/*:refs/remotes/"+name+"/*")
}

// refs/remotes/a/b/c is branch "b/c" of remote "a" or branch "c" of remote
// "a/b". The configured remotes decide: the longest one that prefixes the ref
// wins and the rest, slashes included, is the branch.
func TestBranchShortName_ResolvesLongestConfiguredRemote(t *testing.T) {
	remotes := []string{"a", "a/b"}
	for ref, want := range map[string]string{
		"refs/heads/feature/x":  "feature/x",
		"refs/remotes/a/b/c":    "c",
		"refs/remotes/a/x/y":    "x/y",
		"refs/remotes/a/main":   "main",
		"refs/remotes/a/b/c/d":  "c/d",
		"refs/remotes/zz/q":     "",
		"refs/remotes/a":        "",
		"refs/remotes/a/":       "",
		"refs/remotes/a/HEAD":   "",
		"refs/remotes/a/b/HEAD": "",
		"refs/remotes/ab/c":     "",
		"refs/tags/v1":          "",
	} {
		assert.Equal(t, want, branchShortName(ref, remotes), ref)
	}
	// The order the remotes are listed in does not matter.
	assert.Equal(t, "c", branchShortName("refs/remotes/a/b/c", []string{"a/b", "a"}))
	assert.Equal(t, "", branchShortName("refs/remotes/a/b/c", nil), "no configured remote: omitted, never guessed")
}

func TestBranchResolver_RemoteNameContainingSlash_LongestRemoteWins(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "--detach")
	d1 := brCommit(t, dir, "d1")
	runGit(t, dir, "checkout", "-q", "--detach", c1)
	d2 := brCommit(t, dir, "d2")
	runGit(t, dir, "checkout", "-q", "--detach", c1)
	d3 := brCommit(t, dir, "d3")
	runGit(t, dir, "checkout", "-q", "main")
	addRemote(t, dir, "a")
	addRemote(t, dir, "a/b")
	runGit(t, dir, "update-ref", "refs/remotes/a/b/c", d1) // remote "a/b", branch "c" (not "b/c" of "a")
	runGit(t, dir, "update-ref", "refs/remotes/a/x/y", d2) // remote "a", branch "x/y": slashes kept
	runGit(t, dir, "update-ref", "refs/remotes/zz/q", d3)  // no remote "zz": omitted

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			assert.Equal(t, "main", r.of(c1))
			assert.Equal(t, "c", r.of(d1))
			assert.Equal(t, "x/y", r.of(d2))
			assert.Equal(t, "", r.of(d3), "a remote-tracking ref of no configured remote names no branch")
			assert.Empty(t, r.notes)
		})
	}
}

// --- note causes --------------------------------------------------------------

// The walk-lines bound has its own wording: it counts lines streamed, not
// commits, and must not read as the distinct-commit bound.
func TestBranchResolver_CapMaxOffHeadWalkLines_NoteNamesTheLinesBound(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	var off string
	for _, name := range []string{"a", "b", "c"} {
		runGit(t, dir, "checkout", "-q", "-b", name, c1)
		off = brCommit(t, dir, name+"1")
	}
	runGit(t, dir, "checkout", "-q", "main")

	setWalkLines(t, 2)
	want := offHeadNotePrefix + "more than 2 commits streamed across the branches' histories"
	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			assert.Equal(t, "", r.of(off))
			assert.Equal(t, []string{want}, r.notes)
			assert.NotContains(t, r.notes[0], "such commits", "not the distinct-commit bound's wording")
		})
	}
	// The distinct-commit bound keeps its own wording.
	setWalkLines(t, defaultMaxOffHeadWalkLines)
	setCaps(t, defaultMaxHeadCommits, defaultMaxBranches, 1)
	for backend, r := range resolversFor(t, dir) {
		t.Run(backend+"/distinct commits", func(t *testing.T) {
			assert.Equal(t, "", r.of(off))
			assert.Equal(t, []string{offHeadNotePrefix + "more than 1 such commits"}, r.notes)
		})
	}
}

func looseObjectPath(dir, id string) string {
	return filepath.Join(dir, ".git", "objects", id[:2], id[2:])
}

// corruptObject overwrites the loose object id of dir with garbage.
func corruptObject(t *testing.T, dir, id string) {
	t.Helper()
	path := looseObjectPath(dir, id)
	require.NoError(t, os.Chmod(path, 0o644))
	require.NoError(t, os.WriteFile(path, []byte("not a git object"), 0o644))
}

// HEAD names a commit, but its history cannot be read (an ancestor is gone):
// nothing is attributed, and the warning says why.
func TestBranchResolver_HeadHistoryUnreadable_NoteAndNothingResolved(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	c2 := brCommit(t, dir, "c2")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")
	require.NoError(t, os.Remove(looseObjectPath(dir, c1)))

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			for _, c := range []string{c1, c2, f1} {
				assert.Equal(t, "", r.of(c), "contains and checked-out cannot be told apart")
			}
			assert.Equal(t, []string{branchNoteHeadUnreadable}, r.notes)
			assert.Equal(t, "titus: branch not recorded: could not read HEAD's history\n", branchWarnings(r))
		})
	}
}

// An unborn HEAD is a legitimate state: the other branches still resolve and
// nothing is warned. A failed check is not, and says so.
func TestBranchResolver_UnbornHead_ResolvesOtherBranchesWithoutWarning(t *testing.T) {
	dir := brInit(t) // HEAD names refs/heads/main, which does not exist yet
	other := brInit(t)
	o1 := brCommit(t, other, "o1")
	runGit(t, dir, "fetch", "-q", other, "main:refs/heads/feature")

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			assert.Equal(t, "feature", r.of(o1), "no commit is on the unborn HEAD, so the one branch holding it is named")
			assert.Empty(t, r.notes)
			assert.Empty(t, branchWarnings(r))
		})
	}
}

func TestBranchResolver_HeadCheckFailed_NoteAndNothingResolved(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")
	corruptObject(t, dir, c1) // HEAD's own commit object is unreadable: not "unborn"

	rs := resolversFor(t, dir)
	t.Run("native", func(t *testing.T) {
		r := rs["native"]
		for _, c := range []string{c1, f1} {
			assert.Equal(t, "", r.of(c), "a failed check is not an unborn HEAD: nothing is attributed")
		}
		assert.Equal(t, []string{branchNoteHeadCheckFailed}, r.notes)
		assert.Equal(t, "titus: branch not recorded: could not check whether HEAD names a commit\n", branchWarnings(r))
	})
	// go-git reports a HEAD commit it cannot decode as plumbing.ErrReferenceNotFound,
	// the unborn signal, so the check cannot fail this way there. The outcome is
	// still closed: the walk of the branches reads the same object, fails, and
	// attributes nothing, with a warning.
	t.Run("go-git", func(t *testing.T) {
		r := rs["go-git"]
		for _, c := range []string{c1, f1} {
			assert.Equal(t, "", r.of(c))
		}
		require.Len(t, r.notes, 1)
		assert.Equal(t, offHeadNotePrefix+"could not read a branch's history", r.notes[0])
	})
}

// --- total ref bound ------------------------------------------------------------

func setRefCap(t *testing.T, n int) {
	t.Helper()
	old := maxBranchRefs
	maxBranchRefs = n
	t.Cleanup(func() { maxBranchRefs = old })
}

// Many remotes holding the same branch name stay under the short-name bound
// but are many refs: past maxBranchRefs the off-HEAD part is omitted, with a
// note that names this bound.
func TestBranchResolver_CapMaxBranchRefs_DuplicateShortNames(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")
	remotes := []string{"r1", "r2", "r3", "r4"}
	for _, r := range remotes {
		addRemote(t, dir, r)
		runGit(t, dir, "update-ref", "refs/remotes/"+r+"/feature", f1)
	}
	// Refs: main, feature and four remote-tracking: six refs, two short names.

	setRefCap(t, 5)
	for backend, r := range resolversFor(t, dir) {
		t.Run(backend+"/over the bound", func(t *testing.T) {
			assert.Equal(t, "", r.of(f1), "never guessed")
			assert.Equal(t, "main", r.of(c1), "the HEAD set does not depend on the ref bound")
			assert.Equal(t, []string{offHeadNotePrefix + "more than 5 branch refs"}, r.notes)
		})
	}
	setRefCap(t, 6)
	for backend, r := range resolversFor(t, dir) {
		t.Run(backend+"/at the bound", func(t *testing.T) {
			assert.Equal(t, "feature", r.of(f1))
			assert.Equal(t, "main", r.of(c1))
			assert.Empty(t, r.notes)
		})
	}
	// The listings return the dedicated sentinel, not the short-name bound's.
	setRefCap(t, 5)
	repo, err := openGoGitRepo(dir)
	require.NoError(t, err)
	_, _, err = nativeBranchRefs(context.Background(), dir, remotes)
	assert.ErrorIs(t, err, errBranchRefCap)
	_, err = goGitBranchTips(repo)
	assert.ErrorIs(t, err, errBranchRefCap)
}

// --- lazy off-HEAD part ------------------------------------------------------------

// countOffRuns wraps the resolver's lazy off-HEAD builder with a counter.
func countOffRuns(t *testing.T, r *branchResolver) *int32 {
	t.Helper()
	require.NotNil(t, r.lazyOff, "the off-HEAD part is lazy")
	var n int32
	orig := r.lazyOff
	r.lazyOff = func(ctx context.Context) {
		atomic.AddInt32(&n, 1)
		orig(ctx)
	}
	return &n
}

func TestBranchResolver_Lazy_NoOffHeadWorkWhenEveryCommitIsOnHead(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	c2 := brCommit(t, dir, "c2")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")
	setCaps(t, defaultMaxHeadCommits, 1, defaultMaxOffHeadCommits) // would warn if the off-HEAD part ran

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			runs := countOffRuns(t, r)
			var warn bytes.Buffer
			r.writeWarnings(&warn)
			assert.Equal(t, "main", r.of(c1))
			assert.Equal(t, "main", r.of(c2))
			assert.Equal(t, "", r.of("not-a-commit-id"))
			assert.Equal(t, int32(0), atomic.LoadInt32(runs), "no branch was walked")
			assert.False(t, r.offOK)
			assert.Empty(t, r.notes)
			assert.Empty(t, warn.String())
		})
	}
}

func TestBranchResolver_Lazy_OffHeadCommitRunsOnceAndWarnsOnce(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "a", c1)
	a1 := brCommit(t, dir, "a1")
	runGit(t, dir, "checkout", "-q", "-b", "b", c1)
	b1 := brCommit(t, dir, "b1")
	runGit(t, dir, "checkout", "-q", "main")

	t.Run("resolves", func(t *testing.T) {
		for backend, r := range resolversFor(t, dir) {
			t.Run(backend, func(t *testing.T) {
				runs := countOffRuns(t, r)
				assert.Equal(t, "main", r.of(c1))
				assert.Equal(t, int32(0), atomic.LoadInt32(runs))
				assert.Equal(t, "a", r.of(a1))
				assert.Equal(t, "b", r.of(b1))
				assert.Equal(t, "a", r.of(a1))
				assert.Equal(t, int32(1), atomic.LoadInt32(runs), "the off-HEAD part is built once")
				assert.Empty(t, r.notes)
			})
		}
	})

	t.Run("one warning when a bound is reached, sent to the writer given earlier", func(t *testing.T) {
		setCaps(t, defaultMaxHeadCommits, 1, defaultMaxOffHeadCommits)
		for backend, r := range resolversFor(t, dir) {
			t.Run(backend, func(t *testing.T) {
				var warn bytes.Buffer
				r.writeWarnings(&warn)
				assert.Empty(t, warn.String(), "nothing yet: the walk has not run")
				var wg sync.WaitGroup
				for range 16 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						assert.Equal(t, "", r.of(a1))
						assert.Equal(t, "", r.of(b1))
					}()
				}
				wg.Wait()
				assert.Equal(t, offHeadNotePrefix+"more than 1 branches\n", warn.String(), "exactly one line")
			})
		}
	})
}

// Concurrent first lookups of off-HEAD commits all see the same complete
// answer, and the walk runs once. Run under -race.
func TestBranchResolver_Lazy_ConcurrentFirstLookupsAgree(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	want := map[string]string{c1: "main"}
	for _, name := range []string{"a", "b", "c", "d"} {
		runGit(t, dir, "checkout", "-q", "-b", name, c1)
		want[brCommit(t, dir, name+"1")] = name
	}
	runGit(t, dir, "checkout", "-q", "main")

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			runs := countOffRuns(t, r)
			var wg sync.WaitGroup
			var bad atomic.Int32
			for range 32 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for c, w := range want {
						if r.of(c) != w {
							bad.Add(1)
						}
					}
				}()
			}
			wg.Wait()
			assert.Zero(t, bad.Load())
			assert.Equal(t, int32(1), atomic.LoadInt32(runs))
			assert.Empty(t, r.notes)
		})
	}
}

// The off-HEAD walk runs under the context bound to the resolver: a scan that
// is cancelled before the first off-HEAD lookup attributes nothing and says so.
func TestBranchResolver_Lazy_BoundContextCancelsTheWalk(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature", c1)
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			r.bindContext(ctx)
			cancel()
			assert.Equal(t, "main", r.of(c1), "the HEAD part was built before the cancel")
			assert.Equal(t, "", r.of(f1), "a cancelled walk attributes nothing")
			require.Len(t, r.notes, 1)
			assert.Contains(t, r.notes[0], offHeadNotePrefix)
		})
	}
}
