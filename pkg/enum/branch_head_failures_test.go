package enum

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every fixture is a real git repository. HEAD and ref damage is made by
// writing the files git itself reads, so no fixture depends on a git version.

// writeGitFile replaces a file under dir/.git.
func writeGitFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, ".git", filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// --- HEAD cannot be read -------------------------------------------------------

// A HEAD file git cannot parse is a failed check, not a detached HEAD: without
// HEAD the off-HEAD walk could not exclude it, so a commit on the checked-out
// branch would be named after the other branch that also holds it.
func TestBranchResolver_NativeHeadUnreadable_NoteAndNothingAttributed(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")
	writeGitFile(t, dir, "HEAD", "this is not a ref\n")

	r := resolveBranchesNative(context.Background(), dir)
	for _, c := range []string{c1, f1} {
		assert.Equal(t, "", r.of(c), "no HEAD-less walk may attribute a branch")
	}
	assert.Equal(t, []string{branchNoteHeadCheckFailed}, r.notes)
	assert.Equal(t, "titus: branch not recorded: could not check whether HEAD names a commit\n", branchWarnings(r))
}

// A detached HEAD is not a failure: the off-HEAD rule applies and no note is
// written.
func TestBranchResolver_DetachedHead_OffHeadRuleNoNote(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "--detach", c1)

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			// c1 is on main and on feature, none checked out: two names.
			assert.Equal(t, "", r.of(c1))
			assert.Equal(t, "feature", r.of(f1))
			assert.Empty(t, r.notes)
		})
	}
}

// go-git reads a HEAD file it cannot parse as a hash reference rather than
// failing, so the read-error branch of goGitHead is not reachable from a repo
// built with git. This pins the outcome that is reachable: a commit on the
// checked-out branch is never named after another branch.
func TestBranchResolver_GoGitHeadGarbage_NeverAttributesWrongBranch(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")
	writeGitFile(t, dir, "HEAD", "this is not a ref\n")

	repo, err := openGoGitRepo(dir)
	if err != nil {
		t.Skipf("go-git rejects the repository outright (%v): the HEAD read error is closed before the resolver", err)
	}
	r := resolveBranchesGoGit(context.Background(), repo)
	assert.NotEqual(t, "feature", r.of(c1), "a commit on the checked-out branch must not be named after another")
}

// --- symbolic HEAD target ---------------------------------------------------------

// The symbolic HEAD names an existing branch whose commit object is gone: that
// is a failed check, never an unborn HEAD.
func TestBranchResolver_HeadCommitMissing_CheckFailedBothResolvers(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")
	require.NoError(t, os.Remove(looseObjectPath(dir, c1)))

	rs := resolversFor(t, dir)
	t.Run("go-git", func(t *testing.T) {
		r := rs["go-git"]
		for _, c := range []string{c1, f1} {
			assert.Equal(t, "", r.of(c), "a failed check attributes nothing")
		}
		assert.Equal(t, []string{branchNoteHeadCheckFailed}, r.notes)
	})
	// git itself reports a missing (not corrupt) HEAD commit through the
	// off-HEAD walk, with its own wording; the outcome is the same: nothing
	// is attributed and one warning says so.
	t.Run("native", func(t *testing.T) {
		r := rs["native"]
		for _, c := range []string{c1, f1} {
			assert.Equal(t, "", r.of(c), "a failed check attributes nothing")
		}
		assert.Len(t, r.notes, 1)
	})
}

// A symbolic HEAD whose target ref does not exist is unborn: the other
// branches still resolve and nothing is warned (go-git).
func TestBranchResolver_UnbornHead_GoGitResolvesOthersNoNote(t *testing.T) {
	dir := brInit(t) // HEAD names refs/heads/main, which does not exist
	other := brInit(t)
	o1 := brCommit(t, other, "o1")
	runGit(t, dir, "fetch", "-q", other, "main:refs/heads/feature")

	repo, err := openGoGitRepo(dir)
	require.NoError(t, err)
	r := resolveBranchesGoGit(context.Background(), repo)
	assert.Equal(t, "feature", r.of(o1))
	assert.Empty(t, r.notes)
}

// --- symbolic branch refs -------------------------------------------------------------

// alias -> feature: git for-each-ref reports alias as a second name for
// feature's commit, so the commit has two names and is attributed to neither.
// Both resolvers must agree.
func TestBranchResolver_SymbolicBranchAlias_TwoNamesAgree(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")
	runGit(t, dir, "symbolic-ref", "refs/heads/alias", "refs/heads/feature")

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			assert.Equal(t, "main", r.of(c1))
			assert.Equal(t, "", r.of(f1), "feature and alias both hold it")
			assert.Empty(t, r.notes)
		})
	}
}

// An alias is counted under its own name and its target's commit: pointing at
// a branch at a different commit makes that commit two-named, and leaves the
// other branch's commit alone.
func TestBranchResolver_SymbolicBranchAlias_ToDifferentCommit(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "-b", "other", c1)
	o1 := brCommit(t, dir, "o1")
	runGit(t, dir, "checkout", "-q", "main")
	runGit(t, dir, "symbolic-ref", "refs/heads/alias", "refs/heads/other")

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			assert.Equal(t, "feature", r.of(f1))
			assert.Equal(t, "", r.of(o1), "other and alias both hold it")
			assert.Empty(t, r.notes)
		})
	}
}

// A symbolic ref whose target does not exist names no commit and is skipped.
func TestBranchResolver_DanglingSymbolicBranchRef_Skipped(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")
	writeGitFile(t, dir, "refs/heads/dangling", "ref: refs/heads/does-not-exist\n")

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			assert.Equal(t, "main", r.of(c1))
			assert.Equal(t, "feature", r.of(f1))
			assert.Empty(t, r.notes)
		})
	}
}

// Two symbolic refs pointing at each other resolve to nothing and are skipped,
// and the resolver does not hang on them.
func TestBranchResolver_CyclicSymbolicBranchRefs_SkippedWithoutHang(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")
	writeGitFile(t, dir, "refs/heads/loop-a", "ref: refs/heads/loop-b\n")
	writeGitFile(t, dir, "refs/heads/loop-b", "ref: refs/heads/loop-a\n")

	done := make(chan map[string]*branchResolver, 1)
	go func() { done <- resolversFor(t, dir) }()
	select {
	case rs := <-done:
		for backend, r := range rs {
			t.Run(backend, func(t *testing.T) {
				assert.Equal(t, "main", r.of(c1))
				assert.Equal(t, "feature", r.of(f1))
			})
		}
	case <-time.After(30 * time.Second):
		t.Fatal("resolver hung on a symbolic ref cycle")
	}
}

// --- cancellation ------------------------------------------------------------------------

// A context cancelled before the synchronous HEAD walk yields an empty
// resolver: no commit is named, so none is named wrongly.
func TestBranchResolver_CancelledBeforeHeadWalk_Empty(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := resolveBranchesNative(ctx, dir)
	for _, c := range []string{c1, f1} {
		assert.Equal(t, "", r.of(c))
	}

	// buildBlobIndex under a cancelled context returns an error, not an index.
	idx, err := buildBlobIndex(ctx, dir)
	assert.Error(t, err)
	assert.Nil(t, idx)
}

// The lazy off-HEAD walk is bound to the scan context, not the build's: it
// still resolves after the caller's context passed to buildBlobIndex ends.
func TestBuildBlobIndex_LaterCancelledCaller_LazyOffHeadWalkStillResolves(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")

	ctx, cancel := context.WithCancel(context.Background())
	idx, err := buildBlobIndex(ctx, dir)
	require.NoError(t, err)
	cancel() // the caller's context ends after the index is built

	require.NotNil(t, idx.branch)
	assert.Equal(t, "main", idx.branch.of(c1), "HEAD part built before the cancel")
	assert.Equal(t, "feature", idx.branch.of(f1), "the lazy walk does not inherit the build context's cancel")
	assert.Empty(t, idx.branch.notes)
}
