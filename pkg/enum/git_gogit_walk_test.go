package enum

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// assertGoGitMatchesNative runs both history walks over dir and fails for
// every blob that differs, and for any wanted content either walk missed.
func assertGoGitMatchesNative(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	native := describeRun(runNative(t, nativeEnum(dir)))
	gogit := describeRun(runGoGit(t, nativeEnum(dir)))
	for name, content := range want {
		id := types.ComputeBlobID([]byte(content))
		if _, ok := native[id]; !ok {
			t.Errorf("native walk missed the %s blob", name)
		}
		if _, ok := gogit[id]; !ok {
			t.Errorf("go-git walk missed the %s blob", name)
		}
	}
	for id, n := range native {
		if gogit[id] != n {
			t.Errorf("blob %s differs\nnative: %s\ngo-git: %s", id.Hex(), n, gogit[id])
		}
	}
	for id, g := range gogit {
		if _, ok := native[id]; !ok {
			t.Errorf("go-git has blob %s that native lacks: %s", id.Hex(), g)
		}
	}
}

// A ref whose tip is a merge with a first parent already reached from HEAD
// must still walk the merge's other parent. go-git's Log(All) stops each ref
// at the first known commit and never reaches that side.
func TestGoGitHistory_MergeBehindKnownCommit(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "base.txt"), "base\n")
	baseCommit := commitAt(t, dir, "base", "2026-01-01T00:00:00Z")
	base := gitOutput(t, dir, "rev-parse", "--abbrev-ref", "HEAD")

	runGit(t, dir, "checkout", "-q", "-b", "side")
	writeFile(t, filepath.Join(dir, "transient.env"), "only on the side branch\n")
	sideAdd := commitAt(t, dir, "side add", "2026-02-01T00:00:00Z")
	runGit(t, dir, "rm", "-q", "transient.env")
	commitAt(t, dir, "side remove", "2026-02-02T00:00:00Z")

	runGit(t, dir, "checkout", "-q", "-b", "tip", base)
	runGitEnv(t, dir, []string{"GIT_AUTHOR_DATE=2026-03-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-03-01T00:00:00Z"},
		"merge", "-q", "--no-ff", "--no-gpg-sign", "-m", "merge side", "side")
	runGit(t, dir, "checkout", "-q", base)
	runGit(t, dir, "branch", "-q", "-D", "side")

	// Fixture shape: the merge's first parent is the commit HEAD already
	// reaches, and the commit adding transient.env is reachable only through
	// the merge's second parent. Without this shape the test proves nothing.
	if got := gitOutput(t, dir, "rev-parse", "tip^1"); got != baseCommit {
		t.Fatalf("tip^1 = %s, want base commit %s", got, baseCommit)
	}
	if got := gitOutput(t, dir, "branch", "--format=%(refname:short)", "--contains", sideAdd); got != "tip" {
		t.Fatalf("branches containing the side commit = %q, want only %q", got, "tip")
	}

	assertGoGitMatchesNative(t, dir, map[string]string{"transient.env": "only on the side branch\n"})
}

// A commit reachable only through an annotated tag is part of --all.
func TestGoGitHistory_AnnotatedTagOnly(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "base.txt"), "base\n")
	commitAt(t, dir, "base", "2026-01-01T00:00:00Z")
	base := gitOutput(t, dir, "rev-parse", "--abbrev-ref", "HEAD")

	runGit(t, dir, "checkout", "-q", "--detach")
	writeFile(t, filepath.Join(dir, "release.env"), "tagged only\n")
	release := commitAt(t, dir, "release", "2026-02-01T00:00:00Z")
	// tag.gpgSign=false: a global signing config must not break the fixture.
	runGit(t, dir, "-c", "tag.gpgSign=false", "tag", "-a", "-m", "v1", "v1")
	runGit(t, dir, "checkout", "-q", base)

	// Fixture shape: v1 is an annotated tag object, and no branch reaches
	// the release commit, so the tag is its only route.
	if got := gitOutput(t, dir, "cat-file", "-t", "v1"); got != "tag" {
		t.Fatalf("v1 object type = %q, want an annotated tag", got)
	}
	if got := gitOutput(t, dir, "branch", "--format=%(refname:short)", "--contains", release); got != "" {
		t.Fatalf("branches containing the release commit = %q, want none", got)
	}

	assertGoGitMatchesNative(t, dir, map[string]string{"release.env": "tagged only\n"})
}

// A cancelled context stops the go-git history walk with ctx.Err().
func TestGoGitHistory_Cancelled(t *testing.T) {
	skipIfNoGit(t)
	dir, _, _, _ := parityFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := nativeEnum(dir).enumerateAllHistory(ctx, func([]byte, types.BlobID, types.Provenance) error {
		t.Fatal("callback ran after cancellation")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// M4: tags that point at a tree or a blob, not a commit, are part of --all.
// The go-git walk must scan what they reach, exactly as the native walk does.
func TestGoGitHistory_TagsToTreesAndBlobs(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "base.txt"), "base\n")
	commitAt(t, dir, "base", "2026-01-01T00:00:00Z")

	const (
		inTree      = "TREE_TAGGED=reachable-only-through-a-tagged-tree\n"
		annotated   = "BLOB_TAGGED=reachable-only-through-an-annotated-tag\n"
		lightweight = "LIGHT_TAGGED=reachable-only-through-a-lightweight-tag\n"
	)
	tree := gitInput(t, dir, []byte("100644 blob "+hashBlob(t, dir, inTree)+"\tinner.env\n"), "mktree")
	runGit(t, dir, "-c", "tag.gpgSign=false", "tag", "-a", "-m", "t", "tree-tag", tree)
	runGit(t, dir, "-c", "tag.gpgSign=false", "tag", "-a", "-m", "b", "blob-tag", hashBlob(t, dir, annotated))
	runGit(t, dir, "tag", "light-blob", hashBlob(t, dir, lightweight))

	// Fixture shape: two annotated tags (to a tree and a blob) and one
	// lightweight tag to a blob; no commit reaches any of the three blobs.
	for tag, want := range map[string]string{"tree-tag": "tree", "blob-tag": "blob", "light-blob": "blob"} {
		if got := gitOutput(t, dir, "cat-file", "-t", tag+"^{}"); got != want {
			t.Fatalf("%s peels to %q, want %q", tag, got, want)
		}
	}

	assertGoGitMatchesNative(t, dir, map[string]string{
		"tagged tree's inner.env": inTree,
		"annotated-tag blob":      annotated,
		"lightweight-tag blob":    lightweight,
	})
}
