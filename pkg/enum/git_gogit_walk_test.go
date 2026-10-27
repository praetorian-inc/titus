package enum

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

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

// treeBomb writes a tree of depth levels in which each level names the level
// below twice, so depth+1 tree objects expand to 2^depth paths, and tags it.
// It returns the content of the one blob at the bottom.
func treeBomb(t *testing.T, dir string, depth int) string {
	t.Helper()
	const leaf = "BOMB_LEAF=one-blob-under-every-path\n"
	tree := gitInput(t, dir, []byte("100644 blob "+hashBlob(t, dir, leaf)+"\tf\n"), "mktree")
	for range depth {
		tree = gitInput(t, dir, []byte("040000 tree "+tree+"\tx\n040000 tree "+tree+"\ty\n"), "mktree")
	}
	runGit(t, dir, "tag", "bomb", tree)
	return leaf
}

// N1: a tagged tree that names the same subtree many times is walked once
// per distinct tree, as rev-list --objects does, not once per path. A
// depth-20 bomb (2^20 paths, 21 tree objects) must finish; a per-path walk
// does not finish inside the 5 s bound.
func TestGoGitHistory_TaggedTreeBomb(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "base.txt"), "base\n")
	commitAt(t, dir, "base", "2026-01-01T00:00:00Z")
	leaf := treeBomb(t, dir, 20)

	repo, err := git.PlainOpen(dir)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		blobs []blobEntry
		err   error
	}
	done := make(chan result, 1)
	go func() {
		blobs, _, _, err := goGitHistoryIndex(context.Background(), repo)
		done <- result{blobs, err}
	}()
	var r result
	select {
	case r = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("go-git walk of a depth-20 tagged tree bomb did not finish in 5 s: subtrees are walked per path")
	}
	if r.err != nil {
		t.Fatalf("goGitHistoryIndex: %v", r.err)
	}
	want := strings.Repeat("x/", 20) + "f"
	leafHash := contentHash(leaf)
	found := false
	for _, b := range r.blobs {
		if b.hash == leafHash {
			found = true
			if b.path != want {
				t.Errorf("leaf path = %q, want %q (rev-list's first path)", b.path, want)
			}
		}
	}
	if !found {
		t.Error("the bomb's leaf blob was not scanned")
	}
	assertGoGitMatchesNative(t, dir, map[string]string{"bomb leaf": leaf})
}

// N1: the tagged-tree walk checks the context itself, not only between
// tagged roots.
func TestGoGitHistory_TaggedTreeWalkCancelled(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	treeBomb(t, dir, 2)
	repo, err := git.PlainOpen(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, typ, err := peelRef(repo, plumbing.NewHash(gitOutput(t, dir, "rev-parse", "bomb")))
	if err != nil || typ != plumbing.TreeObject {
		t.Fatalf("fixture: peel bomb = %v, %v", typ, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := newTaggedWalk(repo, nil, map[[20]byte]struct{}{}, &indexStats{})
	if err := w.add(ctx, taggedObject{hash: h, typ: typ}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// enumWalks are the two history walks, keyed by name, for tests that
// assert the same behavior on both.
var enumWalks = map[string]func(*GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error{
	"native": func(e *GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error {
		return e.enumerateAllHistoryNative
	},
	"go-git": func(e *GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error {
		return e.enumerateAllHistory
	},
}

// runWalkWarn runs one walk over dir and returns the scanned contents and
// the warnings.
func runWalkWarn(t *testing.T, dir string, walk func(*GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error) (map[string]bool, string) {
	t.Helper()
	e := nativeEnum(dir)
	var warn bytes.Buffer
	e.warn = &warn
	seen := map[string]bool{}
	err := walk(e)(context.Background(), func(content []byte, _ types.BlobID, _ types.Provenance) error {
		seen[string(content)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v (warnings %q)", err, warn.String())
	}
	return seen, warn.String()
}

// N2: a subtree missing from the repository is counted and reported, and
// the tagged tree's other entries are still scanned, on both walks.
func TestGoGitHistory_TaggedTreeMissingSubtree(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "base.txt"), "base\n")
	commitAt(t, dir, "base", "2026-01-01T00:00:00Z")

	const (
		lost    = "LOST=under-a-missing-subtree\n"
		sibling = "SIBLING=after-the-missing-subtree\n"
	)
	sub := gitInput(t, dir, []byte("100644 blob "+hashBlob(t, dir, lost)+"\tlost.env\n"), "mktree")
	tree := gitInput(t, dir, []byte("040000 tree "+sub+"\ta\n100644 blob "+hashBlob(t, dir, sibling)+"\tb.env\n"), "mktree")
	runGit(t, dir, "tag", "partial", tree)
	if err := os.Remove(filepath.Join(dir, ".git", "objects", sub[:2], sub[2:])); err != nil {
		t.Fatalf("fixture: remove subtree object: %v", err)
	}

	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			seen, warn := runWalkWarn(t, dir, walk)
			if !seen[sibling] {
				t.Error("b.env, the missing subtree's sibling, was not scanned")
			}
			if want := "titus: 1 git objects are missing"; !strings.Contains(warn, want) {
				t.Errorf("warnings = %q, want %q", warn, want)
			}
		})
	}
}

// R2: a tagged-tree path over maxRecord is dropped and counted in the
// over-long warning on both walks; the blob is still scanned.
func TestGoGitHistory_TaggedTreeOverlongPath(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "base.txt"), "base\n")
	commitAt(t, dir, "base", "2026-01-01T00:00:00Z")

	const content = "LONG=path-over-max-record\n"
	id, err := hex.DecodeString(hashBlob(t, dir, content))
	if err != nil {
		t.Fatal(err)
	}
	body := "100644 " + strings.Repeat("p", maxRecord+1) + "\x00" + string(id)
	runGit(t, dir, "tag", "long", hashObjectLiterally(t, dir, "tree", body))

	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			seen, warn := runWalkWarn(t, dir, walk)
			if !seen[content] {
				t.Error("the blob at the over-long path was not scanned")
			}
			if want := "titus: skipped 1 over-long git records"; !strings.Contains(warn, want) {
				t.Errorf("warnings = %q, want %q", warn, want)
			}
		})
	}
}

// R2b: both walks apply one over-long predicate, the path's own length, so
// a path up to maxRecord keeps its location on both and a longer one is
// dropped and counted on both. The object id's length plays no part.
func TestGitHistory_OverlongPathBoundAgrees(t *testing.T) {
	skipIfNoGit(t)
	for _, n := range []int{maxRecord - 41, maxRecord - 1, maxRecord, maxRecord + 1} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			dir := t.TempDir()
			initGitRepo(t, dir)
			writeFile(t, filepath.Join(dir, "base.txt"), "base\n")
			commitAt(t, dir, "base", "2026-01-01T00:00:00Z")

			const content = "LONG=path-near-max-record\n"
			id, err := hex.DecodeString(hashBlob(t, dir, content))
			if err != nil {
				t.Fatal(err)
			}
			path := strings.Repeat("p", n)
			runGit(t, dir, "tag", "long", hashObjectLiterally(t, dir, "tree", "100644 "+path+"\x00"+string(id)))

			wantKept, wantOverlong := n <= maxRecord, 0
			if !wantKept {
				wantOverlong = 1
			}
			for name, walk := range enumWalks {
				kept, overlong := walkPathKept(t, dir, walk, content, path)
				if kept != wantKept {
					t.Errorf("%s: path of %d bytes kept = %v, want %v", name, n, kept, wantKept)
				}
				if overlong != wantOverlong {
					t.Errorf("%s: over-long count = %d, want %d", name, overlong, wantOverlong)
				}
			}
		})
	}
}

// walkPathKept runs one walk over dir and reports whether the blob with
// content was scanned with path among its locations, and the over-long
// count from the warnings.
func walkPathKept(t *testing.T, dir string, walk func(*GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error, content, path string) (bool, int) {
	t.Helper()
	e := nativeEnum(dir)
	var warn bytes.Buffer
	e.warn = &warn
	scanned, kept := false, false
	err := walk(e)(context.Background(), func(c []byte, _ types.BlobID, prov types.Provenance) error {
		if string(c) != content {
			return nil
		}
		scanned = true
		gp, ok := prov.(types.GitProvenance)
		if !ok {
			return nil
		}
		kept = kept || gp.BlobPath == path
		for _, loc := range gp.Locations {
			kept = kept || loc.Path == path
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v (warnings %q)", err, warn.String())
	}
	if !scanned {
		t.Fatal("the blob was not scanned")
	}
	overlong := 0
	if m := overlongWarning.FindStringSubmatch(warn.String()); m != nil {
		overlong, _ = strconv.Atoi(m[1])
	}
	return kept, overlong
}

var overlongWarning = regexp.MustCompile(`skipped (\d+) over-long git records`)
