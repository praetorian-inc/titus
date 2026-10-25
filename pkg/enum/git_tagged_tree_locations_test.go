package enum

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/praetorian-inc/titus/pkg/types"
)

// taggedTreeWarning is part of the stderr line both walks print when a ref
// points directly at a tree.
const taggedTreeWarning = "git refs point directly at a tree"

// walkProv runs one walk over dir and returns the provenance of the blob with
// content, and the warnings. It fails when the blob was not scanned.
func walkProv(t *testing.T, dir string, walk func(*GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error, content string) (types.GitProvenance, string) {
	t.Helper()
	e := nativeEnum(dir)
	var warn bytes.Buffer
	e.warn = &warn
	var (
		prov  types.GitProvenance
		found bool
	)
	err := walk(e)(context.Background(), func(c []byte, _ types.BlobID, p types.Provenance) error {
		if string(c) == content {
			prov, found = p.(types.GitProvenance), true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v (warnings %q)", err, warn.String())
	}
	if !found {
		t.Fatalf("the blob was not scanned (warnings %q)", warn.String())
	}
	return prov, warn.String()
}

func locPaths(locs []types.GitLocation) []string {
	out := make([]string, len(locs))
	for i, l := range locs {
		out[i] = l.Path
	}
	return out
}

// F1 (a): a blob in a commit at a.txt and in a tagged tree at b-tagged.txt is
// reported at both paths on both walks. a.txt keeps its commit; b-tagged.txt
// has none. The blob is marked as possibly missing locations, and a warning
// says why.
func TestGitHistory_TaggedTreePathOfCommittedBlob(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	const secret = "TAGGED_AND_COMMITTED=ghp_example\n"
	writeFile(t, filepath.Join(dir, "a.txt"), secret)
	commit := commitAt(t, dir, "add a", "2026-01-01T00:00:00Z")
	tree := gitInput(t, dir, []byte("100644 blob "+hashBlob(t, dir, secret)+"\tb-tagged.txt\n"), "mktree")
	runGit(t, dir, "tag", "zz", tree)

	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			prov, warn := walkProv(t, dir, walk, secret)
			if got := locPaths(prov.Locations); strings.Join(got, ",") != "a.txt,b-tagged.txt" {
				t.Fatalf("locations = %q, want [a.txt b-tagged.txt]", got)
			}
			if c := prov.Locations[0].Commit; c == nil || c.CommitID != commit {
				t.Errorf("a.txt commit = %v, want %s", c, commit)
			}
			if c := prov.Locations[1].Commit; c != nil {
				t.Errorf("b-tagged.txt commit = %s, want none", c.CommitID)
			}
			if prov.BlobPath != "a.txt" {
				t.Errorf("primary path = %q, want a.txt", prov.BlobPath)
			}
			if !prov.LocationsTruncated {
				t.Error("blob under a tagged tree is not marked as possibly missing locations")
			}
			if want := "titus: 1 " + taggedTreeWarning; !strings.Contains(warn, want) {
				t.Errorf("warnings = %q, want %q", warn, want)
			}
		})
	}
}

// F1 (b): two tags point at trees that hold the same blob at first.txt and
// second.txt. Only the first path git reaches is listed, so the blob is
// marked as possibly missing locations and a warning says why.
func TestGitHistory_SameBlobUnderTwoTaggedTrees(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	const secret = "TWO_TAGGED_TREES=ghp_example\n"
	blob := hashBlob(t, dir, secret)
	runGit(t, dir, "tag", "t1", gitInput(t, dir, []byte("100644 blob "+blob+"\tfirst.txt\n"), "mktree"))
	runGit(t, dir, "tag", "t2", gitInput(t, dir, []byte("100644 blob "+blob+"\tsecond.txt\n"), "mktree"))

	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			prov, warn := walkProv(t, dir, walk, secret)
			if got := locPaths(prov.Locations); strings.Join(got, ",") != "first.txt" {
				t.Fatalf("locations = %q, want [first.txt]", got)
			}
			if prov.Locations[0].Commit != nil {
				t.Error("a tagged-tree location has a commit")
			}
			if !prov.LocationsTruncated {
				t.Error("blob under two tagged trees is not marked as possibly missing locations")
			}
			if want := "titus: 2 " + taggedTreeWarning; !strings.Contains(warn, want) {
				t.Errorf("warnings = %q, want %q", warn, want)
			}
		})
	}
}

// F1: a blob a ref points at directly, and a committed blob, are not marked:
// neither has a path that could be missing. No tagged-tree warning is
// printed.
func TestGitHistory_TaggedBlobNotMarked(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	const (
		committed = "COMMITTED=only\n"
		tagged    = "TAGGED_BLOB=only\n"
	)
	writeFile(t, filepath.Join(dir, "c.txt"), committed)
	commitAt(t, dir, "add c", "2026-01-01T00:00:00Z")
	runGit(t, dir, "tag", "blob", hashBlob(t, dir, tagged))

	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			for _, content := range []string{committed, tagged} {
				prov, warn := walkProv(t, dir, walk, content)
				if prov.LocationsTruncated {
					t.Errorf("%q is marked as possibly missing locations", content)
				}
				if strings.Contains(warn, taggedTreeWarning) {
					t.Errorf("warnings = %q, want no tagged-tree warning", warn)
				}
			}
		})
	}
}

// F2: rev-list visits refs in name order whatever their storage, and walks
// tagged trees before commit trees. go-git lists loose refs before packed
// ones, so a packed ref that sorts first must still give its tagged-tree
// path, and the committed blob's tagged path must be the one rev-list
// reaches first.
func TestGoGitHistory_PackedAndLooseRefOrder(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	const secret = "PACKED_AND_LOOSE=ghp_example\n"
	writeFile(t, filepath.Join(dir, "committed.txt"), secret)
	commitAt(t, dir, "add", "2026-01-01T00:00:00Z")
	blob := hashBlob(t, dir, secret)
	runGit(t, dir, "tag", "a-packed", gitInput(t, dir, []byte("100644 blob "+blob+"\tfrom-a.txt\n"), "mktree"))
	runGit(t, dir, "pack-refs", "--all")
	runGit(t, dir, "tag", "b-loose", gitInput(t, dir, []byte("100644 blob "+blob+"\tfrom-b.txt\n"), "mktree"))

	// Fixture shape: a-packed is only in packed-refs, b-loose is only loose.
	if _, err := os.Stat(filepath.Join(dir, ".git", "refs", "tags", "a-packed")); !os.IsNotExist(err) {
		t.Fatalf("fixture: a-packed is a loose ref (stat err %v)", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git", "refs", "tags", "b-loose")); err != nil {
		t.Fatalf("fixture: b-loose is not a loose ref: %v", err)
	}

	native, _ := walkProv(t, dir, enumWalks["native"], secret)
	if got := locPaths(native.Locations); strings.Join(got, ",") != "committed.txt,from-a.txt" {
		t.Fatalf("native locations = %q, want [committed.txt from-a.txt]", got)
	}
	assertGoGitMatchesNative(t, dir, map[string]string{"secret": secret})
}

// deepTaggedTree writes, through go-git, a tree nested depth levels deep with
// one blob at the bottom, and points refs/tags/deep at it. It returns the
// blob's path.
func deepTaggedTree(t *testing.T, dir, content string, depth int) string {
	t.Helper()
	repo, err := git.PlainOpen(dir)
	if err != nil {
		t.Fatal(err)
	}
	blob := repo.Storer.NewEncodedObject()
	blob.SetType(plumbing.BlobObject)
	w, err := blob.Writer()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	h, err := repo.Storer.SetEncodedObject(blob)
	if err != nil {
		t.Fatal(err)
	}
	entry := object.TreeEntry{Name: "f", Mode: filemode.Regular, Hash: h}
	for i := 0; i <= depth; i++ {
		obj := repo.Storer.NewEncodedObject()
		if err := (&object.Tree{Entries: []object.TreeEntry{entry}}).Encode(obj); err != nil {
			t.Fatal(err)
		}
		if h, err = repo.Storer.SetEncodedObject(obj); err != nil {
			t.Fatal(err)
		}
		entry = object.TreeEntry{Name: "d", Mode: filemode.Dir, Hash: h}
	}
	if err := repo.Storer.SetReference(plumbing.NewHashReference("refs/tags/deep", h)); err != nil {
		t.Fatal(err)
	}
	return strings.Repeat("d/", depth) + "f"
}

// F3: a tagged tree about 1100 levels deep is scanned on both walks, with
// its full path, and the walk exits cleanly. go-git used to fail the whole
// scan past 1024 levels.
func TestGitHistory_DeepTaggedTree(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "base.txt"), "base\n")
	commitAt(t, dir, "base", "2026-01-01T00:00:00Z")
	const secret = "DEEP_TAGGED=ghp_example\n"
	path := deepTaggedTree(t, dir, secret, 1100)

	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			prov, _ := walkProv(t, dir, walk, secret)
			if got := locPaths(prov.Locations); len(got) != 1 || got[0] != path {
				t.Errorf("locations = %d paths, want the one path of %d bytes", len(got), len(path))
			}
		})
	}
	assertGoGitMatchesNative(t, dir, map[string]string{"deep secret": secret})
}
