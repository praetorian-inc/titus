package enum

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// taggedWalk collects the blobs of tagged trees and blobs as rev-list
// --objects lists them: each object once, a blob with the first path it is
// reached at in a pre-order walk, in tree-entry order. Every tree is read
// once across all tagged roots, so a tree that names one subtree many
// times costs one read per distinct tree, not one per path (N1).
type taggedWalk struct {
	repo    *git.Repository
	blobs   []blobEntry
	seen    map[[20]byte]struct{}      // blobs, shared with the commit walk
	inTree  map[[20]byte]struct{}      // every blob under a tagged tree
	trees   map[plumbing.Hash]struct{} // trees already walked, across roots
	stats   *indexStats                // receives over-long paths (R2)
	missing map[plumbing.Hash]struct{} // objects missing from the repository
}

func newTaggedWalk(repo *git.Repository, blobs []blobEntry, seen map[[20]byte]struct{}, stats *indexStats) *taggedWalk {
	return &taggedWalk{
		repo:    repo,
		blobs:   blobs,
		seen:    seen,
		inTree:  make(map[[20]byte]struct{}),
		trees:   make(map[plumbing.Hash]struct{}),
		stats:   stats,
		missing: make(map[plumbing.Hash]struct{}),
	}
}

// add walks the tagged object o, a tree or a blob.
func (w *taggedWalk) add(ctx context.Context, o taggedObject) error {
	if o.typ == plumbing.BlobObject {
		w.addBlob(o.hash, "")
		return nil
	}
	return w.walkTree(ctx, o.hash)
}

// treeFrame is one tree on the walk's stack: its entries, the next entry to
// visit, and the length of the tree's path in the shared path buffer.
type treeFrame struct {
	entries []object.TreeEntry
	next    int
	prefix  int
}

// walkTree adds the blobs under the tree root. It keeps its own stack, so
// any nesting depth is walked, as git walks it, without growing the
// goroutine stack (F3). A tree missing from the repository is counted, as
// rev-list's missing=print mode reports it, and its siblings are still
// walked (N2).
func (w *taggedWalk) walkTree(ctx context.Context, root plumbing.Hash) error {
	var (
		stack []treeFrame
		path  []byte
	)
	push := func(h plumbing.Hash) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, ok := w.trees[h]; ok {
			return nil
		}
		w.trees[h] = struct{}{}
		tree, err := w.repo.TreeObject(h)
		if errors.Is(err, plumbing.ErrObjectNotFound) {
			w.missing[h] = struct{}{}
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to get tagged tree %s: %w", h, err)
		}
		stack = append(stack, treeFrame{entries: tree.Entries, prefix: len(path)})
		return nil
	}
	if err := push(root); err != nil {
		return err
	}
	for len(stack) > 0 {
		top := len(stack) - 1
		if stack[top].next == len(stack[top].entries) {
			stack = stack[:top]
			continue
		}
		entry := stack[top].entries[stack[top].next]
		stack[top].next++
		path = path[:stack[top].prefix]
		if len(path) > 0 {
			path = append(path, '/')
		}
		path = append(path, entry.Name...)
		switch entry.Mode {
		case filemode.Submodule:
			continue // a gitlink, not an object in this repository
		case filemode.Dir:
			if err := push(entry.Hash); err != nil {
				return err
			}
		default:
			w.inTree[[20]byte(entry.Hash)] = struct{}{}
			w.addBlob(entry.Hash, string(path))
		}
	}
	return nil
}

// addBlob adds h with path unless it was already seen. A path over
// maxRecord is dropped and counted, as rev-list's is (SEC-9, R2).
func (w *taggedWalk) addBlob(h plumbing.Hash, path string) {
	hash := [20]byte(h)
	if _, ok := w.seen[hash]; ok {
		return
	}
	w.seen[hash] = struct{}{}
	if len(path) > maxRecord {
		w.stats.overlong++
		path = ""
	}
	w.blobs = append(w.blobs, blobEntry{hash: hash, path: path})
}

// taggedObject is a tree or blob that a ref points at, directly or through
// annotated tags.
type taggedObject struct {
	hash plumbing.Hash
	typ  plumbing.ObjectType
}
