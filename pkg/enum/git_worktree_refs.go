package enum

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/filesystem"
)

// perWorktreeRefDirs are the ref namespaces each worktree keeps in its own
// gitdir, never in the common store, and never packed (R6-1).
var perWorktreeRefDirs = []string{"refs/worktree", "refs/bisect", "refs/rewritten"}

// maxSymrefDepth bounds a symbolic ref chain, as git's SYMREF_MAXDEPTH does.
const maxSymrefDepth = 5

// refReader reads a ref file by name from one worktree's gitdir. exists is
// false for a missing file; bad reports one git would use that is not read
// here (an error, or a symlink or other non-regular file).
type refReader func(name string) (b []byte, exists, bad bool)

// osRefReader reads ref files under the gitdir dir.
func osRefReader(dir string) refReader {
	open := func(n string) (io.ReadCloser, error) { return os.Open(n) }
	return func(name string) ([]byte, bool, bool) {
		return readRefFile(os.Lstat, open, filepath.Join(dir, filepath.FromSlash(name)))
	}
}

// readRefFile reads at most maxWorktreeHead bytes of the regular file name.
// A symlink is not followed: git would read through it, but the target is
// outside the repository's control, so it counts as bad.
func readRefFile(lstat func(string) (os.FileInfo, error), open func(string) (io.ReadCloser, error), name string) (b []byte, exists, bad bool) {
	fi, err := lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, false
	}
	if err != nil || !fi.Mode().IsRegular() {
		return nil, true, true
	}
	f, err := open(name)
	if err != nil {
		return nil, true, true
	}
	b, err = io.ReadAll(io.LimitReader(f, maxWorktreeHead))
	_ = f.Close()
	if err != nil {
		return nil, true, true
	}
	return b, true, false
}

// isPerWorktreeRef reports whether name lives in a worktree's own gitdir.
func isPerWorktreeRef(name string) bool {
	for _, d := range perWorktreeRefDirs {
		if strings.HasPrefix(name, d+"/") {
			return true
		}
	}
	return false
}

// parseSymref parses "ref: <name>" as git does, trimming whitespace. The
// name must be a clean path under refs/, so a crafted file cannot send the
// read outside the gitdir.
func parseSymref(b []byte) (string, bool) {
	s, ok := strings.CutPrefix(string(b), "ref:")
	if !ok {
		return "", false
	}
	name := strings.TrimSpace(s)
	if !strings.HasPrefix(name, "refs/") || path.Clean(name) != name ||
		strings.ContainsFunc(name, func(r rune) bool { return r <= ' ' || r == 0x7f || r == '\\' }) {
		return "", false
	}
	return name, true
}

// resolveSymref follows the symbolic ref target as git does from the
// worktree read reads: per-worktree names from that worktree's gitdir, the
// rest from the common store (R6-1). found reports a commit-ish to add as a
// tip. A target in the common store that exists is a listed ref, and a
// missing target is an unborn branch, as git treats it; both are neither.
// bad reports a ref git would follow that is not read here: unreadable, not
// an object id or symref, an id of the other hash width, or a chain deeper
// than git follows.
func resolveSymref(repo *git.Repository, read refReader, target string) (h plumbing.Hash, found, bad bool) {
	for range maxSymrefDepth {
		if !isPerWorktreeRef(target) {
			ref, err := repo.Storer.Reference(plumbing.ReferenceName(target))
			switch {
			case errors.Is(err, plumbing.ErrReferenceNotFound):
				return h, false, false
			case err != nil:
				return h, false, true
			case ref.Type() == plumbing.SymbolicReference:
				target = string(ref.Target())
				continue
			}
			return h, false, false
		}
		b, exists, bad := read(target)
		switch {
		case !exists:
			return h, false, false
		case bad:
			return h, false, true
		}
		if h, ok := parseDetachedHead(b); ok {
			return h, true, false
		}
		next, ok := parseSymref(b)
		if !ok {
			return h, false, true // malformed or other-width id
		}
		target = next
	}
	return h, false, true
}

// gitDirs returns the gitdir go-git opened and the common directory. They
// differ in a linked worktree. ok is false when the storage is not on disk
// or the common directory cannot be found.
func gitDirs(repo *git.Repository) (self, common string, ok bool) {
	s, isFS := repo.Storer.(*filesystem.Storage)
	if !isFS {
		return "", "", false
	}
	fsys := s.Filesystem()
	// Paths under objects/ resolve in the common directory (R4-2).
	ofs, err := fsys.Chroot("objects")
	if err != nil {
		return fsys.Root(), "", false
	}
	return fsys.Root(), filepath.Dir(ofs.Root()), true
}

// perWorktreeRefs lists the loose refs under the per-worktree namespaces of
// the gitdir self, which go-git does not read in a linked worktree: it maps
// refs/worktree/<name> to the common store (R6-1). Each is returned as a
// hash ref, symrefs resolved. lost counts refs that git would follow and
// that are not read here.
func perWorktreeRefs(repo *git.Repository, self string) (refs []*plumbing.Reference, lost int) {
	read := osRefReader(self)
	for _, dir := range perWorktreeRefDirs {
		root := filepath.Join(self, filepath.FromSlash(dir))
		fi, err := os.Lstat(root)
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil || fi.Mode()&os.ModeSymlink != 0:
			lost++
			continue
		case !fi.IsDir():
			continue // git finds no refs here either
		}
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				lost++
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(self, p)
			name := filepath.ToSlash(rel)
			if strings.HasSuffix(name, ".lock") {
				return nil // an update in progress, never a ref name
			}
			b, exists, bad := read(name)
			switch {
			case !exists:
				return nil
			case bad:
				lost++
				return nil
			}
			h, ok := parseDetachedHead(b)
			if !ok {
				target, isSym := parseSymref(b)
				if !isSym {
					lost++ // malformed, or an id of the other width
					return nil
				}
				var found, bad bool
				h, found, bad = resolveSymref(repo, read, target)
				if bad {
					lost++
				}
				if !found {
					return nil
				}
			}
			refs = append(refs, plumbing.NewHashReference(plumbing.ReferenceName(name), h))
			return nil
		})
	}
	return refs, lost
}
