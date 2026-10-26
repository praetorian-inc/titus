package enum

import (
	"bufio"
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

// perWorktreeRefDirs are the ref namespaces git reads, for a linked
// worktree, from that worktree's own gitdir as loose refs. git pack-refs
// leaves them loose, but git still falls back to the common packed-refs for
// these names when no loose ref exists, so a line there is read too (R7 F1).
var perWorktreeRefDirs = []string{"refs/worktree", "refs/bisect", "refs/rewritten"}

// maxSymrefDepth bounds a symbolic ref chain, as git's SYMREF_MAXDEPTH does.
const maxSymrefDepth = 5

// refReader reads a ref file by name from one worktree's gitdir. exists is
// false for a missing file; bad reports one git would use that is not read
// here (an error, or a symlink or other non-regular file).
type refReader func(name string) (b []byte, exists, bad bool)

// openRefFunc opens a file read-only with extra open flags.
type openRefFunc func(name string, flag int) (io.ReadCloser, error)

// osRefReader reads ref files under the gitdir dir.
func osRefReader(dir string) refReader {
	open := func(n string, flag int) (io.ReadCloser, error) { return os.OpenFile(n, flag, 0) }
	return func(name string) ([]byte, bool, bool) {
		return readRefFile(os.Lstat, open, filepath.Join(dir, filepath.FromSlash(name)))
	}
}

// readRefFile reads at most maxWorktreeHead bytes of the regular file name.
// A symlink is not followed: git would read through it, but the target is
// outside the repository's control, so it counts as bad. Where the platform
// has O_NOFOLLOW the file is opened with it and O_NONBLOCK, and the open
// file is checked with fstat, so a file swapped for a symlink or a FIFO
// after any earlier check is neither followed nor waited on (R7 I-1).
// Without O_NOFOLLOW, or for a billy file that cannot be fstat'd (an
// in-memory filesystem, where no other process can swap it), the Lstat
// check stands in.
func readRefFile(lstat func(string) (os.FileInfo, error), open openRefFunc, name string) (b []byte, exists, bad bool) {
	regular := func(fi os.FileInfo, err error) bool { return err == nil && fi.Mode().IsRegular() }
	checked := false
	if !openNoFollow {
		fi, err := lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, false
		}
		if !regular(fi, err) {
			return nil, true, true
		}
		checked = true
	}
	f, err := open(name, os.O_RDONLY|openRefFlags)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, false
	}
	if err != nil {
		return nil, true, true // ELOOP for a symlink under O_NOFOLLOW
	}
	defer func() { _ = f.Close() }()
	if st, ok := f.(interface{ Stat() (os.FileInfo, error) }); ok {
		if !regular(st.Stat()) {
			return nil, true, true
		}
	} else if !checked && !regular(lstat(name)) {
		return nil, true, true
	}
	b, err = io.ReadAll(io.LimitReader(f, maxWorktreeHead))
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

// readFromWorktree reports whether git reads the ref name from a
// worktree's own gitdir rather than the common store: a per-worktree ref,
// or a one-level root ref such as MY_REF (R7 F2).
func readFromWorktree(name string) bool {
	return isPerWorktreeRef(name) || isRootRefName(name)
}

// isRootRefName reports whether name has git's root ref syntax
// (is_root_ref_syntax): one level of upper-case letters, '-' and '_'. git
// 2.50 resolves a worktree HEAD of "ref: MY_REF" or "ref: MY-REF" from that
// worktree's gitdir, and takes "ref: My_Ref" as unborn.
func isRootRefName(name string) bool {
	return name != "" && !strings.ContainsFunc(name, func(r rune) bool {
		return (r < 'A' || r > 'Z') && r != '-' && r != '_'
	})
}

// parseSymref parses "ref: <name>" as git does, trimming whitespace. The
// name must be a clean path under refs/ or a root ref name, so a crafted
// file cannot send the read outside the gitdir. A caller must count content
// that starts with "ref:" and fails here as unread, never skip it.
func parseSymref(b []byte) (string, bool) {
	s, ok := strings.CutPrefix(string(b), "ref:")
	if !ok {
		return "", false
	}
	name := strings.TrimSpace(s)
	if isRootRefName(name) {
		return name, true
	}
	if !strings.HasPrefix(name, "refs/") || path.Clean(name) != name ||
		strings.ContainsFunc(name, func(r rune) bool { return r <= ' ' || r == 0x7f || r == '\\' }) {
		return "", false
	}
	return name, true
}

// resolveSymref follows the symbolic ref target as git does from the
// worktree read reads: per-worktree and root ref names from that worktree's
// gitdir, the rest from the common store (R6-1, R7 F2). A per-worktree name
// with no loose file there is one git may find in the common packed-refs;
// perWorktreeRefs lists those, so it is treated as unborn here. found reports a commit-ish to add as a
// tip. A target in the common store that exists is a listed ref, and a
// missing target is an unborn branch, as git treats it; both are neither.
// bad reports a ref git would follow that is not read here: unreadable, not
// an object id or symref, an id of the other hash width, or a chain deeper
// than git follows.
func resolveSymref(repo *git.Repository, read refReader, target string) (h plumbing.Hash, found, bad bool) {
	for range maxSymrefDepth {
		if !readFromWorktree(target) {
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

// perWorktreeRefs lists the per-worktree refs git reads in the linked
// worktree whose gitdir is self, which go-git does not: it maps
// refs/worktree/<name> to the common store (R6-1). These are the loose refs
// under the per-worktree namespaces of self, then each per-worktree line of
// the common packed-refs that no loose file in self shadows, since git
// falls back to it (R7 F1). Each is returned as a hash ref, symrefs
// resolved. lost counts refs that git would follow and that are not read
// here.
func perWorktreeRefs(repo *git.Repository, self string) (refs []*plumbing.Reference, lost int) {
	read := osRefReader(self)
	loose := map[string]bool{}
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
				loose[name] = true
				lost++
				return nil
			}
			loose[name] = true // git uses it, not a packed line
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
	if _, common, ok := gitDirs(repo); ok {
		packed, packedLost := packedPerWorktreeRefs(common, loose)
		refs = append(refs, packed...)
		lost += packedLost
	}
	return refs, lost
}

// packedPerWorktreeRefs lists the per-worktree lines of the packed-refs file
// in the common directory whose names are not in loose: git reads such a
// line from a linked worktree that has no loose ref of that name (R7 F1).
// A packed-refs file that cannot be read, or a per-worktree line that names
// no object id of this repository's width, counts in lost.
func packedPerWorktreeRefs(common string, loose map[string]bool) (refs []*plumbing.Reference, lost int) {
	name := filepath.Join(common, "packed-refs")
	if !openNoFollow {
		fi, err := os.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0
		}
		if err != nil || !fi.Mode().IsRegular() {
			return nil, 1
		}
	}
	f, err := os.OpenFile(name, os.O_RDONLY|openRefFlags, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0
	}
	if err != nil {
		return nil, 1 // ELOOP for a symlink under O_NOFOLLOW
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, 1
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := sc.Text()
		_, ref, ok := strings.Cut(line, " ")
		if !ok || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") ||
			!isPerWorktreeRef(ref) || loose[ref] {
			continue
		}
		h, ok := parseDetachedHead([]byte(line))
		if !ok {
			lost++ // an id of the other width, or not an id
			continue
		}
		refs = append(refs, plumbing.NewHashReference(plumbing.ReferenceName(ref), h))
	}
	if sc.Err() != nil {
		lost++
	}
	return refs, lost
}
