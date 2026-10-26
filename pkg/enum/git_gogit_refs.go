package enum

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
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

// osOpenRef is an openRefFunc on the host filesystem.
func osOpenRef(name string, flag int) (io.ReadCloser, error) { return os.OpenFile(name, flag, 0) }

// osRefReader reads ref files under the gitdir dir.
func osRefReader(dir string) refReader {
	return func(name string) ([]byte, bool, bool) {
		return readRefFile(os.Lstat, osOpenRef, filepath.Join(dir, filepath.FromSlash(name)))
	}
}

// readRefFile reads at most maxWorktreeHead bytes of the regular file name,
// opened with openRegularRefFile.
func readRefFile(lstat func(string) (os.FileInfo, error), open openRefFunc, name string) (b []byte, exists, bad bool) {
	f, exists, bad := openRegularRefFile(lstat, open, name)
	if !exists || bad {
		return nil, exists, bad
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxWorktreeHead))
	if err != nil {
		return nil, true, true
	}
	return b, true, false
}

// openRegularRefFile opens the regular file name for reading. A symlink is
// not followed: git would read through it, but the target is outside the
// repository's control, so it counts as bad. Where the platform has
// O_NOFOLLOW the file is opened with it and O_NONBLOCK, and the open file is
// checked with fstat, so a file swapped for a symlink or a FIFO after any
// earlier check is neither followed nor waited on (R7 I-1). Without
// O_NOFOLLOW, or for a billy file that cannot be fstat'd (an in-memory
// filesystem, where no other process can swap it), the Lstat check stands
// in. f is open only when exists is true and bad is false.
func openRegularRefFile(lstat func(string) (os.FileInfo, error), open openRefFunc, name string) (f io.ReadCloser, exists, bad bool) {
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
	if st, ok := f.(interface{ Stat() (os.FileInfo, error) }); ok {
		if !regular(st.Stat()) {
			_ = f.Close()
			return nil, true, true
		}
	} else if !checked && !regular(lstat(name)) {
		_ = f.Close()
		return nil, true, true
	}
	return f, true, false
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
// worktree's gitdir, and takes "ref: My_Ref" as unborn; parseSymref rejects
// that name, so it is counted as unread here, which over-reports (R8-2).
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
// gitdir, the rest from the common store (R6-1, R7 F2). A name read from
// the worktree with no loose file there is looked up in the common
// packed-refs, as git falls back to it (R8-1). found reports a commit-ish to
// add as a tip. A target in the common store that exists is a listed ref, and a
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
			_, common, ok := gitDirs(repo)
			if !ok {
				return h, false, true
			}
			return lookupPackedRef(common, target)
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
// in the common directory whose names are not in loose, the loose refs of
// the opened worktree: git reads such a line from it when it has no loose
// ref of that name (R7 F1). Another worktree's per-worktree refs are not
// rev-list --all tips; its HEAD is, and resolveSymref finds a packed target
// for it (R8-1). A packed-refs file that cannot be read, or a per-worktree
// line that names no object id of this repository's width, counts in lost.
func packedPerWorktreeRefs(common string, loose map[string]bool) (refs []*plumbing.Reference, lost int) {
	bad := scanPackedRefs(common, func(ref, line string) bool {
		if !isPerWorktreeRef(ref) || loose[ref] {
			return true
		}
		h, ok := parseDetachedHead([]byte(line))
		if !ok {
			lost++ // an id of the other width, or not an id
			return true
		}
		refs = append(refs, plumbing.NewHashReference(plumbing.ReferenceName(ref), h))
		return true
	})
	if bad {
		lost++
	}
	return refs, lost
}

// lookupPackedRef looks name up in the packed-refs file in the common
// directory. found reports a line naming an object id; bad reports a file
// that cannot be read, or a line for name that names no object id of this
// repository's width. A missing file or name is neither: an unborn ref.
func lookupPackedRef(common, name string) (h plumbing.Hash, found, bad bool) {
	matched := false
	unread := scanPackedRefs(common, func(ref, line string) bool {
		if ref != name {
			return true
		}
		matched = true
		h, found = parseDetachedHead([]byte(line))
		return false
	})
	return h, found, unread || (matched && !found)
}

// scanPackedRefs calls fn with the name and line of each ref line of the
// packed-refs file in common until fn returns false. bad reports a file that
// is not a regular file or cannot be read; a missing file is not.
func scanPackedRefs(common string, fn func(ref, line string) bool) (bad bool) {
	f, exists, bad := openRegularRefFile(os.Lstat, osOpenRef, filepath.Join(common, "packed-refs"))
	if !exists || bad {
		return bad
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := sc.Text()
		_, ref, ok := strings.Cut(line, " ")
		if !ok || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
			continue
		}
		if !fn(ref, line) {
			return false
		}
	}
	return sc.Err() != nil
}

// goGitTips returns the commits that HEAD, every ref and every other
// worktree's HEAD point at, the tips of rev-list --all, and the trees and
// blobs refs point at. Refs are taken in name order, then HEAD, then the
// other worktrees' HEADs, as rev-list --all takes them; go-git lists loose
// refs before packed ones, and the order decides the path a blob under two
// tagged trees is listed at. Annotated tags are peeled; an unborn HEAD and
// refs to a missing object are skipped, as git skips broken refs. The
// missing objects refs name are added to missing, which rev-list reports as
// missing; a ref file that is not an object id names none. lost counts the
// other worktrees whose HEAD could not be read.
func goGitTips(repo *git.Repository, missing map[plumbing.Hash]struct{}) (tips []plumbing.Hash, others []taggedObject, lost int, err error) {
	addHash := func(name string, h plumbing.Hash, countTree bool) error {
		h, typ, err := peelRef(repo, h)
		if err != nil {
			return fmt.Errorf("failed to peel ref %s: %w", name, err)
		}
		switch typ {
		case plumbing.CommitObject:
			tips = append(tips, h)
		case plumbing.TreeObject:
			if countTree {
				others = append(others, taggedObject{hash: h, typ: typ})
			}
		case plumbing.BlobObject:
			others = append(others, taggedObject{hash: h, typ: typ})
		case plumbing.InvalidObject:
			// A ref, or a tag on its chain, names an object the repository
			// lacks: rev-list reports it as missing, once. The zero hash is
			// a ref file that is not an object id, which names nothing.
			if !h.IsZero() {
				missing[h] = struct{}{}
			}
		}
		return nil
	}
	add := func(ref *plumbing.Reference, countTree bool) error {
		name := ref.Name()
		if ref.Type() == plumbing.HashReference {
			return addHash(name.String(), ref.Hash(), countTree)
		}
		resolved, err := storer.ResolveReference(repo.Storer, name)
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return nil // dangling symbolic ref, such as an unborn HEAD
		}
		if err != nil {
			return fmt.Errorf("failed to resolve ref %s: %w", name, err)
		}
		return addHash(name.String(), resolved.Hash(), countTree)
	}
	refs, err := repo.Storer.IterReferences()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to list refs: %w", err)
	}
	// In a linked worktree go-git reads refs/worktree/<name> and the other
	// per-worktree refs from the common store, which holds the main
	// worktree's. They are dropped and read from the opened gitdir instead
	// (R6-1). In the main worktree the two are one directory, and go-git
	// lists them itself.
	self, common, onDisk := gitDirs(repo)
	linked := onDisk && !sameDir(self, common)
	var named []*plumbing.Reference
	if err := refs.ForEach(func(ref *plumbing.Reference) error {
		if ref.Name() != plumbing.HEAD && (!linked || !isPerWorktreeRef(ref.Name().String())) {
			named = append(named, ref)
		}
		return nil
	}); err != nil {
		return nil, nil, 0, err
	}
	if linked {
		own, ownLost := perWorktreeRefs(repo, self)
		named = append(named, own...)
		lost += ownLost
	}
	slices.SortFunc(named, func(a, b *plumbing.Reference) int {
		return strings.Compare(string(a.Name()), string(b.Name()))
	})
	for _, ref := range named {
		if err := add(ref, true); err != nil {
			return nil, nil, 0, err
		}
	}
	// HEAD as a symbolic ref to a listed ref is that ref again: its tree,
	// if any, is not counted a second time.
	headTree := true
	head, err := repo.Storer.Reference(plumbing.HEAD)
	symbolic := err == nil && head.Type() == plumbing.SymbolicReference
	if symbolic {
		headTree = !slices.ContainsFunc(named, func(r *plumbing.Reference) bool { return r.Name() == head.Target() })
	}
	// A HEAD on a per-worktree ref is resolved from the opened gitdir: go-git
	// looks for the target in the common store, finds nothing, and would
	// take the HEAD as unborn (R6-1).
	var h plumbing.Hash
	found, bad := false, false
	if symbolic && onDisk {
		h, found, bad = resolveSymref(repo, osRefReader(self), string(head.Target()))
	}
	switch {
	case found:
		err = addHash("HEAD", h, headTree)
	case bad:
		lost++
	default:
		err = add(plumbing.NewSymbolicReference(plumbing.HEAD, ""), headTree)
	}
	if err != nil {
		return nil, nil, 0, err
	}
	// go-git has no API for other worktrees' HEADs (R4-1). A detached one
	// is a tip like a ref; one on a branch repeats a listed ref.
	heads, headsLost := goGitWorktreeHeads(repo)
	lost += headsLost
	for _, wt := range heads {
		if err := addHash("worktree HEAD", wt, true); err != nil {
			return nil, nil, 0, err
		}
	}
	return tips, others, lost, nil
}

// maxWorktreeHead bounds the read of a worktree's HEAD file. An object id
// or a symbolic ref fits easily; a longer file is neither.
const maxWorktreeHead = 4 << 10

// goGitWorktreeHeads returns the HEAD commit-ish of every worktree except
// the one opened, read as git reads it: an object id, or a symbolic ref.
// Linked worktrees keep theirs in <commondir>/worktrees/<id>/HEAD, and the
// main worktree in <commondir>/HEAD, which go-git does not read when the
// scan is opened in a linked worktree (R5-1). A symbolic HEAD on a
// per-worktree ref is resolved from that worktree's gitdir (R6-1); one on a
// common ref repeats a listed ref, and a file that names no object id names
// nothing, as for refs; both are skipped. A worktree entry or HEAD that is a
// symlink, or cannot be read, is counted in lost, since git would still
// reach it; so is an object id of the other hash width, which go-git cannot
// look up (O4).
func goGitWorktreeHeads(repo *git.Repository) (heads []plumbing.Hash, lost int) {
	s, ok := repo.Storer.(*filesystem.Storage)
	if !ok {
		return nil, 0 // not on disk: no worktrees
	}
	fs := s.Filesystem()
	self, common, ok := gitDirs(repo)
	read := func(r refReader) {
		h, found, bad := readHeadFile(repo, r)
		switch {
		case found:
			heads = append(heads, h)
		case bad:
			lost++
		}
	}
	if !ok {
		lost++
	} else if !sameDir(common, self) {
		read(osRefReader(common))
	}
	fi, err := fs.Lstat("worktrees")
	switch {
	case errors.Is(err, os.ErrNotExist):
		return heads, lost
	case err != nil || fi.Mode()&os.ModeSymlink != 0:
		return heads, lost + 1
	case !fi.IsDir():
		return heads, lost // git finds no worktrees here either
	}
	wfs, err := fs.Chroot("worktrees")
	if err != nil {
		return heads, lost + 1
	}
	entries, err := wfs.ReadDir(".")
	if err != nil {
		return heads, lost + 1
	}
	// billy passes the flags through to os.OpenFile on disk (R7 I-1).
	wopen := func(n string, flag int) (io.ReadCloser, error) { return wfs.OpenFile(n, flag, 0) }
	for _, e := range entries {
		if e.Mode()&os.ModeSymlink != 0 {
			lost++
			continue
		}
		if !e.IsDir() || sameDir(filepath.Join(wfs.Root(), e.Name()), self) {
			continue // not a worktree, or the one opened: its HEAD is HEAD
		}
		id := e.Name()
		read(func(name string) ([]byte, bool, bool) {
			return readRefFile(wfs.Lstat, wopen, path.Join(id, name))
		})
	}
	return heads, lost
}

// readHeadFile reads the HEAD file of the worktree read reads, at most
// maxWorktreeHead bytes of a regular file. found reports a HEAD naming an
// object, directly or through a per-worktree ref. bad reports a HEAD git
// would use that is not read here: an error, a symlink or other non-regular
// file, an object id of the other hash width, a "ref:" line parseSymref
// rejects, or a symbolic ref that resolveSymref cannot follow. A missing file is neither: git skips that
// worktree too.
func readHeadFile(repo *git.Repository, read refReader) (h plumbing.Hash, found, bad bool) {
	b, exists, bad := read("HEAD")
	if !exists || bad {
		return h, false, bad
	}
	if h, ok := parseDetachedHead(b); ok {
		return h, true, false
	}
	if target, ok := parseSymref(b); ok {
		return resolveSymref(repo, read, target)
	}
	if bytes.HasPrefix(b, []byte("ref:")) {
		return h, false, true // a symref git may follow that is not read here (R7 F2)
	}
	return h, false, otherWidthID(b)
}

// otherWidthID reports whether b starts with a non-null object id of the
// hash width the repository does not use (40 or 64 hex digits), followed by
// the end or whitespace. git in such a repository names an object go-git
// cannot read, so the HEAD is counted as lost rather than dropped (O4).
func otherWidthID(b []byte) bool {
	own := hex.EncodedLen(len(plumbing.Hash{}))
	for _, n := range []int{40, 64} {
		if n == own || len(b) < n || (len(b) > n && !strings.ContainsRune(" \t\n\r", rune(b[n]))) {
			continue
		}
		id := string(b[:n])
		if _, err := hex.DecodeString(id); err == nil && strings.Trim(id, "0") != "" {
			return true
		}
	}
	return false
}

// sameDir reports whether a and b name the same directory: equal once
// cleaned, or once symlinks are resolved (O1), so a common directory spelled
// through a symlinked path is still recognized as the one opened.
func sameDir(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if a == b {
		return true
	}
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}

// parseDetachedHead parses a HEAD file as git parses a loose ref: an object
// id of the repository's hash width, then the end or whitespace. The null id
// and anything else, such as "ref: ...", name no object.
func parseDetachedHead(b []byte) (plumbing.Hash, bool) {
	var h plumbing.Hash
	n := hex.EncodedLen(len(h))
	if len(b) < n || (len(b) > n && !strings.ContainsRune(" \t\n\r", rune(b[n]))) {
		return h, false
	}
	if _, err := hex.Decode(h[:], b[:n]); err != nil || h.IsZero() {
		return h, false
	}
	return h, true
}

// peelRef follows annotated tags from h and returns the object the chain
// ends at and its type. The type is plumbing.InvalidObject when an object on
// the chain is missing.
func peelRef(repo *git.Repository, h plumbing.Hash) (plumbing.Hash, plumbing.ObjectType, error) {
	for {
		obj, err := repo.Storer.EncodedObject(plumbing.AnyObject, h)
		if errors.Is(err, plumbing.ErrObjectNotFound) {
			return h, plumbing.InvalidObject, nil
		}
		if err != nil {
			return h, plumbing.InvalidObject, err
		}
		if obj.Type() != plumbing.TagObject {
			return h, obj.Type(), nil
		}
		tag, err := object.DecodeTag(repo.Storer, obj)
		if err != nil {
			return h, plumbing.InvalidObject, err
		}
		h = tag.Target
	}
}
