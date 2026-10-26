package enum

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha1" // #nosec G505 -- git object ids, not integrity
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/titus/pkg/types"
)

// blobCallback is the callback every Enumerator invokes per blob.
type blobCallback = func(content []byte, blobID types.BlobID, prov types.Provenance) error

// CombinedEnumerator runs multiple enumerators sequentially and deduplicates
// blobs by BlobID so each unique blob is yielded at most once.
type CombinedEnumerator struct {
	enumerators []Enumerator
}

// NewCombinedEnumerator creates a CombinedEnumerator that wraps the provided
// enumerators. They are run in order and duplicate blobs (same BlobID) are
// suppressed.
func NewCombinedEnumerator(enumerators ...Enumerator) *CombinedEnumerator {
	return &CombinedEnumerator{enumerators: enumerators}
}

// Enumerate runs each child enumerator in sequence, passing unique blobs to
// callback. A blob is considered a duplicate if its BlobID was already seen
// by a previous call across any enumerator in this combined set. A duplicate
// carrying a GitProvenance still reaches callback: git reports each object
// once, and two objects share a BlobID when they hold the same text in
// different encodings (UTF-8 and UTF-16), so dropping one would drop its
// history locations.
//
// When the set is a git enumerator followed by a filesystem enumerator over
// the same root (the `scan --git` shape), the working tree is folded into the
// git provenance instead: see enumerateGitWithWorktree.
func (c *CombinedEnumerator) Enumerate(ctx context.Context, callback blobCallback) error {
	if g, fs, ok := c.gitWithWorktree(); ok {
		return enumerateGitWithWorktree(ctx, g, fs, callback)
	}

	var mu sync.Mutex
	seen := make(map[types.BlobID]bool)

	for _, e := range c.enumerators {
		err := e.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			mu.Lock()
			dup := seen[blobID]
			seen[blobID] = true
			mu.Unlock()
			if _, isGit := prov.(types.GitProvenance); dup && !isGit {
				return nil
			}

			return callback(content, blobID, prov)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// gitWithWorktree reports whether the set is exactly a git enumerator and a
// filesystem enumerator over the same root.
func (c *CombinedEnumerator) gitWithWorktree() (*GitEnumerator, *FilesystemEnumerator, bool) {
	if len(c.enumerators) != 2 {
		return nil, nil, false
	}
	g, okGit := c.enumerators[0].(*GitEnumerator)
	fs, okFS := c.enumerators[1].(*FilesystemEnumerator)
	if !okGit || !okFS || g == nil || fs == nil {
		return nil, nil, false
	}
	gitRoot, errGit := filepath.Abs(g.config.Root)
	fsRoot, errFS := filepath.Abs(fs.config.Root)
	return g, fs, errGit == nil && errFS == nil && gitRoot == fsRoot
}

// worktreeMerge folds a repository's working tree into its git enumeration so
// each blob gets one callback carrying its history and working-tree locations
// (C-WORKTREE-1, INV-ONECALLBACK).
//
// The working tree is prewalked concurrently with git's own index phase. The
// prewalk keeps only blob id -> repo-relative paths, never content. Blobs that
// git does not report are read again from disk afterwards, one at a time per
// reader, so memory stays bounded by the number of working-tree paths.
type worktreeMerge struct {
	fs       *FilesystemEnumerator
	root     string // filesystem root as configured; walked paths start with it
	absRoot  string
	callback blobCallback

	done     chan struct{}
	err      error                     // prewalk error; read only after done
	paths    map[types.BlobID][]string // sorted, slash-separated; read only after done
	archives map[string]struct{}       // archive files the prewalk extracted from
	head     map[string]string         // HEAD tree path, scan-root-relative -> blob object id (hex); read only after done
	// prefix is the scan root's path inside the repository ("sub/", or
	// empty at the top level). History paths are repository-relative and
	// working-tree paths scan-root-relative, so prefix joins them. Read
	// only after done.
	prefix string
	warn   io.Writer

	mu    sync.Mutex
	seen  map[types.BlobID]bool
	ident *types.GitProvenance // identity of the first git provenance reported
	// deferred holds, per blob id, the working-tree paths whose HEAD blob
	// is another git object with the same text (see withWorktree). A later
	// git callback for that id that records the path in history settles
	// it; whatever is left is reported by emitDeferred.
	deferred map[types.BlobID]*deferredWorktree
}

// deferredWorktree is the content of a blob and its working-tree paths not
// yet known to be covered by a history location.
type deferredWorktree struct {
	content []byte
	paths   []string
}

// enumerateGitWithWorktree runs the git enumeration with the working tree
// merged in. git remains the scan authority: a working-tree failure never
// stops or drops a history blob (SEC-12); it is returned after history and
// any working-tree blobs already found are reported.
func enumerateGitWithWorktree(ctx context.Context, g *GitEnumerator, fs *FilesystemEnumerator, callback blobCallback) error {
	absRoot, err := filepath.Abs(g.config.Root)
	if err != nil {
		absRoot = g.config.Root
	}
	m := &worktreeMerge{
		fs:       fs,
		root:     fs.config.Root,
		absRoot:  absRoot,
		callback: callback,
		done:     make(chan struct{}),
		paths:    make(map[types.BlobID][]string),
		archives: make(map[string]struct{}),
		seen:     make(map[types.BlobID]bool),
		deferred: make(map[types.BlobID]*deferredWorktree),
		warn:     g.warnWriter(),
	}

	walkCtx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		<-m.done
	}()
	go m.prewalk(walkCtx)

	if err := g.Enumerate(ctx, m.gitCallback(ctx)); err != nil {
		return err
	}
	if err := m.wait(ctx); err != nil {
		return err
	}
	if err := m.emitDeferred(ctx, g); err != nil {
		return err
	}
	return errors.Join(m.emitWorktreeOnly(ctx, g), m.err)
}

// prewalk records every working-tree path per blob id, dropping content, and
// HEAD's blob per path. It reuses every filesystem filter (ignore file, size,
// symlinks, archives).
func (m *worktreeMerge) prewalk(ctx context.Context) {
	defer close(m.done)
	m.head = headBlobs(ctx, m.absRoot, m.warn)
	m.prefix = repoPrefix(ctx, m.absRoot)
	var mu sync.Mutex
	m.err = m.fs.Enumerate(ctx, func(_ []byte, id types.BlobID, prov types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
		switch p := prov.(type) {
		case types.FileProvenance:
			if rel, err := filepath.Rel(m.root, p.FilePath); err == nil {
				m.paths[id] = append(m.paths[id], filepath.ToSlash(rel))
			}
		case types.ArchiveProvenance:
			m.archives[p.ArchivePath] = struct{}{}
		}
		return nil
	})
	for _, ps := range m.paths {
		slices.Sort(ps)
	}
}

// wait blocks until the prewalk has finished or ctx is done.
func (m *worktreeMerge) wait(ctx context.Context) error {
	select {
	case <-m.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// claim marks id as reported; it returns false when it already was.
func (m *worktreeMerge) claim(id types.BlobID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[id] {
		return false
	}
	m.seen[id] = true
	return true
}

// gitCallback wraps the caller's callback for git blobs: it waits for the
// prewalk, then adds the blob's working-tree paths to its locations.
//
// git reports each object once, but two objects share a BlobID when they hold
// the same text in different encodings (a UTF-8 and a UTF-16 file). The first
// callback for an id carries its working-tree paths; a later one passes
// through with only its own history locations, never dropped, and settles
// the working-tree paths the first one deferred to it.
func (m *worktreeMerge) gitCallback(ctx context.Context) blobCallback {
	return func(content []byte, id types.BlobID, prov types.Provenance) error {
		if err := m.wait(ctx); err != nil {
			return err
		}
		gp, isGit := prov.(types.GitProvenance)
		m.mu.Lock()
		first := !m.seen[id]
		m.seen[id] = true
		if isGit && m.ident == nil {
			m.ident = &types.GitProvenance{RepoPath: gp.RepoPath, RepoRoot: gp.RepoRoot, RepoTop: gp.RepoTop, RemoteIdentity: gp.RemoteIdentity}
		}
		if !first && isGit {
			m.settleDeferred(id, gp)
		}
		m.mu.Unlock()
		if !first || !isGit {
			return m.callback(content, id, prov)
		}
		gp, wait := m.withWorktree(gp, id, m.paths[id], content)
		if len(wait) > 0 {
			m.mu.Lock()
			m.deferred[id] = &deferredWorktree{content: content, paths: wait}
			m.mu.Unlock()
		}
		return m.callback(content, id, gp)
	}
}

// settleDeferred drops the deferred working-tree paths of id that gp records
// in history. m.mu must be held.
func (m *worktreeMerge) settleDeferred(id types.BlobID, gp types.GitProvenance) {
	d := m.deferred[id]
	if d == nil {
		return
	}
	d.paths = slices.DeleteFunc(d.paths, func(p string) bool {
		return gp.BlobPath == m.prefix+p || slices.ContainsFunc(gp.Locations, func(l types.GitLocation) bool {
			return !l.WorkingTree && l.Path == m.prefix+p
		})
	})
	if len(d.paths) == 0 {
		delete(m.deferred, id)
	}
}

// emitDeferred reports, after git has reported every blob, the deferred
// working-tree paths no history location covered, one callback per blob.
func (m *worktreeMerge) emitDeferred(ctx context.Context, g *GitEnumerator) error {
	m.mu.Lock()
	ids := slices.SortedFunc(maps.Keys(m.deferred), func(a, b types.BlobID) int { return bytes.Compare(a[:], b[:]) })
	m.mu.Unlock()
	if len(ids) == 0 {
		return nil
	}
	ident := m.identity(ctx, g)
	for _, id := range ids {
		m.mu.Lock()
		d := m.deferred[id]
		delete(m.deferred, id)
		m.mu.Unlock()
		gp := ident
		gp.BlobPath = d.paths[0]
		gp.Locations = make([]types.GitLocation, len(d.paths))
		for i, p := range d.paths {
			gp.Locations[i] = types.GitLocation{Path: p, WorkingTree: true}
		}
		if err := m.callback(d.content, id, gp); err != nil {
			return err
		}
	}
	return nil
}

// withWorktree appends each working-tree path of blob id as a WorkingTree
// location unless HEAD holds this same blob at that path and history records
// it there. A tracked, unmodified file therefore adds nothing, while a file
// restored to a blob only an older commit held keeps its working-tree
// location. Working-tree paths stay relative to the scan root; history
// paths are matched with the scan root's prefix in the repository.
//
// A path HEAD holds as a different git object with the same text (the
// UTF-16 copy of a UTF-8 blob, or the reverse) is not decided here: that
// object's own callback records it in history. It is returned in wait so the
// caller can confirm that, and report it if no callback does.
func (m *worktreeMerge) withWorktree(gp types.GitProvenance, id types.BlobID, wt []string, content []byte) (_ types.GitProvenance, wait []string) {
	locs := gp.Locations
	if len(locs) == 0 {
		locs = []types.GitLocation{{Path: gp.BlobPath, Commit: gp.Commit}}
	}
	var extra []types.GitLocation
	for _, p := range wt {
		inHistory := slices.ContainsFunc(locs, func(l types.GitLocation) bool { return l.Path == m.prefix+p })
		held := m.headHolds(id, p)
		switch {
		case inHistory && held:
		case held && !m.headIsObject(p, content):
			wait = append(wait, p)
		default:
			extra = append(extra, types.GitLocation{Path: p, WorkingTree: true})
		}
	}
	if len(extra) == 0 {
		return gp, wait
	}
	gp.Locations = slices.Concat(locs, extra)
	gp.RepoRoot = cmp.Or(gp.RepoRoot, m.absRoot)
	return gp, wait
}

// headIsObject reports whether HEAD's blob at path is the git object whose
// content git reported as content. A transcoded object's content is not its
// stored bytes, so it never is; its path is then settled by emitDeferred.
func (m *worktreeMerge) headIsObject(path string, content []byte) bool {
	oid := m.head[path]
	return gitObjectID(content, len(oid)) == oid
}

// headHolds reports whether HEAD's blob at path is the working-tree file
// there, whose BlobID is id. In a SHA-1 repository a file git did not
// transcode has its object id as its BlobID; otherwise (UTF-16 text, SHA-256)
// the file is hashed as git hashes it, which only such files pay for.
//
// That read takes only a regular file, never through a symlink and never
// waiting on a FIFO, and at most the scanner's maximum file size. A file it
// cannot read that way counts as not held, so its working-tree location is
// kept.
func (m *worktreeMerge) headHolds(id types.BlobID, path string) bool {
	oid, ok := m.head[path]
	if !ok {
		return false
	}
	if oid == id.Hex() {
		return true
	}
	f, exists, bad := openRegularRefFile(os.Lstat, osOpenRef, filepath.Join(m.root, filepath.FromSlash(path)))
	if !exists || bad {
		return false
	}
	defer func() { _ = f.Close() }()
	r := io.Reader(f)
	limit := m.fs.config.MaxFileSize
	if limit > 0 {
		r = io.LimitReader(f, limit+1)
	}
	content, err := io.ReadAll(r)
	if err != nil || (limit > 0 && int64(len(content)) > limit) {
		return false
	}
	return gitObjectID(content, len(oid)) == oid
}

// emitWorktreeOnly reports the working-tree blobs git did not: each blob is
// read once, from its first readable path, and gets one callback carrying
// every working-tree path. Archives are re-extracted and keep today's dedup.
func (m *worktreeMerge) emitWorktreeOnly(ctx context.Context, g *GitEnumerator) error {
	var pending []types.BlobID
	for id := range m.paths {
		if !m.isSeen(id) {
			pending = append(pending, id)
		}
	}
	if len(pending) == 0 && len(m.archives) == 0 {
		return nil
	}
	slices.SortFunc(pending, func(a, b types.BlobID) int { return bytes.Compare(a[:], b[:]) })
	cb := m.worktreeCallback(m.identity(ctx, g))

	eg, ectx := errgroup.WithContext(ctx)
	eg.SetLimit(cmp.Or(max(m.fs.config.NumReaders, 0), runtime.NumCPU()))
	for _, id := range pending {
		eg.Go(func() error { return m.readWorktreeBlob(ectx, id, cb) })
	}
	for _, archive := range slices.Sorted(maps.Keys(m.archives)) {
		eg.Go(func() error { return m.fs.processFile(ectx, archive, cb) })
	}
	return eg.Wait()
}

// readWorktreeBlob reads the blob's paths in order until one yields it.
func (m *worktreeMerge) readWorktreeBlob(ctx context.Context, id types.BlobID, cb blobCallback) error {
	for _, rel := range m.paths[id] {
		if m.isSeen(id) {
			return nil
		}
		if err := m.fs.processFile(ctx, filepath.Join(m.root, filepath.FromSlash(rel)), cb); err != nil {
			return err
		}
	}
	return nil
}

func (m *worktreeMerge) isSeen(id types.BlobID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seen[id]
}

// worktreeCallback reports a working-tree-only file blob as a GitProvenance
// whose locations are all of its working-tree paths. The id is the one
// computed from the content just read, so a file changed since the prewalk
// is still reported, under its new id; when another callback already
// reported that id, the file still reaches the callback, as its own path
// only, so its location is not dropped. Other provenances (archive members)
// pass through, deduplicated as the filesystem scan does.
func (m *worktreeMerge) worktreeCallback(ident types.GitProvenance) blobCallback {
	return func(content []byte, id types.BlobID, prov types.Provenance) error {
		fp, isFile := prov.(types.FileProvenance)
		first := m.claim(id)
		if !first && !isFile {
			return nil
		}
		if isFile {
			paths := m.paths[id]
			if len(paths) == 0 || !first {
				rel, err := filepath.Rel(m.root, fp.FilePath)
				if err != nil {
					rel = fp.FilePath
				}
				paths = []string{filepath.ToSlash(rel)}
			}
			gp := ident
			gp.BlobPath = paths[0]
			gp.Locations = make([]types.GitLocation, len(paths))
			for i, p := range paths {
				gp.Locations[i] = types.GitLocation{Path: p, WorkingTree: true}
			}
			prov = gp
		}
		return m.callback(content, id, prov)
	}
}

// identity is the repository identity for working-tree-only blobs: the one
// git reported, or, when git reported no blob, the one the native path
// would have used.
func (m *worktreeMerge) identity(ctx context.Context, g *GitEnumerator) types.GitProvenance {
	m.mu.Lock()
	ident := m.ident
	m.mu.Unlock()
	if ident != nil {
		gp := *ident
		gp.RepoRoot = cmp.Or(gp.RepoRoot, m.absRoot)
		return gp
	}
	remote, ok := originIdentity(ctx, g.config.Root)
	id := g.repoIdentity(remote, ok)
	return types.GitProvenance{RepoPath: id.path, RepoRoot: id.root, RemoteIdentity: id.remote}
}

// headBlobs maps each blob path in HEAD's tree under dir, relative to dir,
// to its object id (hex). It is empty when HEAD cannot be read, so every
// working-tree path is then kept. That is expected when HEAD is unborn (a
// repository with no commit, or an orphan branch); any other failure is
// warned on warn.
func headBlobs(ctx context.Context, dir string, warn io.Writer) map[string]string {
	head := make(map[string]string)
	out, err := hardenedGit(ctx, dir, "ls-tree", "-r", "-z", "HEAD").Output()
	if err != nil {
		if ctx.Err() == nil && hardenedGit(ctx, dir, "rev-parse", "--verify", "-q", "HEAD").Run() == nil {
			_, _ = fmt.Fprintf(warn, "warning: %s\n", types.SanitizeDisplay(fmt.Sprintf(
				"cannot list HEAD's tree in %s (%v); working-tree copies of tracked files are reported as working-tree locations", dir, err)))
		}
		return head
	}
	// Each record is "<mode> SP <type> SP <object> TAB <path>".
	for rec := range bytes.SplitSeq(out, []byte{0}) {
		meta, path, ok := bytes.Cut(rec, []byte{'\t'})
		fields := bytes.Fields(meta)
		if !ok || len(fields) != 3 || string(fields[1]) != "blob" {
			continue
		}
		head[string(path)] = string(fields[2])
	}
	return head
}

// repoPrefix is dir's path inside its repository, slash-separated with a
// trailing slash ("sub/"), or empty at the top level or when git cannot say.
func repoPrefix(ctx context.Context, dir string) string {
	out, err := hardenedGit(ctx, dir, "rev-parse", "--show-prefix").Output()
	if err != nil {
		return ""
	}
	return string(bytes.TrimSuffix(out, []byte{'\n'}))
}

// repoTop is the absolute top level of the repository holding dir, or ""
// when dir is that top level or git cannot say. History paths are relative
// to it. It is dir with its in-repository prefix removed, which keeps the
// spelling the scan root was given, unless that is not the directory git
// names as the top level (a symlink inside the prefix); then it is git's.
func repoTop(ctx context.Context, dir string) string {
	prefix := bytes.TrimSuffix([]byte(repoPrefix(ctx, dir)), []byte{'/'})
	if len(prefix) == 0 {
		return ""
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	top := abs
	for range bytes.Count(prefix, []byte{'/'}) + 1 {
		top = filepath.Dir(top)
	}
	out, err := hardenedGit(ctx, dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return top
	}
	gitTop := filepath.FromSlash(string(bytes.TrimSuffix(out, []byte{'\n'})))
	a, errA := os.Stat(top)
	b, errB := os.Stat(gitTop)
	if errA == nil && errB == nil && os.SameFile(a, b) {
		return top
	}
	return gitTop
}

// gitObjectID is the hex object id git gives content as a blob: SHA-1 when
// hexLen is 40, else SHA-256.
func gitObjectID(content []byte, hexLen int) string {
	h := sha256.New()
	if hexLen == 2*sha1.Size {
		h = sha1.New() // #nosec G401 -- git object ids, not integrity
	}
	_, _ = fmt.Fprintf(h, "blob %d\x00", len(content))
	_, _ = h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}
