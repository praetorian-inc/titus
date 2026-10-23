package enum

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"maps"
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
// by a previous call across any enumerator in this combined set.
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
			if seen[blobID] {
				mu.Unlock()
				return nil
			}
			seen[blobID] = true
			mu.Unlock()

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

	mu    sync.Mutex
	seen  map[types.BlobID]bool
	ident *types.GitProvenance // identity of the first git provenance reported
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
	return errors.Join(m.emitWorktreeOnly(ctx, g), m.err)
}

// prewalk records every working-tree path per blob id, dropping content. It
// reuses every filesystem filter (ignore file, size, symlinks, archives).
func (m *worktreeMerge) prewalk(ctx context.Context) {
	defer close(m.done)
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
func (m *worktreeMerge) gitCallback(ctx context.Context) blobCallback {
	return func(content []byte, id types.BlobID, prov types.Provenance) error {
		if err := m.wait(ctx); err != nil {
			return err
		}
		if !m.claim(id) {
			return nil
		}
		if gp, ok := prov.(types.GitProvenance); ok {
			m.mu.Lock()
			if m.ident == nil {
				m.ident = &types.GitProvenance{RepoPath: gp.RepoPath, RepoRoot: gp.RepoRoot, RemoteIdentity: gp.RemoteIdentity}
			}
			m.mu.Unlock()
			prov = m.withWorktree(gp, m.paths[id])
		}
		return m.callback(content, id, prov)
	}
}

// withWorktree appends each working-tree path that history does not already
// record for the blob as a WorkingTree location. A tracked, unmodified file
// therefore adds nothing.
func (m *worktreeMerge) withWorktree(gp types.GitProvenance, wt []string) types.GitProvenance {
	locs := gp.Locations
	if len(locs) == 0 {
		locs = []types.GitLocation{{Path: gp.BlobPath, Commit: gp.Commit}}
	}
	var extra []types.GitLocation
	for _, p := range wt {
		if !slices.ContainsFunc(locs, func(l types.GitLocation) bool { return l.Path == p }) {
			extra = append(extra, types.GitLocation{Path: p, WorkingTree: true})
		}
	}
	if len(extra) == 0 {
		return gp
	}
	gp.Locations = slices.Concat(locs, extra)
	gp.RepoRoot = cmp.Or(gp.RepoRoot, m.absRoot)
	return gp
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
// is still reported, under its new id. Other provenances (archive members)
// pass through.
func (m *worktreeMerge) worktreeCallback(ident types.GitProvenance) blobCallback {
	return func(content []byte, id types.BlobID, prov types.Provenance) error {
		if !m.claim(id) {
			return nil
		}
		if fp, ok := prov.(types.FileProvenance); ok {
			paths := m.paths[id]
			if len(paths) == 0 {
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
