package enum

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/praetorian-inc/titus/pkg/repoid"
	"github.com/praetorian-inc/titus/pkg/types"
)

// GitEnumerator enumerates blobs from a git repository.
type GitEnumerator struct {
	config Config
	// CommitRef optionally specifies a specific commit to enumerate (defaults to HEAD)
	CommitRef string
	// WalkAll when true walks all commits from all refs instead of single commit
	WalkAll bool

	// buildIndex builds the history blob index; nil means buildBlobIndex.
	buildIndex func(context.Context, string) (*blobIndex, error)
	// warn receives enumeration warnings; nil means os.Stderr.
	warn io.Writer
}

// NewGitEnumerator creates a new git enumerator.
func NewGitEnumerator(config Config) *GitEnumerator {
	return &GitEnumerator{
		config:    config,
		CommitRef: "HEAD",
	}
}

// Enumerate walks git history and yields unique blobs.
// When WalkAll is true, it prefers native git commands (60x faster on large repos)
// and falls back to go-git if the git binary is not available.
func (e *GitEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	if e.WalkAll {
		if gitBinaryAvailable() {
			return e.enumerateAllHistoryNative(ctx, callback)
		}
		return e.enumerateAllHistory(ctx, callback)
	}
	return e.enumerateSingleCommit(ctx, callback)
}

// openGoGitRepo opens the repository at root. A linked worktree's .git
// names a gitdir that holds only its HEAD and per-worktree refs; objects and
// shared refs are in the common directory, which git reads too (R4-2).
func openGoGitRepo(root string) (*git.Repository, error) {
	return git.PlainOpenWithOptions(root, &git.PlainOpenOptions{EnableDotGitCommonDir: true})
}

// goGitExtensions are the repository extensions go-git reads as git does.
// objectformat is allowed only as sha1: plumbing.Hash is 20 bytes.
var goGitExtensions = map[string]bool{
	"noop":            true,
	"preciousobjects": true,
	"partialclone":    true,
	"worktreeconfig":  true,
}

// goGitFormatSupported fails closed on a repository format go-git does not
// read, such as reftable refs or SHA-256 objects. A walk of one would skip
// history without an error (B1).
func goGitFormatSupported(repo *git.Repository, root string) error {
	cfg, err := repo.Config()
	if err != nil {
		return fmt.Errorf("failed to read git config: %w", err)
	}
	// go-git does not parse core.repositoryformatversion into cfg.Core.
	var version string
	for _, s := range cfg.Raw.Sections {
		if s.IsName("core") && s.Options.Has("repositoryformatversion") {
			version = strings.TrimSpace(s.Options.Get("repositoryformatversion"))
		}
	}
	// Extensions are checked in a version 0 repository too: git 2.28+ honours
	// v1-only ones such as refstorage there and refuses to read the
	// repository, so an extension go-git cannot read fails closed (R9-1).
	switch version {
	case "", "0", "1":
	default:
		return fmt.Errorf("%s: core.repositoryformatversion %s is not supported by the built-in git reader; install git to scan this repository's history", root, version)
	}
	for _, s := range cfg.Raw.Sections {
		if !s.IsName("extensions") {
			continue
		}
		for _, o := range s.Options {
			key := strings.ToLower(o.Key)
			if goGitExtensions[key] || (key == "objectformat" && strings.EqualFold(o.Value, "sha1")) {
				continue
			}
			return fmt.Errorf("%s: extensions.%s=%s is not supported by the built-in git reader; install git to scan this repository's history", root, key, o.Value)
		}
	}
	return nil
}

// treeBlob is one blob of a single tree and every path it is stored at.
type treeBlob struct {
	hash  plumbing.Hash
	paths []string
}

// enumerateSingleCommit walks the tree at a single commit (CommitRef). Each
// blob is yielded once, with every path it has in that tree as a location.
func (e *GitEnumerator) enumerateSingleCommit(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	repo, err := openGoGitRepo(e.config.Root)
	if err != nil {
		return fmt.Errorf("failed to open git repository: %w", err)
	}

	ref, err := repo.ResolveRevision(plumbing.Revision(e.CommitRef))
	if err != nil {
		return fmt.Errorf("failed to resolve ref %s: %w", e.CommitRef, err)
	}

	commit, err := repo.CommitObject(*ref)
	if err != nil {
		return fmt.Errorf("failed to get commit: %w", err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return fmt.Errorf("failed to get tree: %w", err)
	}

	// A TreeWalker, not tree.Files(): Files decodes every blob while walking,
	// and each blob is read once below anyway.
	var blobs []*treeBlob
	byHash := make(map[plumbing.Hash]*treeBlob)
	w := object.NewTreeWalker(tree, true, nil)
	defer w.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, entry, err := w.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to walk tree: %w", err)
		}
		if entry.Mode == filemode.Dir || entry.Mode == filemode.Submodule {
			continue
		}
		b, ok := byHash[entry.Hash]
		if !ok {
			b = &treeBlob{hash: entry.Hash}
			byHash[entry.Hash] = b
			blobs = append(blobs, b)
		}
		b.paths = append(b.paths, name)
	}

	id := e.repoIdentity(goGitOriginIdentity(repo))
	meta := &types.CommitMetadata{
		CommitID:           commit.Hash.String(),
		AuthorName:         commit.Author.Name,
		AuthorEmail:        commit.Author.Email,
		AuthorTimestamp:    commit.Author.When,
		CommitterName:      commit.Committer.Name,
		CommitterEmail:     commit.Committer.Email,
		CommitterTimestamp: commit.Committer.When,
		Message:            commit.Message,
	}

	for _, b := range blobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		content, ok, err := readGoGitBlob(repo, b.hash, e.config.MaxFileSize)
		if err != nil {
			return fmt.Errorf("failed to get contents of %s: %w", b.paths[0], err)
		}
		if !ok {
			continue
		}
		content, isText := textContent(content)
		if !isText {
			continue
		}

		slices.Sort(b.paths)
		locs := make([]types.GitLocation, len(b.paths))
		for i, p := range b.paths {
			locs[i] = types.GitLocation{Path: p, Commit: meta}
		}
		prov := types.GitProvenance{
			RepoPath:       id.path,
			Commit:         meta,
			BlobPath:       locs[0].Path,
			RepoRoot:       id.root,
			RemoteIdentity: id.remote,
			Locations:      locs,
		}
		if err := callback(content, types.ComputeBlobID(content), prov); err != nil {
			return err
		}
	}
	return nil
}

// enumerateAllHistory walks all commits from all refs with go-git, for hosts
// without a git binary. It yields the same callbacks as the native path: one
// per blob, with every (path, earliest commit) location from a first-parent,
// rename-free diff of each commit.
func (e *GitEnumerator) enumerateAllHistory(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	repo, err := openGoGitRepo(e.config.Root)
	if err != nil {
		return fmt.Errorf("failed to open git repository: %w", err)
	}
	if err := goGitFormatSupported(repo, e.config.Root); err != nil {
		return err
	}

	// missing starts at the tagged-tree subtrees the index walk could not
	// read, so one warning reports them with the missing blobs (N2).
	blobs, idx, missing, err := goGitHistoryIndex(ctx, repo)
	if err != nil {
		return err
	}
	writeEnumWarnings(e.warnWriter(), idx, 0)
	id := e.repoIdentity(goGitOriginIdentity(repo))

	defer func() { writeMissingWarning(e.warnWriter(), missing) }()
	for _, b := range blobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		content, ok, err := readGoGitBlob(repo, plumbing.Hash(b.hash), e.config.MaxFileSize)
		if errors.Is(err, plumbing.ErrObjectNotFound) {
			missing++ // counted and reported, as streamBlobContents does (V2)
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get contents of blob %s: %w", plumbing.Hash(b.hash), err)
		}
		if !ok {
			continue
		}
		content, isText := textContent(content)
		if !isText {
			continue
		}
		// The git blob hash is the BlobID, as on the native path.
		if err := callback(content, types.BlobID(b.hash), blobProvenance(b, idx, id)); err != nil {
			return err
		}
	}
	return nil
}

// goGitHistoryIndex diffs every commit reachable from HEAD or any ref against
// its first parent (no rename detection), the go-git equivalent of
// blobIndexLogArgs. It returns the scan set, deduplicated by blob in
// first-seen order, the blob index, and the number of distinct ref targets
// and tagged-tree subtrees missing from the repository. Only two trees are
// held at a time.
//
// It walks the commit graph itself rather than with repo.Log(All): that
// iterator skips refs to annotated tags, stops each ref's walk at the first
// commit already seen (so a merge's other parents behind it are never
// reached), and drops iterator errors.
func goGitHistoryIndex(ctx context.Context, repo *git.Repository) ([]blobEntry, *blobIndex, int, error) {
	p := &indexParser{
		pathIDs: make(map[string]uint32),
		nameIDs: make(map[string]uint32),
		cur:     -1,
	}
	seen := make(map[[20]byte]struct{})
	tw := newTaggedWalk(repo, nil, seen, &p.x.stats)
	// The walk and the tips share one missing set, so an object that a ref
	// names and a tagged tree holds is counted once, as rev-list counts it.
	stack, others, lost, err := goGitTips(repo, tw.missing)
	if err != nil {
		return nil, nil, 0, err
	}
	p.x.stats.lostWorktreeHeads = lost
	shallowList, err := repo.Storer.Shallow()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to read shallow commits: %w", err)
	}
	shallow := make(map[plumbing.Hash]struct{}, len(shallowList))
	for _, h := range shallowList {
		shallow[h] = struct{}{}
	}

	// Trees and blobs a ref reaches only through a tag (M4) come first:
	// rev-list --all --objects walks them before any commit's tree, so a
	// blob in both is listed at its tagged-tree path. git log never sees
	// them, so they join the scan set with that path and no commit, as on
	// the native path, and the blobs under a tagged tree are marked.
	treeRefs := 0
	for _, o := range others {
		if o.typ == plumbing.TreeObject {
			treeRefs++
		}
		if err := tw.add(ctx, o); err != nil {
			return nil, nil, 0, err
		}
	}
	blobs := tw.blobs
	walked := make(map[plumbing.Hash]struct{})

	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, nil, 0, err
		}
		h := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := walked[h]; ok {
			continue
		}
		walked[h] = struct{}{}

		c, err := repo.CommitObject(h)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to get commit %s: %w", h, err)
		}
		// A shallow commit's parents are not in the repository: git treats
		// it as a root.
		_, isShallow := shallow[h]
		if !isShallow {
			stack = append(stack, c.ParentHashes...)
		}
		changes, err := firstParentChanges(ctx, c, isShallow)
		if err != nil {
			return nil, nil, 0, err
		}
		p.goGitHeader(c)
		for _, ch := range changes {
			to := ch.To
			if to.Name == "" || to.TreeEntry.Mode == filemode.Submodule || to.TreeEntry.Hash.IsZero() {
				continue // deletion, or a gitlink rather than a blob
			}
			hash := [20]byte(to.TreeEntry.Hash)
			overlong := len(to.Name) > maxRecord
			if _, ok := seen[hash]; !ok {
				seen[hash] = struct{}{}
				b := blobEntry{hash: hash}
				if !overlong { // an over-long path is dropped, as rev-list does (SEC-9)
					b.path = to.Name
				}
				blobs = append(blobs, b)
			}
			if overlong {
				p.x.stats.overlong++
				continue
			}
			p.addEntry(hash, []byte(to.Name))
		}
	}
	idx := p.finish()
	idx.setTaggedTrees(tw.inTree, treeRefs)
	return blobs, idx, len(tw.missing), nil
}

// firstParentChanges diffs c against its first parent, or against the empty
// tree for a root commit or when root is set (a shallow boundary). A missing
// parent is an error, as it is for git log and rev-list.
func firstParentChanges(ctx context.Context, c *object.Commit, root bool) (object.Changes, error) {
	tree, err := c.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree for commit %s: %w", c.Hash, err)
	}
	var parentTree *object.Tree
	if !root && c.NumParents() > 0 {
		parent, err := c.Parent(0)
		if err != nil {
			return nil, fmt.Errorf("failed to get parent of commit %s: %w", c.Hash, err)
		}
		if parentTree, err = parent.Tree(); err != nil {
			return nil, fmt.Errorf("failed to get tree for commit %s: %w", parent.Hash, err)
		}
	}
	// nil options: no rename detection, as in blobIndexLogArgs.
	changes, err := object.DiffTreeWithOptions(ctx, parentTree, tree, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to diff commit %s: %w", c.Hash, err)
	}
	return changes, nil
}

// goGitHeader records c as the current commit, as header does for a git log
// record: the same interning, time rules and %s subject. Once the index is
// full it keeps only the commit's ordering key, as header does.
func (p *indexParser) goGitHeader(c *object.Commit) {
	x := &p.x
	hexID := []byte(c.Hash.String())
	if p.full {
		unix, _, ok := goGitTime(c.Committer.When)
		p.setCurKey(hexID, !ok || unix == 0, unix)
		return
	}
	off, n := x.appendArena(hexID)
	r := commitRec{idLen: uint8(n), id: off}
	r.authorName = p.intern([]byte(c.Author.Name))
	r.authorEmail = p.intern([]byte(c.Author.Email))
	r.committerName = p.intern([]byte(c.Committer.Name))
	r.committerEmail = p.intern([]byte(c.Committer.Email))

	var ok bool
	if r.authorUnix, r.authorOff, ok = goGitTime(c.Author.When); !ok {
		r.flags |= authorTimeUnusable
	}
	if r.committerUnix, r.committerOff, ok = goGitTime(c.Committer.When); !ok || r.committerUnix == 0 {
		r.flags |= commitTimeUnusable
	}

	subj := []byte(gitSubject(c.Message))
	r.subj, r.subjLen = x.appendArena(subj)

	x.commits = append(x.commits, r)
	p.cur = len(x.commits) - 1
	p.setCurKey(hexID, r.flags&commitTimeUnusable != 0, r.committerUnix)
}

// goGitTime splits a signature time into unix seconds and zone offset; go-git
// leaves the zero time when the signature's time does not parse.
func goGitTime(t time.Time) (unix int64, offset int32, ok bool) {
	if t.IsZero() {
		return 0, 0, false
	}
	_, off := t.Zone()
	return t.Unix(), int32(off), true
}

// gitSubject is git's %s: leading blank lines skipped, then the first
// paragraph with each line's trailing whitespace removed, joined by spaces.
func gitSubject(msg string) string {
	var lines []string
	for line := range strings.Lines(msg) {
		line = strings.TrimRight(line, " \t\r\n")
		if line == "" {
			if len(lines) > 0 {
				break
			}
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, " ")
}

// goGitOriginIdentity is originIdentity read through go-git: the last
// remote.origin.url value, the one originIdentity reads, normalized.
func goGitOriginIdentity(repo *git.Repository) (string, bool) {
	cfg, err := repo.Config()
	if err != nil {
		return "", false
	}
	origin, ok := cfg.Remotes["origin"]
	if !ok || len(origin.URLs) == 0 {
		return "", false
	}
	return repoid.Normalize(origin.URLs[len(origin.URLs)-1])
}

// objectSizer is implemented by storers that report an object's size without
// loading it, such as the filesystem storage.
type objectSizer interface {
	EncodedObjectSize(plumbing.Hash) (int64, error)
}

// readGoGitBlob reads the blob hash. ok is false when maxSize > 0 and the blob
// is larger; where the storer reports sizes, that is decided before the blob
// is loaded. A missing blob is an error wrapping plumbing.ErrObjectNotFound.
func readGoGitBlob(repo *git.Repository, hash plumbing.Hash, maxSize int64) (content []byte, ok bool, err error) {
	if s, isSizer := repo.Storer.(objectSizer); isSizer && maxSize > 0 {
		// ErrObjectNotFound here may only mean an alternate object store,
		// which EncodedObjectSize does not search: BlobObject decides.
		size, err := s.EncodedObjectSize(hash)
		if err != nil && !errors.Is(err, plumbing.ErrObjectNotFound) {
			return nil, false, err
		}
		if err == nil && size > maxSize {
			return nil, false, nil
		}
	}
	obj, err := repo.BlobObject(hash)
	if err != nil {
		return nil, false, err
	}
	if maxSize > 0 && obj.Size > maxSize {
		return nil, false, nil
	}
	content, err = readBlobObject(obj)
	if err != nil {
		return nil, false, err
	}
	return content, true, nil
}

func readBlobObject(obj *object.Blob) ([]byte, error) {
	r, err := obj.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
