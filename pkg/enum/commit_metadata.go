package enum

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// --- blob location index -----------------------------------------------------

// maxIndexPairs caps the (blob, path) pairs one index holds (R1). A variable so
// tests can lower it.
var maxIndexPairs = 20_000_000

// minCompactPairs is the slice length from which a full pairs slice is
// deduplicated in place instead of grown. A variable so tests can lower it.
var minCompactPairs = 1 << 20

// maxRecord bounds one git output record (a NUL-terminated field or path).
const maxRecord = 1 << 20

const nulReaderBuffer = 256 << 10

const (
	// commitTimeUnusable marks a committer time that failed to parse or is
	// zero; such commits sort after every commit with a usable time (SEC-14).
	commitTimeUnusable uint8 = 1 << iota
	// authorTimeUnusable marks an author time that failed to parse.
	authorTimeUnusable
)

// indexPair records that blob hash was stored at paths[path], first in
// commits[commit]. 28 bytes, no pointers.
type indexPair struct {
	hash   [20]byte
	path   uint32
	commit uint32
}

// commitRec is a compact commit header. Strings live in the index's arena
// (id, subject) or its interned names table; no pointers.
type commitRec struct {
	id, subj, subjLen                                      uint32
	authorName, authorEmail, committerName, committerEmail uint32
	authorUnix, committerUnix                              int64
	authorOff, committerOff                                int32
	idLen                                                  uint8
	flags                                                  uint8
}

type indexStats struct {
	overlong     int // records over maxRecord, skipped (SEC-9)
	malformed    int // records that do not fit the log grammar (SEC-8)
	droppedPairs int // pairs not stored after maxIndexPairs (R1)
	// attributed counts the over-long and malformed records whose loss is
	// tied to a blob: the blob is in truncatedBlobs, or the record carried
	// no location to lose. The rest could hide a location of any blob
	// (dropsUnattributed).
	attributed int
	// lostWorktreeHeads counts worktree HEADs and per-worktree refs that
	// go-git or git could not read, so commits only they reach were not
	// scanned (R4-1, R5-3, R6-1). It is not a count of worktrees (R7 F3).
	lostWorktreeHeads int
}

// blobIndex maps a blob to every path it was stored at in history and the
// earliest commit that stored it there. It is read-only after construction
// and safe for concurrent lookups.
type blobIndex struct {
	pairs   []indexPair // sorted by hash, then path (lexical)
	paths   []string    // sorted lexically; indexPair.path indexes it
	names   []string    // interned author and committer names and emails
	arena   []byte      // hex commit ids and subjects
	commits []commitRec
	stats   indexStats

	compactions int // compact calls, parse and finish alike

	// truncatedBlobs holds every blob that lost a location when the index
	// reached maxIndexPairs (R1), or whose raw entry was skipped as
	// over-long or malformed with its blob id still readable. It is nil
	// until then. Memory is one
	// 20-byte key per distinct affected blob, bounded by the blobs in the
	// history, never by the number of dropped pairs.
	truncatedBlobs map[[20]byte]struct{}

	// failed marks an index that could not be built: it records no
	// location, so every blob's locations are incomplete. An index built
	// from an empty history is not failed.
	failed bool

	// treeBlobs holds every blob under a tree that a ref points at directly,
	// not through a commit. git lists such a blob at the first path it
	// reaches it by and at no other, and listing every path under a tagged
	// tree is unbounded (ENG-9329), so these blobs are marked as possibly
	// missing locations. taggedTrees counts those refs for the warning.
	treeBlobs   map[[20]byte]struct{}
	taggedTrees int

	mu   sync.Mutex
	meta map[uint32]*types.CommitMetadata // materialized on lookup, shared
}

// blobIndexLogArgs is the git log invocation the index parses: one
// first-parent raw diff per commit, NUL-delimited and never quoted (SEC-8).
// The tips come on stdin, one commit id per line (see resolveRefTips).
func blobIndexLogArgs() []string {
	return []string{"log", "--stdin", "-z",
		"--format=%H%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%s",
		"--raw", "--no-abbrev", "--no-renames", "--diff-merges=first-parent",
		"--root", "--no-textconv", "--no-ext-diff", "--no-show-signature",
		// Paths stay repository-relative and complete even when the scan
		// root is a subdirectory and the repository sets diff.relative.
		"--no-relative",
		// An empty order file keeps git's own entry order and overrides
		// diff.orderFile, which reorders entries or, naming a missing file,
		// makes git log fail and the whole index unavailable. Git for
		// Windows maps /dev/null to NUL.
		"-O/dev/null"}
}

// buildBlobIndex streams the history of repoPath into a blobIndex. It always
// drains git's output before waiting on it (SEC-10).
//
// The log starts from the commits rev-list --all starts from, not from
// --all: git log --all dies on the first broken ref, which would cost every
// blob its commit metadata, where rev-list and go-git skip that ref. The
// tips go on stdin, so a repository with many refs never hits the argv limit.
func buildBlobIndex(ctx context.Context, repoPath string) (*blobIndex, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	tips, err := resolveRefTips(ctx, repoPath)
	if err != nil {
		return nil, fmt.Errorf("git log: tips: %w", err)
	}
	if len(tips.commits) == 0 {
		// No commit to start from. git log --stdin with no input falls
		// back to HEAD, so it is not run.
		return parseBlobIndex(bytes.NewReader(nil))
	}
	var in bytes.Buffer
	for _, id := range tips.commits {
		in.WriteString(id)
		in.WriteByte('\n')
	}

	cmd := hardenedGit(ctx, repoPath, blobIndexLogArgs()...)
	cmd.Stdin = &in
	stderr := &limitedBuffer{limit: 4 << 10}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git log: pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git log: start: %w", err)
	}

	idx, parseErr := parseBlobIndex(stdout)
	if parseErr != nil {
		cancel()
	}
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()

	switch {
	case parseErr != nil:
		return nil, fmt.Errorf("git log: parse: %w", parseErr)
	case waitErr != nil:
		return nil, fmt.Errorf("git log in %s: %w: %s", repoPath, waitErr, strings.TrimSpace(stderr.String()))
	case ctx.Err() != nil:
		return nil, fmt.Errorf("git log: %w", ctx.Err())
	}
	return idx, nil
}

// unavailableIndex stands in for an index that could not be built. Every
// lookup is empty and every blob is marked LocationsTruncated, so a blob
// that falls back to one path says that others may be missing (R1).
func unavailableIndex() *blobIndex {
	return &blobIndex{failed: true}
}

// parseBlobIndex builds an index from the output of blobIndexLogArgs.
func parseBlobIndex(r io.Reader) (*blobIndex, error) {
	p := &indexParser{
		z:       newNulReader(r, nulReaderBuffer, maxRecord),
		pathIDs: make(map[string]uint32),
		nameIDs: make(map[string]uint32),
		cur:     -1,
	}
	if err := p.run(); err != nil {
		return nil, err
	}
	return p.finish(), nil
}

// indexParser holds the transient state of one parse; the interning maps are
// dropped when the index is finished.
type indexParser struct {
	z       *nulReader
	x       blobIndex
	pathIDs map[string]uint32
	nameIDs map[string]uint32
	cur     int // index of the current commit, -1 before the first header
	full    bool

	// curKey orders the current commit for drop. Once the index is full a
	// header is reduced to this key and nothing else is stored, so memory
	// stops growing with the history; curID backs curKey.id.
	curKey commitKey
	curID  []byte
}

func (p *indexParser) run() error {
	for {
		tok, overlong, err := p.z.next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if overlong {
			p.x.stats.overlong++
			continue
		}
		tok = bytes.TrimPrefix(tok, []byte{'\n'})
		switch {
		case len(tok) > 0 && tok[0] == ':':
			if err := p.rawEntry(tok); err != nil {
				return err
			}
		case isObjectID(tok):
			if err := p.header(tok); err != nil {
				return err
			}
		default:
			p.x.stats.malformed++
		}
	}
}

// header reads the seven fields that follow a commit id. Once the index is
// full it keeps only the commit's ordering key: no interning, no arena
// growth, no commit record.
func (p *indexParser) header(id []byte) error {
	x := &p.x
	store := !p.full
	var c commitRec
	if store {
		off, n := x.appendArena(id)
		c = commitRec{idLen: uint8(n), id: off}
	}
	p.setCurKey(id, false, 0)

	for field := range 7 {
		tok, overlong, err := p.z.next()
		if errors.Is(err, io.EOF) {
			x.stats.malformed++
			x.stats.attributed++ // the stream ended: no location follows
			break
		}
		if err != nil {
			return err
		}
		if overlong {
			x.stats.overlong++
			x.stats.attributed++ // a metadata field, not a location
			tok = nil
		}
		switch {
		case field == 5:
			var ok bool
			if c.committerUnix, c.committerOff, ok = parseGitTime(tok); !ok || c.committerUnix == 0 {
				c.flags |= commitTimeUnusable
			}
			p.setCurKey(id, c.flags&commitTimeUnusable != 0, c.committerUnix)
		case !store:
		case field == 0:
			c.authorName = p.intern(tok)
		case field == 1:
			c.authorEmail = p.intern(tok)
		case field == 2:
			var ok bool
			if c.authorUnix, c.authorOff, ok = parseGitTime(tok); !ok {
				c.flags |= authorTimeUnusable
			}
		case field == 3:
			c.committerName = p.intern(tok)
		case field == 4:
			c.committerEmail = p.intern(tok)
		case field == 6:
			c.subj, c.subjLen = x.appendArena(tok)
		}
	}
	if store {
		x.commits = append(x.commits, c)
		p.cur = len(x.commits) - 1
	}
	return nil
}

// setCurKey records the ordering key of the commit being parsed. The id is
// copied: the reader reuses its buffer.
func (p *indexParser) setCurKey(id []byte, unusable bool, unix int64) {
	p.curID = append(p.curID[:0], id...)
	p.curKey = commitKey{id: p.curID, unusable: unusable, unix: unix}
}

// rawEntry handles one ":srcmode dstmode srcid dstid status" token and always
// consumes the path token that follows it.
func (p *indexParser) rawEntry(meta []byte) error {
	dst, keep, malformed := p.parseMeta(meta)

	path, overlong, err := p.z.next()
	if errors.Is(err, io.EOF) {
		p.x.stats.malformed++
		p.skipEntry(dst, keep, malformed)
		return nil
	}
	if err != nil {
		return err
	}
	switch {
	case overlong:
		p.x.stats.overlong++
		p.skipEntry(dst, keep, malformed)
	case malformed || p.cur < 0:
		p.x.stats.malformed++
		p.skipEntry(dst, keep, malformed)
	case keep:
		p.addEntry(dst, path)
	}
	return nil
}

// skipEntry ties a raw entry the index skipped to its blob. An entry worth
// indexing marks its blob, which lost the location; an entry not worth
// indexing (a deletion, a submodule) lost nothing. Only an entry whose blob
// id cannot be read stays unattributed.
func (p *indexParser) skipEntry(dst [20]byte, keep, malformed bool) {
	switch {
	case malformed:
		return
	case keep:
		p.x.markTruncated(dst)
	}
	p.x.stats.attributed++
}

// addEntry records that blob hash is stored at path in the current commit.
// Once the index is full nothing is interned: a path the index has never
// seen means the (hash, path) pair is new, so its location is lost.
func (p *indexParser) addEntry(hash [20]byte, path []byte) {
	if !p.full {
		p.addPair(indexPair{hash: hash, path: p.internPath(path), commit: uint32(p.cur)})
		return
	}
	p.x.stats.droppedPairs++
	id, ok := p.pathIDs[string(path)]
	if !ok {
		p.x.markTruncated(hash)
		return
	}
	p.drop(hash, id)
}

// parseMeta reports the destination blob of a raw entry and whether it is a
// file added, modified or type-changed into a blob worth indexing.
func (p *indexParser) parseMeta(meta []byte) (dst [20]byte, keep, malformed bool) {
	var f [5][]byte
	rest := meta[1:]
	for i := range f {
		var ok bool
		f[i], rest, ok = bytes.Cut(rest, []byte{' '})
		if ok != (i < 4) || len(f[i]) == 0 {
			return dst, false, true
		}
	}
	switch f[4][0] {
	case 'A', 'M', 'T':
	default:
		return dst, false, false
	}
	if string(f[1]) == "160000" { // submodule commit, not a blob
		return dst, false, false
	}
	dst, tail, ok := objectKey(f[3])
	if !ok || (dst == [20]byte{} && tail == [12]byte{}) {
		return dst, false, true
	}
	return dst, true, false
}

func (p *indexParser) intern(b []byte) uint32 {
	if id, ok := p.nameIDs[string(b)]; ok {
		return id
	}
	id := uint32(len(p.x.names))
	s := string(b)
	p.x.names = append(p.x.names, s)
	p.nameIDs[s] = id
	return id
}

func (p *indexParser) internPath(b []byte) uint32 {
	if id, ok := p.pathIDs[string(b)]; ok {
		return id
	}
	id := uint32(len(p.x.paths))
	s := string(b)
	p.x.paths = append(p.x.paths, s)
	p.pathIDs[s] = id
	return id
}

// addPair stores a pair, folding duplicates when the slice fills so that a
// long history of re-touched files does not grow memory with commit count.
// At maxIndexPairs a compaction that frees fewer than 1/64 of the slots
// makes the index full, so a run of duplicates cannot cost one sort of the
// whole slice per pair.
func (p *indexParser) addPair(pair indexPair) {
	x := &p.x
	if len(x.pairs) >= maxIndexPairs {
		x.compact()
		if maxIndexPairs-len(x.pairs) < max(maxIndexPairs/64, 1) {
			p.full = true
			x.stats.droppedPairs++
			p.drop(pair.hash, pair.path)
			return
		}
	}
	if len(x.pairs) == cap(x.pairs) && len(x.pairs) >= minCompactPairs {
		x.compact()
		if len(x.pairs) > cap(x.pairs)/4*3 {
			x.pairs = slices.Grow(x.pairs, cap(x.pairs))
		}
	}
	x.pairs = append(x.pairs, pair)
}

// drop marks the blob of a pair the full index cannot store when the pair,
// seen in the current commit, carried a location the index lacks: a (blob,
// path) it has not recorded, or a recorded one first seen at an earlier
// commit than the one it holds. A re-touch at the same or a later commit
// loses nothing and marks nothing. The comparison uses the current commit's
// key with the same order as compact, so it holds whatever order commits
// arrive in. The index is full only right after compact, so pairs are
// sorted by (hash, path, commit) and nothing is appended afterwards; path
// ids are still the parse-time ids that the pairs carry.
func (p *indexParser) drop(hash [20]byte, path uint32) {
	x := &p.x
	if _, ok := x.truncatedBlobs[hash]; ok {
		return
	}
	i, found := slices.BinarySearchFunc(x.pairs, indexPair{hash: hash, path: path}, func(e, t indexPair) int {
		if c := bytes.Compare(e.hash[:], t.hash[:]); c != 0 {
			return c
		}
		return cmp.Compare(e.path, t.path)
	})
	if found && compareCommitKeys(x.commitKey(x.pairs[i].commit), p.curKey) <= 0 {
		return
	}
	x.markTruncated(hash)
}

// skipOverlongPath marks hash, whose location was skipped because its path
// is over maxRecord (SEC-9), and counts the skip as attributed.
func (x *blobIndex) skipOverlongPath(hash [20]byte) {
	x.stats.overlong++
	x.stats.attributed++
	x.markTruncated(hash)
}

func (x *blobIndex) markTruncated(hash [20]byte) {
	if x.truncatedBlobs == nil {
		x.truncatedBlobs = make(map[[20]byte]struct{})
	}
	x.truncatedBlobs[hash] = struct{}{}
}

// finish sorts paths lexically, remaps pair path ids to match, deduplicates
// and trims the index to its final size.
func (p *indexParser) finish() *blobIndex {
	x := &p.x
	p.pathIDs, p.nameIDs = nil, nil

	order := make([]uint32, len(x.paths))
	for i := range order {
		order[i] = uint32(i)
	}
	slices.SortFunc(order, func(a, b uint32) int { return strings.Compare(x.paths[a], x.paths[b]) })
	remap := make([]uint32, len(order))
	sorted := make([]string, len(order))
	for newID, oldID := range order {
		remap[oldID] = uint32(newID)
		sorted[newID] = x.paths[oldID]
	}
	x.paths = sorted
	for i := range x.pairs {
		x.pairs[i].path = remap[x.pairs[i].path]
	}

	x.compact()
	if cap(x.pairs)-len(x.pairs) > len(x.pairs)/8 {
		x.pairs = slices.Clone(x.pairs)
	}
	if cap(x.arena)-len(x.arena) > len(x.arena)/8 {
		x.arena = slices.Clone(x.arena)
	}
	x.commits = slices.Clip(x.commits)
	return x
}

// compact sorts pairs by (hash, path, earliest commit) and keeps the first
// pair of each (hash, path).
func (x *blobIndex) compact() {
	x.compactions++
	slices.SortFunc(x.pairs, func(a, b indexPair) int {
		if c := bytes.Compare(a.hash[:], b.hash[:]); c != 0 {
			return c
		}
		if c := cmp.Compare(a.path, b.path); c != 0 {
			return c
		}
		return x.compareCommits(a.commit, b.commit)
	})
	x.pairs = slices.CompactFunc(x.pairs, func(a, b indexPair) bool {
		return a.hash == b.hash && a.path == b.path
	})
}

// compareCommits orders commits earliest first: usable committer times before
// unusable ones, then by committer time, then by commit id (SEC-14).
func (x *blobIndex) compareCommits(a, b uint32) int {
	if a == b {
		return 0
	}
	return compareCommitKeys(x.commitKey(a), x.commitKey(b))
}

// commitKey is what orders a commit: its committer time, whether that time
// is usable, and its id.
type commitKey struct {
	id       []byte
	unix     int64
	unusable bool
}

func (x *blobIndex) commitKey(i uint32) commitKey {
	c := &x.commits[i]
	return commitKey{id: x.commitID(c), unix: c.committerUnix, unusable: c.flags&commitTimeUnusable != 0}
}

func compareCommitKeys(a, b commitKey) int {
	if a.unusable != b.unusable {
		if a.unusable {
			return 1
		}
		return -1
	}
	if !a.unusable {
		if c := cmp.Compare(a.unix, b.unix); c != 0 {
			return c
		}
	}
	return bytes.Compare(a.id, b.id)
}

func (x *blobIndex) commitID(c *commitRec) []byte {
	return x.arena[c.id : c.id+uint32(c.idLen)]
}

// appendArena copies b into the arena and returns its offset and the length
// to store with it. A string that would overflow 32-bit offsets is stored
// empty: length 0, so it never reads back another string's bytes (M2).
func (x *blobIndex) appendArena(b []byte) (off, n uint32) {
	if len(x.arena)+len(b) > math.MaxUint32 {
		return 0, 0
	}
	off = uint32(len(x.arena))
	x.arena = append(x.arena, b...)
	return off, uint32(len(b))
}

// lookup returns every location of hash, sorted by path, or nil when the
// index has none; a nil index has none.
func (x *blobIndex) lookup(hash [20]byte) []types.GitLocation {
	if x == nil {
		return nil
	}
	i, found := slices.BinarySearchFunc(x.pairs, hash, func(p indexPair, h [20]byte) int {
		return bytes.Compare(p.hash[:], h[:])
	})
	if !found {
		return nil
	}
	j := i
	for j < len(x.pairs) && x.pairs[j].hash == hash {
		j++
	}
	locs := make([]types.GitLocation, 0, j-i)
	for _, p := range x.pairs[i:j] {
		locs = append(locs, types.GitLocation{Path: x.paths[p.path], Commit: x.commitMeta(p.commit)})
	}
	return locs
}

// commitMeta materializes a commit once and shares the pointer afterwards.
func (x *blobIndex) commitMeta(id uint32) *types.CommitMetadata {
	x.mu.Lock()
	defer x.mu.Unlock()
	if m, ok := x.meta[id]; ok {
		return m
	}
	c := &x.commits[id]
	m := &types.CommitMetadata{
		CommitID:           string(x.commitID(c)),
		AuthorName:         x.names[c.authorName],
		AuthorEmail:        x.names[c.authorEmail],
		AuthorTimestamp:    gitTime(c.authorUnix, c.authorOff, c.flags&authorTimeUnusable != 0),
		CommitterName:      x.names[c.committerName],
		CommitterEmail:     x.names[c.committerEmail],
		CommitterTimestamp: gitTime(c.committerUnix, c.committerOff, c.flags&commitTimeUnusable != 0),
		Message:            string(x.arena[c.subj : c.subj+c.subjLen]),
	}
	if x.meta == nil {
		x.meta = make(map[uint32]*types.CommitMetadata)
	}
	x.meta[id] = m
	return m
}

// locationsTruncated reports whether the index dropped a location of hash at
// maxIndexPairs (R1), or skipped an over-long or malformed raw entry of hash,
// so its lookup is incomplete by an unknown count. This
// includes a blob all of whose pairs were dropped, which lookup reports as
// unknown. A blob with no dropped pair is not marked, even when the index is
// truncated: none of its history locations were lost to the cap. An index
// that could not be built (unavailableIndex) marks every blob; a nil index
// marks nothing. When a linked worktree's HEAD could not be read, any blob
// may have a location only that worktree reaches, so every blob is marked;
// the index still answers lookups (R5-3).
func (x *blobIndex) locationsTruncated(hash [20]byte) bool {
	if x == nil {
		return false
	}
	if x.failed || x.stats.lostWorktreeHeads > 0 {
		return true
	}
	if _, ok := x.treeBlobs[hash]; ok {
		return true
	}
	_, ok := x.truncatedBlobs[hash]
	return ok
}

// dropsUnattributed reports whether the index or the walk skipped a record it
// cannot tie to a blob (over-long or malformed), so any blob's lookup may be
// missing a location that no per-blob mark records. Skipped records tied to
// a blob mark it in truncatedBlobs instead (stats.attributed).
func (x *blobIndex) dropsUnattributed() bool {
	return x != nil && x.stats.overlong+x.stats.malformed > x.stats.attributed
}

// marksAny reports whether locationsTruncated can be true for some blob.
func (x *blobIndex) marksAny() bool {
	return x != nil && (x.failed || x.stats.lostWorktreeHeads > 0 || len(x.truncatedBlobs) > 0 || len(x.treeBlobs) > 0)
}

// marksAll reports whether locationsTruncated is true for every blob: the
// index could not be built (unavailableIndex), so lookup finds nothing.
func (x *blobIndex) marksAll() bool {
	return x != nil && x.failed
}

// writeWarnings prints one line per kind of record the index could not use.
func (x *blobIndex) writeWarnings(w io.Writer) {
	if x == nil {
		return
	}
	s := x.stats
	if s.overlong > 0 {
		_, _ = fmt.Fprintf(w, "titus: skipped %d over-long git records\n", s.overlong)
	}
	if s.droppedPairs > 0 {
		_, _ = fmt.Fprintf(w, "titus: git history index reached %d locations; %d more were not recorded, so location lists may be incomplete\n", len(x.pairs), s.droppedPairs)
	}
	if s.malformed > 0 {
		_, _ = fmt.Fprintf(w, "titus: skipped %d malformed git records\n", s.malformed)
	}
	if s.lostWorktreeHeads > 0 {
		_, _ = fmt.Fprintf(w, "titus: could not read the HEADs or per-worktree refs of linked git worktrees (%d unread); commits reachable only from them were not scanned, so every finding is marked as possibly missing locations\n", s.lostWorktreeHeads)
	}
	if x.taggedTrees > 0 {
		_, _ = fmt.Fprintf(w, "titus: %d git refs point directly at a tree, not a commit; a file under such a tree is listed only at the first path git reaches it by, so those files are marked as possibly missing locations\n", x.taggedTrees)
	}
}

// setTaggedTrees records the blobs under trees that refs point at directly,
// and the number of those refs.
func (x *blobIndex) setTaggedTrees(blobs map[[20]byte]struct{}, refs int) {
	x.treeBlobs = blobs
	x.taggedTrees = refs
}

// parseGitTime parses git's strict ISO 8601 date (%aI, %cI).
func parseGitTime(b []byte) (unix int64, offset int32, ok bool) {
	t, err := time.Parse(time.RFC3339, string(b))
	if err != nil {
		return 0, 0, false
	}
	_, off := t.Zone()
	return t.Unix(), int32(off), true
}

// gitTime rebuilds a timestamp in its original zone; an unusable one is the
// zero time.
func gitTime(unix int64, offset int32, unusable bool) time.Time {
	if unusable {
		return time.Time{}
	}
	t := time.Unix(unix, 0)
	if offset == 0 {
		return t.UTC()
	}
	return t.In(time.FixedZone("", int(offset)))
}

// Hex lengths of SHA-1 and SHA-256 git object ids.
const (
	sha1HexLen   = 40
	sha256HexLen = 64
)

// isObjectID reports whether b is a 40- (SHA-1) or 64- (SHA-256) hex id.
func isObjectID(b []byte) bool {
	return (len(b) == sha1HexLen || len(b) == sha256HexLen) && isHex(b)
}

// objectKey decodes a lowercase hex object id into the key the blob index
// and the rev-list dedup use: the whole id for SHA-1, and its first 20
// bytes for SHA-256, whose remaining 12 bytes are returned as tail. A
// 160-bit prefix of SHA-256 keeps a 2^80 collision bound, the strength
// SHA-1 was designed for, and keeps the key one fixed width, so a SHA-1
// repository pays nothing for SHA-256 support.
func objectKey(id []byte) (key [20]byte, tail [12]byte, ok bool) {
	if !isObjectID(id) {
		return key, tail, false
	}
	var full [32]byte
	if _, err := hex.Decode(full[:len(id)/2], id); err != nil {
		return key, tail, false
	}
	copy(key[:], full[:20])
	copy(tail[:], full[20:])
	return key, tail, true
}

func isHex(b []byte) bool {
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
