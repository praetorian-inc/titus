package enum

import (
	"bufio"
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

// collectCommitMetadataForRepo runs git log to build a map of file path → commit metadata.
// When firstAdded is true, uses --diff-filter=ARC to find the commit that first
// introduced each path — this includes Adds, Renames, and Copies. Rename detection
// is on by default in git's log machinery, so a `git mv old new` is recorded as an
// `R` entry rather than a delete + add; filtering on `A` alone would miss the
// post-rename path and leave its blobs without commit metadata.
// When false, finds the most recent commit that touched each path.
func collectCommitMetadataForRepo(ctx context.Context, repoPath string, firstAdded bool) (map[string]*types.CommitMetadata, error) {
	args := []string{"log", "--all",
		"--format=%H%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%s", "--name-only"}
	if firstAdded {
		args = append(args, "--diff-filter=ARC")
	}

	cmd := hardenedGit(ctx, repoPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git log: pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git log: start: %w", err)
	}

	result := make(map[string]*types.CommitMetadata)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), maxRecord)

	var current *types.CommitMetadata
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Lines with 7 null-byte separators are commit headers
		parts := strings.SplitN(line, "\x00", 8)
		if len(parts) == 8 && len(parts[0]) == 40 {
			authorTS, _ := time.Parse(time.RFC3339, parts[3])
			committerTS, _ := time.Parse(time.RFC3339, parts[6])
			current = &types.CommitMetadata{
				CommitID:           parts[0],
				AuthorName:         parts[1],
				AuthorEmail:        parts[2],
				AuthorTimestamp:    authorTS,
				CommitterName:      parts[4],
				CommitterEmail:     parts[5],
				CommitterTimestamp: committerTS,
				Message:            parts[7],
			}
			continue
		}

		// File path line — only record the first occurrence per path
		if current != nil {
			if _, exists := result[line]; !exists {
				result[line] = current
			}
		}
	}

	// SEC-10: git blocks on a full pipe, so drain it before Wait whatever
	// stopped the scanner.
	scanErr := scanner.Err()
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if scanErr != nil {
		return result, fmt.Errorf("git log: read: %w", scanErr)
	}
	if waitErr != nil {
		return result, fmt.Errorf("git log: wait: %w", waitErr)
	}

	return result, nil
}

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
	id, subj, subjLen                                     uint32
	authorName, authorEmail, committerName, committerEmail uint32
	authorUnix, committerUnix                              int64
	authorOff, committerOff                                int32
	idLen                                                  uint8
	flags                                                  uint8
}

type indexStats struct {
	overlong       int // records over maxRecord, skipped (SEC-9)
	malformed      int // records that do not fit the log grammar (SEC-8)
	unsupportedOID int // SHA-256 blob ids, not indexable as types.BlobID
	droppedPairs   int // pairs not stored after maxIndexPairs (R1)
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

	mu   sync.Mutex
	meta map[uint32]*types.CommitMetadata // materialized on lookup, shared
}

// blobIndexLogArgs is the git log invocation the index parses: one
// first-parent raw diff per commit, NUL-delimited and never quoted (SEC-8).
func blobIndexLogArgs() []string {
	return []string{"log", "--all", "-z",
		"--format=%H%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%s",
		"--raw", "--no-abbrev", "--no-renames", "--diff-merges=first-parent",
		"--root", "--no-textconv", "--no-ext-diff", "--no-show-signature"}
}

// buildBlobIndex streams the history of repoPath into a blobIndex. It always
// drains git's output before waiting on it (SEC-10).
func buildBlobIndex(ctx context.Context, repoPath string) (*blobIndex, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := hardenedGit(ctx, repoPath, blobIndexLogArgs()...)
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

// header reads the seven fields that follow a commit id.
func (p *indexParser) header(id []byte) error {
	x := &p.x
	c := commitRec{idLen: uint8(len(id))}
	c.id = x.appendArena(id)

	for field := range 7 {
		tok, overlong, err := p.z.next()
		if errors.Is(err, io.EOF) {
			x.stats.malformed++
			break
		}
		if err != nil {
			return err
		}
		if overlong {
			x.stats.overlong++
			tok = nil
		}
		switch field {
		case 0:
			c.authorName = p.intern(tok)
		case 1:
			c.authorEmail = p.intern(tok)
		case 2:
			var ok bool
			if c.authorUnix, c.authorOff, ok = parseGitTime(tok); !ok {
				c.flags |= authorTimeUnusable
			}
		case 3:
			c.committerName = p.intern(tok)
		case 4:
			c.committerEmail = p.intern(tok)
		case 5:
			var ok bool
			if c.committerUnix, c.committerOff, ok = parseGitTime(tok); !ok || c.committerUnix == 0 {
				c.flags |= commitTimeUnusable
			}
		case 6:
			c.subj = x.appendArena(tok)
			c.subjLen = uint32(len(tok))
		}
	}
	x.commits = append(x.commits, c)
	p.cur = len(x.commits) - 1
	return nil
}

// rawEntry handles one ":srcmode dstmode srcid dstid status" token and always
// consumes the path token that follows it.
func (p *indexParser) rawEntry(meta []byte) error {
	dst, keep, malformed := p.parseMeta(meta)

	path, overlong, err := p.z.next()
	if errors.Is(err, io.EOF) {
		p.x.stats.malformed++
		return nil
	}
	if err != nil {
		return err
	}
	switch {
	case overlong:
		p.x.stats.overlong++
	case malformed || p.cur < 0:
		p.x.stats.malformed++
	case keep:
		p.addPair(indexPair{hash: dst, path: p.internPath(path), commit: uint32(p.cur)})
	}
	return nil
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
	switch {
	case len(f[3]) == 64 && isHex(f[3]):
		p.x.stats.unsupportedOID++
		return dst, false, false
	case len(f[3]) != 40:
		return dst, false, true
	}
	if _, err := hex.Decode(dst[:], f[3]); err != nil || dst == ([20]byte{}) {
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
func (p *indexParser) addPair(pair indexPair) {
	x := &p.x
	if p.full {
		x.stats.droppedPairs++
		return
	}
	if len(x.pairs) >= maxIndexPairs {
		x.compact()
		if len(x.pairs) >= maxIndexPairs {
			p.full = true
			x.stats.droppedPairs++
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
	ca, cb := &x.commits[a], &x.commits[b]
	ua, ub := ca.flags&commitTimeUnusable != 0, cb.flags&commitTimeUnusable != 0
	if ua != ub {
		if ua {
			return 1
		}
		return -1
	}
	if !ua {
		if c := cmp.Compare(ca.committerUnix, cb.committerUnix); c != 0 {
			return c
		}
	}
	return bytes.Compare(x.commitID(ca), x.commitID(cb))
}

func (x *blobIndex) commitID(c *commitRec) []byte {
	return x.arena[c.id : c.id+uint32(c.idLen)]
}

// appendArena copies b into the arena and returns its offset. A string that
// would overflow 32-bit offsets is stored empty.
func (x *blobIndex) appendArena(b []byte) uint32 {
	if len(x.arena)+len(b) > math.MaxUint32 {
		return 0
	}
	off := uint32(len(x.arena))
	x.arena = append(x.arena, b...)
	return off
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

// truncated reports whether the index dropped pairs at maxIndexPairs.
func (x *blobIndex) truncated() bool {
	return x != nil && x.stats.droppedPairs > 0
}

// writeWarnings prints one line per kind of record the index could not use.
func (x *blobIndex) writeWarnings(w io.Writer) {
	if x == nil {
		return
	}
	s := x.stats
	if s.overlong > 0 {
		fmt.Fprintf(w, "titus: skipped %d over-long git records\n", s.overlong)
	}
	if s.droppedPairs > 0 {
		fmt.Fprintf(w, "titus: git history index reached %d locations; %d more were not recorded, so location lists may be incomplete\n", len(x.pairs), s.droppedPairs)
	}
	if s.malformed > 0 {
		fmt.Fprintf(w, "titus: skipped %d malformed git records\n", s.malformed)
	}
	if s.unsupportedOID > 0 {
		fmt.Fprintf(w, "titus: %d SHA-256 git objects have no recorded location (only SHA-1 repositories are indexed)\n", s.unsupportedOID)
	}
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

// isObjectID reports whether b is a 40- (SHA-1) or 64- (SHA-256) hex id.
func isObjectID(b []byte) bool {
	return (len(b) == 40 || len(b) == 64) && isHex(b)
}

func isHex(b []byte) bool {
	for _, c := range b {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}
