package enum

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/titus/pkg/repoid"
	"github.com/praetorian-inc/titus/pkg/types"
)

// blobEntry holds a deduplicated blob and its first-seen rev-list path. hash
// is the blob's index key (see objectKey): the object id in a SHA-1
// repository, the first 20 bytes of it in a SHA-256 one.
type blobEntry struct {
	hash [20]byte
	path string
}

// repoIdentity is the repository identity stamped on every provenance record.
type repoIdentity struct {
	path   string // normalized remote identity, or the typed root
	root   string // absolute working-tree root
	remote bool   // path is a normalized remote identity
}

// gitBinaryAvailable returns true if the git binary is on PATH.
func gitBinaryAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// enumerateAllHistoryNative uses native git commands for fast history enumeration.
//
// Phase 1 runs four tasks concurrently:
//   - git rev-list --all --objects: the scan set (the authority on which blobs
//     are scanned). Its failure fails the enumeration and cancels the others.
//   - git log with raw diff output: the blob index, which gives each blob
//     every path it had with the earliest commit for each path. Best effort:
//     a failure falls back to the rev-list path with no commit, and never
//     drops a blob.
//   - git config remote.origin.url: the repository identity. Best effort.
//   - taggedTreeBlobs: the blobs under trees that refs point at directly,
//     which are marked as possibly missing locations. Its failure fails the
//     enumeration, as rev-list's does.
//
// Phase 2 streams blob content through git cat-file --batch and invokes the
// callback once per text blob.
func (e *GitEnumerator) enumerateAllHistoryNative(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	root := e.config.Root
	var (
		rl       revList
		idx      *blobIndex
		indexErr error
		remoteID string
		remoteOK bool
		// treeBlobs are the blobs under trees that refs point at directly;
		// treeRefs counts those refs.
		treeBlobs map[[20]byte]struct{}
		treeRefs  int
	)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		rl, err = e.collectBlobEntries(gctx)
		return err
	})
	g.Go(func() error {
		idx, indexErr = e.indexBuilder()(gctx, root)
		return nil
	})
	g.Go(func() error {
		remoteID, remoteOK = originIdentity(gctx, root)
		return nil
	})
	g.Go(func() error {
		var err error
		treeBlobs, treeRefs, err = taggedTreeBlobs(gctx, root)
		return err
	})
	if err := g.Wait(); err != nil {
		return err
	}

	warn := e.warnWriter()
	if indexErr != nil {
		// Each blob falls back to its one rev-list path, marked as possibly
		// missing others (R1).
		idx = unavailableIndex()
		if ctx.Err() == nil {
			_, _ = fmt.Fprintf(warn, "titus: git history index unavailable: %v; each blob falls back to one path and is marked as possibly missing locations\n", indexErr)
		}
	}
	idx.setTaggedTrees(treeBlobs, treeRefs)
	idx.stats.malformed += rl.malformed
	writeEnumWarnings(warn, idx, rl.overlong)

	err := e.streamBlobContents(ctx, &rl, idx, e.repoIdentity(remoteID, remoteOK), callback)
	writeMissingWarning(warn, rl.missing)
	return err
}

// writeMissingWarning reports objects the repository lacks, which were
// therefore not scanned. Titus never fetches them: a lazy fetch runs the
// scanned repository's own remote configuration (V1).
func writeMissingWarning(w io.Writer, missing int) {
	if missing > 0 {
		_, _ = fmt.Fprintf(w, "titus: %d git objects are missing from the repository (for example, not fetched by a partial clone) and were not scanned; fetch the full history to scan them\n", missing)
	}
}

// indexBuilder returns the blob index builder; tests inject their own.
func (e *GitEnumerator) indexBuilder() func(context.Context, string) (*blobIndex, error) {
	if e.buildIndex != nil {
		return e.buildIndex
	}
	return buildBlobIndex
}

// warnWriter returns where enumeration warnings go (stderr by default).
func (e *GitEnumerator) warnWriter() io.Writer {
	if e.warn != nil {
		return e.warn
	}
	return os.Stderr
}

// repoIdentity resolves the identity for the scanned root: the normalized
// origin remote when there is one, otherwise the root as the user typed it.
func (e *GitEnumerator) repoIdentity(remoteID string, remoteOK bool) repoIdentity {
	root := e.config.Root
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	if remoteOK {
		return repoIdentity{path: remoteID, root: abs, remote: true}
	}
	return repoIdentity{path: typedRepoIdentity(root), root: abs}
}

// typedRepoIdentity is the display-safe form of a root with no remote: the
// value as typed, with URL credentials removed and control characters
// escaped. No host is guessed (SEC-3).
func typedRepoIdentity(root string) string {
	return types.SanitizeDisplay(repoid.RedactUserinfo(root))
}

// originIdentity returns the normalized identity of the origin remote.
func originIdentity(ctx context.Context, dir string) (string, bool) {
	out, err := hardenedGit(ctx, dir, "config", "--get", "remote.origin.url").Output()
	if err != nil {
		return "", false
	}
	return repoid.Normalize(strings.TrimSpace(string(out)))
}

// writeEnumWarnings prints the index warnings, folding rev-list's over-long
// records into the index's count so the user sees one over-long line. It
// runs once, after the index is built, so updating its stats is safe.
func writeEnumWarnings(w io.Writer, idx *blobIndex, revOverlong int) {
	if idx == nil {
		if revOverlong > 0 {
			_, _ = fmt.Fprintf(w, "titus: skipped %d over-long git records\n", revOverlong)
		}
		return
	}
	idx.stats.overlong += revOverlong
	idx.writeWarnings(w)
}

// collectBlobEntries runs git rev-list --all --objects and returns its
// deduplicated blob entries and record counts.
func (e *GitEnumerator) collectBlobEntries(ctx context.Context) (revList, error) {
	// rev-list's missing=print mode lists objects a partial clone lacks as "?<id>"
	// instead of failing or lazily fetching them (V1).
	return runRevList(ctx, e.config.Root, nil, "rev-list", "--all", "--objects", "--missing=print")
}

// runRevList runs git with args in dir, feeding it stdin when that is not
// nil, and parses its rev-list --objects output.
func runRevList(ctx context.Context, dir string, stdin io.Reader, args ...string) (revList, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := hardenedGit(ctx, dir, args...)
	cmd.Stdin = stdin
	stderr := &limitedBuffer{limit: 4 << 10}
	cmd.Stderr = stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return revList{}, fmt.Errorf("git rev-list: pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return revList{}, fmt.Errorf("git rev-list: start: %w", err)
	}

	rl, readErr := parseRevList(stdout)
	if readErr != nil {
		// SEC-10: stop git, drain the pipe, then reap.
		cancel()
		_, _ = io.Copy(io.Discard, stdout)
		_ = cmd.Wait()
		return revList{}, fmt.Errorf("git rev-list: read: %w", readErr)
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return revList{}, ctx.Err()
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return revList{}, fmt.Errorf("git rev-list: %w: %s", err, msg)
		}
		return revList{}, fmt.Errorf("git rev-list: %w", err)
	}
	return rl, nil
}

// revList is the parsed output of git rev-list --objects.
type revList struct {
	blobs []blobEntry
	// tails holds bytes 20-31 of each SHA-256 object id, parallel to blobs,
	// so cat-file can be given the full id. It is nil in a SHA-1
	// repository, which therefore pays nothing for SHA-256 support.
	tails     [][12]byte
	overlong  int // paths over maxRecord: id kept, path dropped (SEC-9)
	malformed int // lines that are not "<id>" or "<id> <path>" (SEC-8)
	// missing counts objects git could not read: "?<id>" lines from
	// rev-list's missing=print mode (a partial clone's unfetched objects) and
	// cat-file "missing" answers. None of them is scanned (V1, V2).
	missing int
}

// sha256 reports whether the repository uses SHA-256 object ids.
func (rl *revList) sha256() bool { return rl.tails != nil }

// objectHex returns the full hex object id of blobs[i].
func (rl *revList) objectHex(dst []byte, i int) []byte {
	dst = hex.AppendEncode(dst, rl.blobs[i].hash[:])
	if rl.sha256() {
		dst = hex.AppendEncode(dst, rl.tails[i][:])
	}
	return dst
}

// parseRevList parses "git rev-list --objects" output. Lines "<id> <path>"
// are objects; lines "<id>" are commits and are skipped. The id width (40
// for SHA-1, 64 for SHA-256) is fixed by the first valid line; a line of the
// other width, or that is not lowercase hex, is skipped and counted as
// malformed. A path longer than maxRecord is dropped and counted as
// over-long, as the go-git walk drops it (SEC-9, R2); its id is kept, so the
// blob is still scanned. A line is buffered up to maxRevListLine, so memory
// per line stays bounded whatever the id width.
func parseRevList(r io.Reader) (revList, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	seen := revListSeen{
		sha1:   make(map[[20]byte]struct{}),
		sha256: make(map[[32]byte]struct{}),
	}
	var (
		rl      revList
		width   int
		long    []byte // a line that did not fit in the reader's buffer
		tooLong bool
	)
	for {
		chunk, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			if len(long)+len(chunk) > maxRevListLine {
				tooLong = true
				if len(long) == 0 {
					long = append(long, chunk[:min(len(chunk), sha256HexLen+1)]...)
				}
				continue
			}
			long = append(long, chunk...)
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return revList{}, err
		}
		line := chunk
		if len(long) > 0 {
			// The line's last chunk is bounded too: without this check a
			// line up to one buffer over the bound kept its path (R2).
			if !tooLong && len(long)+len(bytes.TrimSuffix(chunk, []byte{'\n'})) > maxRevListLine {
				tooLong = true
			}
			if !tooLong {
				long = append(long, chunk...)
			}
			line = long
		}
		line = bytes.TrimSuffix(line, []byte{'\n'})
		if tooLong {
			rl.overlong++
		}
		if len(line) > 0 || err == nil {
			rl.add(line, tooLong, &width, seen)
		}
		long, tooLong = long[:0], false
		if err != nil { // io.EOF
			return rl, nil
		}
	}
}

// maxRevListLine bounds one buffered rev-list line: the widest id, a space
// and a path of maxRecord. A longer line's path is over maxRecord whatever
// the id width, so it is dropped without being buffered.
const maxRevListLine = sha256HexLen + 1 + maxRecord

// revListSeen deduplicates rev-list objects on their full id. SHA-256 ids
// are keyed on all 32 bytes, so two blobs that share the 20-byte index key
// are both scanned rather than one being dropped as a duplicate.
type revListSeen struct {
	sha1   map[[20]byte]struct{}
	sha256 map[[32]byte]struct{}
}

// firstSight records id and reports whether it had not been seen before.
func (s revListSeen) firstSight(key [20]byte, tail [12]byte, sha256 bool) bool {
	if !sha256 {
		if _, dup := s.sha1[key]; dup {
			return false
		}
		s.sha1[key] = struct{}{}
		return true
	}
	var full [32]byte
	copy(full[:20], key[:])
	copy(full[20:], tail[:])
	if _, dup := s.sha256[full]; dup {
		return false
	}
	s.sha256[full] = struct{}{}
	return true
}

// add records one rev-list line.
func (rl *revList) add(line []byte, dropPath bool, width *int, seen revListSeen) {
	if id, ok := bytes.CutPrefix(line, []byte{'?'}); ok {
		// A "?" line (missing=print mode): an object the repository lacks. Titus never
		// fetches it (that would run the repository's remote config), so
		// it is counted and reported instead of being scanned.
		n := revListIDWidth(id)
		switch {
		case n != 0 && n == len(id) && bytes.Count(id, []byte{'0'}) == n:
			// The null id: a ref file that is not an object id, which
			// for-each-ref and go-git skip as a broken ref. It names no
			// object, so nothing is missing.
		case n != 0 && n == len(id):
			rl.missing++
		default:
			rl.malformed++
		}
		return
	}
	n := revListIDWidth(line)
	switch {
	case n == 0 || (*width != 0 && n != *width):
		rl.malformed++
		return
	case *width == 0:
		*width = n
	}
	if len(line) == n { // a commit
		return
	}
	if !dropPath && len(line)-(n+1) > maxRecord {
		// A path over maxRecord within the buffer bound: the same predicate
		// as the go-git walk's, so both keep or drop the same paths (R2).
		rl.overlong++
		dropPath = true
	}
	b, tail, ok := parseRevListLine(line, n, dropPath)
	if !ok {
		rl.malformed++
		return
	}
	if !seen.firstSight(b.hash, tail, n == sha256HexLen) {
		return
	}
	rl.blobs = append(rl.blobs, b)
	if n == sha256HexLen {
		rl.tails = append(rl.tails, tail)
	}
}

// revListIDWidth returns the length of the lowercase hex object id that
// starts line and is followed by the end of the line or a space, or 0.
func revListIDWidth(line []byte) int {
	for _, n := range [...]int{sha256HexLen, sha1HexLen} {
		if len(line) >= n && (len(line) == n || line[n] == ' ') && isHex(line[:n]) {
			return n
		}
	}
	return 0
}

// parseRevListLine decodes "<id> <path>" where the id is n hex characters.
// When dropPath is set only the id is kept.
func parseRevListLine(line []byte, n int, dropPath bool) (blobEntry, [12]byte, bool) {
	var b blobEntry
	hash, tail, ok := objectKey(line[:n])
	if !ok {
		return blobEntry{}, tail, false
	}
	b.hash = hash
	if !dropPath {
		b.path = string(line[n+1:])
	}
	return b, tail, true
}

// streamBlobContents feeds hashes to git cat-file --batch and invokes the
// callback once per text blob, with every location the index knows for it.
// An object cat-file reports missing is counted in rl.missing (V2).
func (e *GitEnumerator) streamBlobContents(ctx context.Context, rl *revList, idx *blobIndex, id repoIdentity, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	if len(rl.blobs) == 0 {
		return nil
	}
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := hardenedGit(ctx, e.config.Root, "cat-file", "--batch")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("git cat-file: stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("git cat-file: stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("git cat-file: start: %w", err)
	}

	// abort stops git, drains its stdout so it cannot block on a full pipe,
	// reaps it, and returns err; the caller's cancellation wins (SEC-10, M1).
	abort := func(err error) error {
		cancel()
		_ = stdin.Close()
		_, _ = io.Copy(io.Discard, stdout)
		_ = cmd.Wait()
		if parent.Err() != nil {
			return parent.Err()
		}
		return err
	}

	reader := bufio.NewReaderSize(stdout, 256*1024)

	// Interleave writes and reads to avoid pipe deadlocks.
	var req []byte
	for i, blob := range rl.blobs {
		if i%1000 == 0 && parent.Err() != nil {
			return abort(parent.Err())
		}

		req = append(rl.objectHex(req[:0], i), '\n')
		if _, err := stdin.Write(req); err != nil {
			return abort(fmt.Errorf("git cat-file: write: %w", err))
		}

		// Read response header: "<hash> <type> <size>\n"
		headerLine, err := reader.ReadString('\n')
		if err != nil {
			return abort(fmt.Errorf("git cat-file: read header: %w", err))
		}
		objType, size, missing, err := parseCatFileHeader(headerLine, req[:len(req)-1])
		if err != nil {
			return abort(fmt.Errorf("git cat-file: %w", err))
		}
		if missing {
			rl.missing++
			continue
		}

		// Non-blob objects and oversized blobs: discard content + trailing
		// newline.
		if objType != "blob" || (e.config.MaxFileSize > 0 && size > e.config.MaxFileSize) {
			if _, err := io.CopyN(io.Discard, reader, size+1); err != nil {
				return abort(fmt.Errorf("git cat-file: discard %s: %w", objType, err))
			}
			continue
		}

		// Read blob content.
		content := make([]byte, size)
		if _, err := io.ReadFull(reader, content); err != nil {
			return abort(fmt.Errorf("git cat-file: read content: %w", err))
		}

		// Consume trailing newline.
		if _, err := reader.ReadByte(); err != nil {
			return abort(fmt.Errorf("git cat-file: read trailing newline: %w", err))
		}

		var isText bool
		if content, isText = textContent(content); !isText {
			continue
		}

		// In a SHA-1 repository the git blob id IS the BlobID: both are
		// SHA-1("blob {len}\0{content}"). A SHA-256 id is not, so the BlobID
		// is computed as the filesystem enumerator computes it.
		blobID := types.BlobID(blob.hash)
		if rl.sha256() {
			blobID = types.ComputeBlobID(content)
		}

		if err := callback(content, blobID, blobProvenance(blob, idx, id)); err != nil {
			return abort(err)
		}
	}

	_ = stdin.Close()

	if err := cmd.Wait(); err != nil {
		if parent.Err() != nil {
			return parent.Err()
		}
		return fmt.Errorf("git cat-file: %w", err)
	}

	return nil
}

// parseCatFileHeader parses a git cat-file --batch header, "<id> <type>
// <size>" or "<id> missing", for the request id want. A header for another
// id, or one that does not fit the grammar, is an error: the stream can no
// longer be framed, so nothing after it can be trusted.
func parseCatFileHeader(line string, want []byte) (objType string, size int64, missing bool, err error) {
	line = strings.TrimSuffix(line, "\n")
	id, rest, _ := strings.Cut(line, " ")
	if id != string(want) { // want is always a well-formed id (objectHex)
		return "", 0, false, fmt.Errorf("unexpected header %q for %s", line, want)
	}
	if rest == "missing" {
		return "", 0, true, nil
	}
	objType, sizeStr, ok := strings.Cut(rest, " ")
	if !ok {
		return "", 0, false, fmt.Errorf("malformed header %q", line)
	}
	size, err = strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return "", 0, false, fmt.Errorf("parse size %q: %w", sizeStr, err)
	}
	if size < 0 {
		return "", 0, false, fmt.Errorf("negative size in header %q", line)
	}
	return objType, size, false, nil
}

// blobProvenance builds the provenance for one blob. Locations is every
// (path, earliest commit) the index recorded, sorted by path; the first is
// the primary location. The walk's own path, which is a path inside a tree a
// ref points at when the index lacks it, is added after them with no commit,
// so no path the walk reached is dropped. A blob the index does not know
// keeps that path alone. LocationsTruncated is set when the index dropped a
// location of this blob at its size limit (R1), whether or not it kept any,
// and for a blob under a tree a ref points at directly.
func blobProvenance(blob blobEntry, idx *blobIndex, id repoIdentity) types.GitProvenance {
	locs := idx.lookup(blob.hash)
	if blob.path != "" && !hasLocationPath(locs, blob.path) {
		locs = append(locs, types.GitLocation{Path: blob.path})
	}
	if len(locs) == 0 {
		locs = []types.GitLocation{{Path: blob.path}}
	}
	return types.GitProvenance{
		RepoPath:           id.path,
		Commit:             locs[0].Commit,
		BlobPath:           locs[0].Path,
		RepoRoot:           id.root,
		RemoteIdentity:     id.remote,
		Locations:          locs,
		LocationsTruncated: idx.locationsTruncated(blob.hash),
	}
}

// hasLocationPath reports whether locs has a location at path.
func hasLocationPath(locs []types.GitLocation, path string) bool {
	for _, l := range locs {
		if l.Path == path {
			return true
		}
	}
	return false
}
