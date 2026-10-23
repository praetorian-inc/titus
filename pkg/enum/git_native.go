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

// blobEntry holds a deduplicated blob hash and its first-seen rev-list path.
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
// Phase 1 runs three tasks concurrently:
//   - git rev-list --all --objects: the scan set (the authority on which blobs
//     are scanned). Its failure fails the enumeration and cancels the others.
//   - git log with raw diff output: the blob index, which gives each blob
//     every path it had with the earliest commit for each path. Best effort:
//     a failure falls back to the rev-list path with no commit, and never
//     drops a blob.
//   - git config remote.origin.url: the repository identity. Best effort.
//
// Phase 2 streams blob content through git cat-file --batch and invokes the
// callback once per text blob.
func (e *GitEnumerator) enumerateAllHistoryNative(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	root := e.config.Root
	var (
		blobs       []blobEntry
		revOverlong int
		idx         *blobIndex
		indexErr    error
		remoteID    string
		remoteOK    bool
	)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		blobs, revOverlong, err = e.collectBlobEntries(gctx)
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
	if err := g.Wait(); err != nil {
		return err
	}

	warn := e.warnWriter()
	if indexErr != nil {
		// Each blob falls back to its one rev-list path, marked as possibly
		// missing others (R1).
		idx = unavailableIndex()
		if ctx.Err() == nil {
			fmt.Fprintf(warn, "titus: git history index unavailable: %v; each blob falls back to one path and is marked as possibly missing locations\n", indexErr)
		}
	}
	writeEnumWarnings(warn, idx, revOverlong)

	return e.streamBlobContents(ctx, blobs, idx, e.repoIdentity(remoteID, remoteOK), callback)
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
			fmt.Fprintf(w, "titus: skipped %d over-long git records\n", revOverlong)
		}
		return
	}
	idx.stats.overlong += revOverlong
	idx.writeWarnings(w)
}

// collectBlobEntries runs git rev-list --all --objects and returns
// deduplicated blob entries and the number of over-long records.
func (e *GitEnumerator) collectBlobEntries(ctx context.Context) ([]blobEntry, int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "rev-list", "--all", "--objects")
	cmd.Dir = e.config.Root
	stderr := &limitedBuffer{limit: 4 << 10}
	cmd.Stderr = stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, fmt.Errorf("git rev-list: pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, 0, fmt.Errorf("git rev-list: start: %w", err)
	}

	blobs, overlong, readErr := readRevList(stdout)
	if readErr != nil {
		// SEC-10: stop git, drain the pipe, then reap.
		cancel()
		_, _ = io.Copy(io.Discard, stdout)
		_ = cmd.Wait()
		return nil, 0, fmt.Errorf("git rev-list: read: %w", readErr)
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, 0, fmt.Errorf("git rev-list: %w: %s", err, msg)
		}
		return nil, 0, fmt.Errorf("git rev-list: %w", err)
	}
	return blobs, overlong, nil
}

// readRevList parses "git rev-list --objects" output. Lines with a space at
// offset 40 are "<40-hex> <path>" objects; other lines are commits and are
// skipped. A line longer than maxRecord keeps its hash, so the blob is still
// scanned, but loses its path and is counted as over-long (SEC-9).
func readRevList(r io.Reader) ([]blobEntry, int, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	seen := make(map[[20]byte]struct{})
	var (
		blobs    []blobEntry
		overlong int
		long     []byte // a line that did not fit in the reader's buffer
		tooLong  bool
	)
	for {
		chunk, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			if len(long)+len(chunk) > maxRecord {
				tooLong = true
				if len(long) == 0 {
					long = append(long, chunk[:min(len(chunk), 41)]...)
				}
				continue
			}
			long = append(long, chunk...)
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, 0, err
		}
		line := chunk
		if len(long) > 0 {
			if !tooLong {
				long = append(long, chunk...)
			}
			line = long
		}
		line = bytes.TrimSuffix(line, []byte{'\n'})
		if tooLong {
			overlong++
		}
		if b, ok := parseRevListLine(line, tooLong); ok {
			if _, dup := seen[b.hash]; !dup {
				seen[b.hash] = struct{}{}
				blobs = append(blobs, b)
			}
		}
		long, tooLong = long[:0], false
		if err != nil { // io.EOF
			return blobs, overlong, nil
		}
	}
}

// parseRevListLine decodes "<40-hex> <path>". When dropPath is set only the
// hash is kept.
func parseRevListLine(line []byte, dropPath bool) (blobEntry, bool) {
	if len(line) < 41 || line[40] != ' ' {
		return blobEntry{}, false
	}
	var b blobEntry
	if _, err := hex.Decode(b.hash[:], line[:40]); err != nil {
		return blobEntry{}, false
	}
	if !dropPath {
		b.path = string(line[41:])
	}
	return b, true
}

// streamBlobContents feeds hashes to git cat-file --batch and invokes the
// callback once per text blob, with every location the index knows for it.
func (e *GitEnumerator) streamBlobContents(ctx context.Context, blobs []blobEntry, idx *blobIndex, id repoIdentity, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	if len(blobs) == 0 {
		return nil
	}

	cmd := exec.CommandContext(ctx, "git", "cat-file", "--batch")
	cmd.Dir = e.config.Root

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

	reader := bufio.NewReaderSize(stdout, 256*1024)

	// Interleave writes and reads to avoid pipe deadlocks.
	for i, blob := range blobs {
		if i%1000 == 0 {
			select {
			case <-ctx.Done():
				_ = stdin.Close()
				_ = cmd.Wait()
				return ctx.Err()
			default:
			}
		}

		hexStr := hex.EncodeToString(blob.hash[:])
		if _, err := fmt.Fprintf(stdin, "%s\n", hexStr); err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("git cat-file: write: %w", err)
		}

		// Read response header: "<hash> <type> <size>\n"
		headerLine, err := reader.ReadString('\n')
		if err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("git cat-file: read header: %w", err)
		}
		headerLine = strings.TrimSuffix(headerLine, "\n")

		// Parse: "<hash> <type> <size>" or "<hash> missing"
		parts := strings.SplitN(headerLine, " ", 3)
		if len(parts) < 3 || parts[1] == "missing" {
			continue
		}

		objType := parts[1]
		size, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			return fmt.Errorf("git cat-file: parse size %q: %w", parts[2], err)
		}

		// Non-blob objects: discard content + trailing newline.
		if objType != "blob" {
			if _, err := io.CopyN(io.Discard, reader, size+1); err != nil {
				_ = stdin.Close()
				_ = cmd.Wait()
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fmt.Errorf("git cat-file: discard non-blob: %w", err)
			}
			continue
		}

		// Oversized blobs: discard.
		if e.config.MaxFileSize > 0 && size > e.config.MaxFileSize {
			if _, err := io.CopyN(io.Discard, reader, size+1); err != nil {
				_ = stdin.Close()
				_ = cmd.Wait()
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fmt.Errorf("git cat-file: discard oversized: %w", err)
			}
			continue
		}

		// Read blob content.
		content := make([]byte, size)
		if _, err := io.ReadFull(reader, content); err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("git cat-file: read content: %w", err)
		}

		// Consume trailing newline.
		if _, err := reader.ReadByte(); err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("git cat-file: read trailing newline: %w", err)
		}

		var isText bool
		if content, isText = textContent(content); !isText {
			continue
		}

		// Git blob hash IS the BlobID — both use SHA-1("blob {len}\0{content}").
		var blobID types.BlobID
		copy(blobID[:], blob.hash[:])

		if err := callback(content, blobID, blobProvenance(blob, idx, id)); err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			return err
		}
	}

	_ = stdin.Close()

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("git cat-file: %w", err)
	}

	return nil
}

// blobProvenance builds the provenance for one blob. Locations is every
// (path, earliest commit) the index recorded, sorted by path; the first is
// the primary location. A blob the index does not know keeps its rev-list
// path with no commit. LocationsTruncated is set when the index dropped a
// location of this blob at its size limit (R1), whether or not it kept any.
func blobProvenance(blob blobEntry, idx *blobIndex, id repoIdentity) types.GitProvenance {
	locs := idx.lookup(blob.hash)
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
