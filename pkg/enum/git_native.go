package enum

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

// blobEntry holds a deduplicated blob hash and its first-seen path.
type blobEntry struct {
	hash [20]byte
	path string
}

// gitBinaryAvailable returns true if the git binary is on PATH.
func gitBinaryAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// enumerateAllHistoryNative uses native git commands for fast history enumeration.
// Phase 1: git rev-list --all --objects → collect unique blob hashes with paths.
// Phase 2: git log → collect commit metadata keyed by file path.
// Phase 3: git cat-file --batch → stream content, filter, and invoke callback.
func (e *GitEnumerator) enumerateAllHistoryNative(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	blobs, err := e.collectBlobEntries(ctx)
	if err != nil {
		return err
	}

	commitMap, _ := e.collectCommitMetadata(ctx) // best-effort; nil map is safe

	return e.streamBlobContentsWithMeta(ctx, blobs, commitMap, callback)
}

// collectBlobEntries runs git rev-list --all --objects and returns deduplicated blob entries.
func (e *GitEnumerator) collectBlobEntries(ctx context.Context) ([]blobEntry, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-list", "--all", "--objects")
	cmd.Dir = e.config.Root

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git rev-list: pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git rev-list: start: %w", err)
	}

	seen := make(map[[20]byte]bool)
	var blobs []blobEntry

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()

		// Lines with a space at position 40 have a path: "<40-hex> <path>"
		// Lines without are commits or root trees — skip them.
		spaceIdx := strings.IndexByte(line, ' ')
		if spaceIdx != 40 {
			continue
		}

		hexStr := line[:40]
		path := line[41:]

		var hash [20]byte
		decoded, err := hex.DecodeString(hexStr)
		if err != nil {
			continue
		}
		copy(hash[:], decoded)

		if seen[hash] {
			continue
		}
		seen[hash] = true

		blobs = append(blobs, blobEntry{hash: hash, path: path})
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return nil, fmt.Errorf("git rev-list: scan: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("git rev-list: %w", err)
	}

	return blobs, nil
}

// collectCommitMetadata runs git log to build a map of file path → first commit metadata.
func (e *GitEnumerator) collectCommitMetadata(ctx context.Context) (map[string]*types.CommitMetadata, error) {
	return collectCommitMetadataForRepo(ctx, e.config.Root, true)
}

// streamBlobContentsWithMeta feeds hashes to git cat-file --batch and invokes callback for text blobs.
// If commitMap is non-nil, attaches commit metadata to git provenance records.
func (e *GitEnumerator) streamBlobContentsWithMeta(ctx context.Context, blobs []blobEntry, commitMap map[string]*types.CommitMetadata, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
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

		if isBinary(content) {
			continue
		}

		// Git blob hash IS the BlobID — both use SHA-1("blob {len}\0{content}").
		var blobID types.BlobID
		copy(blobID[:], blob.hash[:])

		prov := types.GitProvenance{
			RepoPath: e.config.Root,
			Commit:   commitMap[blob.path],
			BlobPath: blob.path,
		}

		if err := callback(content, blobID, prov); err != nil {
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
