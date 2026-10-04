package enum

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// collectBlobCommitMap runs git log --all --reverse --raw to build a map of
// blob hash (hex) → the first commit that introduced that blob. Because
// --reverse outputs oldest-first and we record only the first occurrence per
// hash, every blob maps to the commit where it first appeared in the repo.
//
// This replaces the path-based collectCommitMetadataForRepo approach for the
// native history enumerator: path-based attribution breaks when a secret is
// introduced via a modification to an existing file (--diff-filter=A only
// captures file-creation commits, not modification commits).
func collectBlobCommitMap(ctx context.Context, repoPath string) (map[string]*types.CommitMetadata, error) {
	args := []string{"log", "--all", "--reverse",
		"--format=%H%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%s",
		"--raw", "--no-abbrev"}

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = repoPath

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git log: pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git log: start: %w", err)
	}

	result := make(map[string]*types.CommitMetadata)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	var current *types.CommitMetadata
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Commit header: 8 null-separated fields.
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

		// Raw diff line: ":old_mode new_mode old_hash new_hash status\tpath"
		if current != nil && len(line) > 0 && line[0] == ':' {
			newHash := parseRawDiffNewHash(line)
			if newHash == "" {
				continue
			}
			if _, exists := result[newHash]; !exists {
				result[newHash] = current
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("git log: scan: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return result, fmt.Errorf("git log: wait: %w", err)
	}

	return result, nil
}

const zeroHash = "0000000000000000000000000000000000000000"

// parseRawDiffNewHash extracts the new blob hash from a git raw diff line.
// Format: ":old_mode new_mode old_hash new_hash status\tpath"
// Returns "" if the line is malformed or the new hash is the zero hash (deletion).
func parseRawDiffNewHash(line string) string {
	// Skip the leading colon and split on whitespace.
	// Fields: [":old_mode", "new_mode", "old_hash", "new_hash", "status\tpath"]
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return ""
	}
	newHash := fields[3]
	if len(newHash) != 40 || newHash == zeroHash {
		return ""
	}
	return newHash
}
