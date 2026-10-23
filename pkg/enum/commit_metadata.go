package enum

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// maxGitLogLineSize bounds how long a single git log line may be while still
// being read into the commit map. A commit subject or author name is repo
// data and can be arbitrarily long, so no fixed cap is "correct"; a line past
// this size stops the scan early (with an error) instead of wedging the git
// child against a pipe that nobody drains.
const maxGitLogLineSize = 1 << 20 // 1 MiB

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
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), maxGitLogLineSize)

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

	if err := scanner.Err(); err != nil {
		// The scan stopped before EOF (a line longer than maxGitLogLineSize).
		// Drain the rest of stdout so git is never blocked on a full pipe and
		// can exit, and keep the metadata gathered so far.
		_, _ = io.Copy(io.Discard, stdout)
		_ = cmd.Wait()
		return result, fmt.Errorf("git log: scan: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return result, fmt.Errorf("git log: wait: %w", err)
	}

	return result, nil
}
