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

// collectCommitMetadataForRepo runs git log to build a map of file path → commit metadata.
// When firstAdded is true, uses --diff-filter=A to find the commit that first added each path.
// When false, finds the most recent commit that touched each path.
func collectCommitMetadataForRepo(ctx context.Context, repoPath string, firstAdded bool) (map[string]*types.CommitMetadata, error) {
	args := []string{"log", "--all",
		"--format=%H%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%s", "--name-only"}
	if firstAdded {
		args = append(args, "--diff-filter=A")
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

	if err := cmd.Wait(); err != nil {
		return result, fmt.Errorf("git log: wait: %w", err)
	}

	return result, nil
}
