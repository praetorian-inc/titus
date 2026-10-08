package enum

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
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

// blobIntroduction is the earliest commit that added a blob, and the path
// the blob had in that commit. Same blob at a later path keeps the first one.
type blobIntroduction struct {
	Commit *types.CommitMetadata
	Path   string
}

// collectBlobIntroductions maps a full blob hash to the commit that introduced
// it. git log is newest-first; --reverse --topo-order walks root-to-tip, which
// is the practical form of Nosey Parker's first-sighting rule. The first time
// a blob hash appears wins. Merge commits are not diffed, so a blob that
// exists only as an evil-merge result stays unmapped.
func collectBlobIntroductions(ctx context.Context, repoPath string) (map[string]*blobIntroduction, error) {
	args := []string{
		"log", "--reverse", "--topo-order", "--all", "--source",
		"--raw", "--abbrev=40", "--diff-filter=AMRC",
		"--format=%x01%H%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%s%x00%S",
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

	result := make(map[string]*blobIntroduction)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var current *types.CommitMetadata
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if meta, ok := parseIntroCommit(line); ok {
			current = meta
			continue
		}
		if current == nil || !strings.HasPrefix(line, ":") {
			continue
		}
		hash, path, ok := parseRawDestination(line)
		if !ok {
			continue
		}
		if _, exists := result[hash]; exists {
			continue
		}
		result[hash] = &blobIntroduction{Commit: current, Path: path}
	}
	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return nil, fmt.Errorf("git log: scan: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("git log: wait: %w", err)
	}
	return result, nil
}

func parseIntroCommit(line string) (*types.CommitMetadata, bool) {
	if !strings.HasPrefix(line, "\x01") {
		return nil, false
	}
	parts := strings.Split(line[1:], "\x00")
	if len(parts) != 9 || len(parts[0]) != 40 {
		return nil, false
	}
	authorTS, _ := time.Parse(time.RFC3339, parts[3])
	committerTS, _ := time.Parse(time.RFC3339, parts[6])
	return &types.CommitMetadata{
		CommitID:           parts[0],
		AuthorName:         parts[1],
		AuthorEmail:        parts[2],
		AuthorTimestamp:    authorTS,
		CommitterName:      parts[4],
		CommitterEmail:     parts[5],
		CommitterTimestamp: committerTS,
		Message:            parts[7],
		Branch:             displayRef(parts[8]),
	}, true
}

func parseRawDestination(line string) (hash, path string, ok bool) {
	meta, paths, found := strings.Cut(line, "\t")
	if !found {
		return "", "", false
	}
	fields := strings.Fields(meta)
	if len(fields) < 5 {
		return "", "", false
	}
	hash = fields[3]
	if !fullBlobHash(hash) {
		return "", "", false
	}
	if i := strings.LastIndex(paths, "\t"); i >= 0 {
		paths = paths[i+1:]
	}
	return hash, unquoteGitPath(paths), true
}

func fullBlobHash(s string) bool {
	if len(s) != 40 {
		return false
	}
	nonzero := false
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			if c != '0' {
				nonzero = true
			}
		default:
			return false
		}
	}
	return nonzero
}

func unquoteGitPath(path string) string {
	if len(path) < 2 || path[0] != '"' {
		return path
	}
	s, err := strconv.Unquote(path)
	if err != nil {
		return path
	}
	return s
}

func displayRef(ref string) string {
	switch {
	case strings.HasPrefix(ref, "refs/heads/"):
		return strings.TrimPrefix(ref, "refs/heads/")
	case strings.HasPrefix(ref, "refs/remotes/"):
		rest := strings.TrimPrefix(ref, "refs/remotes/")
		if _, after, ok := strings.Cut(rest, "/"); ok {
			return after
		}
	case strings.HasPrefix(ref, "refs/tags/"):
		return strings.TrimPrefix(ref, "refs/tags/")
	}
	if ref == "HEAD" {
		return ""
	}
	return ref
}
