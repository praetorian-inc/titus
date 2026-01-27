package enum

import (
	"context"
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/praetorian-inc/titus/pkg/types"
)

// GitEnumerator enumerates blobs from a git repository.
type GitEnumerator struct {
	config Config
	// CommitRef optionally specifies a specific commit to enumerate (defaults to HEAD)
	CommitRef string
}

// NewGitEnumerator creates a new git enumerator.
func NewGitEnumerator(config Config) *GitEnumerator {
	return &GitEnumerator{
		config:    config,
		CommitRef: "HEAD",
	}
}

// Enumerate walks git history and yields unique blobs.
func (e *GitEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// Open repository
	repo, err := git.PlainOpen(e.config.Root)
	if err != nil {
		return fmt.Errorf("failed to open git repository: %w", err)
	}

	// Resolve commit reference
	ref, err := repo.ResolveRevision(plumbing.Revision(e.CommitRef))
	if err != nil {
		return fmt.Errorf("failed to resolve ref %s: %w", e.CommitRef, err)
	}

	// Get the commit
	commit, err := repo.CommitObject(*ref)
	if err != nil {
		return fmt.Errorf("failed to get commit: %w", err)
	}

	// Get commit tree
	tree, err := commit.Tree()
	if err != nil {
		return fmt.Errorf("failed to get tree: %w", err)
	}

	// Track seen blobs to avoid duplicates
	seen := make(map[plumbing.Hash]bool)

	// Walk the tree
	err = tree.Files().ForEach(func(f *object.File) error {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip if already seen
		if seen[f.Hash] {
			return nil
		}
		seen[f.Hash] = true

		// Apply size limit
		if e.config.MaxFileSize > 0 && f.Size > e.config.MaxFileSize {
			return nil
		}

		// Get file content
		content, err := f.Contents()
		if err != nil {
			return fmt.Errorf("failed to get contents of %s: %w", f.Name, err)
		}

		// Skip binary files
		if isBinary([]byte(content)) {
			return nil
		}

		// Compute blob ID
		blobID := types.ComputeBlobID([]byte(content))

		// Create git provenance with commit metadata
		commitMeta := &types.CommitMetadata{
			CommitID:           commit.Hash.String(),
			AuthorName:         commit.Author.Name,
			AuthorEmail:        commit.Author.Email,
			AuthorTimestamp:    commit.Author.When,
			CommitterName:      commit.Committer.Name,
			CommitterEmail:     commit.Committer.Email,
			CommitterTimestamp: commit.Committer.When,
			Message:            commit.Message,
		}

		prov := types.GitProvenance{
			RepoPath: e.config.Root,
			Commit:   commitMeta,
			BlobPath: f.Name,
		}

		// Yield to callback
		return callback([]byte(content), blobID, prov)
	})

	if err != nil {
		return fmt.Errorf("failed to walk tree: %w", err)
	}

	return nil
}
