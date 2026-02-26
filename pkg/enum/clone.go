package enum

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/praetorian-inc/titus/pkg/types"
)

// RepoInfo holds basic repository information for clone-based scanning.
type RepoInfo struct {
	Name          string // Full name (e.g., "kubernetes/kubernetes")
	CloneURL      string // HTTPS clone URL
	DefaultBranch string
}

// CloneEnumerator clones repositories and scans them.
// By default it does a full clone and filesystem scan.
// Set Git=true to do a full clone with git history scanning.
type CloneEnumerator struct {
	repos  []RepoInfo
	config Config
	Git    bool // false = full clone + filesystem scan, true = full clone + git history (thorough)
	Depth  int  // override clone depth (0 = automatic: full clone for filesystem mode, unlimited for git mode)
}

// NewCloneEnumerator creates a new clone-based enumerator.
func NewCloneEnumerator(repos []RepoInfo, config Config) *CloneEnumerator {
	return &CloneEnumerator{repos: repos, config: config}
}

// Enumerate clones each repository, scans it, and cleans up.
func (e *CloneEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	for _, repo := range e.repos {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := e.cloneAndScan(ctx, repo, callback); err != nil {
			// Log error and continue to next repo
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", repo.Name, err)
			continue
		}
	}
	return nil
}

func (e *CloneEnumerator) cloneAndScan(ctx context.Context, repo RepoInfo, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	tmpDir, err := os.MkdirTemp("", "titus-clone-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	clonePath := filepath.Join(tmpDir, "repo")

	// Determine effective clone depth
	depth := e.Depth

	// Build clone args
	cloneArgs := []string{"-c", "http.postBuffer=524288000", "clone", "--quiet"}
	if e.Git && depth == 0 {
		// Full history: bare clone for efficiency (no working tree needed)
		cloneArgs = append(cloneArgs, "--bare")
	}
	if depth > 0 {
		cloneArgs = append(cloneArgs, "--depth", strconv.Itoa(depth))
	}
	cloneArgs = append(cloneArgs, repo.CloneURL, clonePath)

	fmt.Fprintf(os.Stderr, "Cloning %s...\n", repo.Name)
	cmd := exec.CommandContext(ctx, "git", cloneArgs...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cloning %s: %w", repo.Name, err)
	}

	cloneConfig := e.config
	cloneConfig.Root = clonePath

	if e.Git {
		// Git history mode: walk all commits
		gitEnum := NewGitEnumerator(cloneConfig)
		if depth == 0 {
			gitEnum.WalkAll = true
		}
		return gitEnum.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			if gp, ok := prov.(types.GitProvenance); ok {
				gp.RepoPath = repo.Name
				return callback(content, blobID, gp)
			}
			return callback(content, blobID, prov)
		})
	}

	// Filesystem mode (default): fast scan of working tree
	return NewFilesystemEnumerator(cloneConfig).Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		// Rewrite file provenance to include repo name
		if fp, ok := prov.(types.FileProvenance); ok {
			// Convert absolute temp path to repo-relative path
			relPath, err := filepath.Rel(clonePath, fp.FilePath)
			if err != nil {
				relPath = fp.FilePath
			}
			return callback(content, blobID, types.GitProvenance{
				RepoPath: repo.Name,
				BlobPath: relPath,
			})
		}
		return callback(content, blobID, prov)
	})
}
