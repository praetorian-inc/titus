package enum

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/go-github/v57/github"
	"golang.org/x/oauth2"

	"github.com/praetorian-inc/titus/pkg/types"
)

// GitHubConfig configures GitHub API enumeration.
type GitHubConfig struct {
	Token  string // GitHub API token (required)
	Owner  string // Repository owner (for single repo)
	Repo   string // Repository name (for single repo)
	Org    string // Organization name (list all org repos)
	User   string // User name (list all user repos)
	Config        // Embedded base config
}

// GitHubEnumerator enumerates blobs from GitHub via API.
type GitHubEnumerator struct {
	client *github.Client
	config GitHubConfig
}

// NewGitHubEnumerator creates a new GitHub API enumerator.
func NewGitHubEnumerator(cfg GitHubConfig) (*GitHubEnumerator, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("GitHub token is required")
	}

	// Create authenticated GitHub client
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.Token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	return &GitHubEnumerator{
		client: client,
		config: cfg,
	}, nil
}

// Enumerate yields blobs from GitHub repositories.
func (e *GitHubEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	repos, err := e.listRepos(ctx)
	if err != nil {
		return err
	}

	// Enumerate each repository
	for _, repo := range repos {
		if err := e.enumerateRepo(ctx, repo, callback); err != nil {
			return fmt.Errorf("enumerating %s: %w", repo.GetFullName(), err)
		}
	}

	return nil
}

// listRepos returns the list of repositories to enumerate.
func (e *GitHubEnumerator) listRepos(ctx context.Context) ([]*github.Repository, error) {
	// Single repository
	if e.config.Repo != "" {
		if e.config.Owner == "" {
			return nil, fmt.Errorf("owner required when repo specified")
		}

		repo, _, err := e.client.Repositories.Get(ctx, e.config.Owner, e.config.Repo)
		if err != nil {
			return nil, fmt.Errorf("getting repository: %w", err)
		}
		return []*github.Repository{repo}, nil
	}

	// Organization repositories
	if e.config.Org != "" {
		return e.listOrgRepos(ctx)
	}

	// User repositories
	if e.config.User != "" {
		return e.listUserRepos(ctx)
	}

	return nil, fmt.Errorf("must specify repo (with owner), org, or user")
}

// listOrgRepos lists all repositories for an organization.
func (e *GitHubEnumerator) listOrgRepos(ctx context.Context) ([]*github.Repository, error) {
	opts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	var allRepos []*github.Repository
	for {
		repos, resp, err := e.client.Repositories.ListByOrg(ctx, e.config.Org, opts)
		if err != nil {
			return nil, fmt.Errorf("listing org repositories: %w", err)
		}

		allRepos = append(allRepos, repos...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}

// listUserRepos lists all repositories for a user.
func (e *GitHubEnumerator) listUserRepos(ctx context.Context) ([]*github.Repository, error) {
	opts := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	var allRepos []*github.Repository
	for {
		repos, resp, err := e.client.Repositories.List(ctx, e.config.User, opts)
		if err != nil {
			return nil, fmt.Errorf("listing user repositories: %w", err)
		}

		allRepos = append(allRepos, repos...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}

// enumerateRepo enumerates all files in a repository.
func (e *GitHubEnumerator) enumerateRepo(ctx context.Context, repo *github.Repository, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// Get default branch
	branch := repo.GetDefaultBranch()
	if branch == "" {
		branch = "main" // Fallback to main if no default set
	}

	// Get repository tree recursively
	tree, _, err := e.client.Git.GetTree(ctx, repo.GetOwner().GetLogin(), repo.GetName(), branch, true)
	if err != nil {
		return fmt.Errorf("getting tree: %w", err)
	}

	// Warn if tree is truncated (>100K files) - secrets beyond limit will be missed
	if tree.GetTruncated() {
		return fmt.Errorf("repository tree for %s is truncated (>100K files); clone locally and use 'titus scan' for complete coverage", repo.GetFullName())
	}

	// Process each entry in the tree
	for _, entry := range tree.Entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip non-blob entries (trees/submodules)
		if entry.GetType() != "blob" {
			continue
		}

		// Apply size limit
		if e.config.MaxFileSize > 0 && int64(entry.GetSize()) > e.config.MaxFileSize {
			continue
		}

		// Get file content
		content, _, _, err := e.client.Repositories.GetContents(ctx, repo.GetOwner().GetLogin(), repo.GetName(), entry.GetPath(), nil)
		if err != nil {
			// Skip files we can't read (permissions, large files, etc.)
			continue
		}

		if content == nil || content.Content == nil {
			continue
		}

		// Decode base64 content
		data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(*content.Content, "\n", ""))
		if err != nil {
			continue
		}

		// Skip binary files
		if isBinary(data) {
			continue
		}

		// Compute blob ID
		blobID := types.ComputeBlobID(data)

		// Create Git provenance (GitHub is git-based)
		prov := types.GitProvenance{
			RepoPath: repo.GetFullName(),
			BlobPath: entry.GetPath(),
			// Commit metadata not available from tree API
			Commit: nil,
		}

		// Yield to callback
		if err := callback(data, blobID, prov); err != nil {
			return err
		}
	}

	return nil
}
