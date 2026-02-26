package enum

import (
	"context"
	"fmt"

	"gitlab.com/gitlab-org/api/client-go"

	"github.com/praetorian-inc/titus/pkg/types"
)

// GitLabConfig for GitLab API enumeration.
type GitLabConfig struct {
	Token   string
	BaseURL string // Optional, defaults to gitlab.com
	Project string // Single project path (namespace/project)
	Group   string // Group name (optional)
	User    string // User name (optional)
	Config         // Embedded base Config
}

// GitLabEnumerator enumerates blobs from GitLab projects via API.
type GitLabEnumerator struct {
	client *gitlab.Client
	config GitLabConfig
}

// NewGitLabEnumerator creates a new GitLab enumerator.
func NewGitLabEnumerator(cfg GitLabConfig) (*GitLabEnumerator, error) {
	if cfg.Project == "" && cfg.Group == "" && cfg.User == "" {
		return nil, fmt.Errorf("must specify project, group, or user")
	}

	var client *gitlab.Client
	var err error

	if cfg.BaseURL != "" {
		client, err = gitlab.NewClient(cfg.Token, gitlab.WithBaseURL(cfg.BaseURL))
	} else {
		client, err = gitlab.NewClient(cfg.Token)
	}
	if err != nil {
		return nil, fmt.Errorf("creating GitLab client: %w", err)
	}

	return &GitLabEnumerator{client: client, config: cfg}, nil
}

// Enumerate walks GitLab projects and yields unique blobs.
func (e *GitLabEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	projects, err := e.listProjects(ctx)
	if err != nil {
		return err
	}

	for _, project := range projects {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := e.enumerateProject(ctx, project, callback); err != nil {
			return err
		}
	}
	return nil
}

// listProjects returns the list of projects to enumerate.
func (e *GitLabEnumerator) listProjects(ctx context.Context) ([]*gitlab.Project, error) {
	// If single project specified
	if e.config.Project != "" {
		project, _, err := e.client.Projects.GetProject(e.config.Project, nil)
		if err != nil {
			return nil, fmt.Errorf("getting project: %w", err)
		}
		return []*gitlab.Project{project}, nil
	}

	// List group projects
	if e.config.Group != "" {
		opts := &gitlab.ListGroupProjectsOptions{
			ListOptions: gitlab.ListOptions{PerPage: 100},
		}
		var allProjects []*gitlab.Project
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			projects, resp, err := e.client.Groups.ListGroupProjects(e.config.Group, opts)
			if err != nil {
				return nil, fmt.Errorf("listing group projects: %w", err)
			}
			allProjects = append(allProjects, projects...)
			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
		return allProjects, nil
	}

	// List user projects
	if e.config.User != "" {
		opts := &gitlab.ListProjectsOptions{
			ListOptions: gitlab.ListOptions{PerPage: 100},
			Owned:       gitlab.Ptr(true),
		}
		var allProjects []*gitlab.Project
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			projects, resp, err := e.client.Projects.ListUserProjects(e.config.User, opts)
			if err != nil {
				return nil, fmt.Errorf("listing user projects: %w", err)
			}
			allProjects = append(allProjects, projects...)
			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
		return allProjects, nil
	}

	return nil, fmt.Errorf("must specify project, group, or user")
}

// ListProjectURLs returns clone URLs for projects matching the configuration.
func (e *GitLabEnumerator) ListProjectURLs(ctx context.Context) ([]RepoInfo, error) {
	projects, err := e.listProjects(ctx)
	if err != nil {
		return nil, err
	}

	var urls []RepoInfo
	for _, p := range projects {
		urls = append(urls, RepoInfo{
			Name:          p.PathWithNamespace,
			CloneURL:      p.HTTPURLToRepo,
			DefaultBranch: p.DefaultBranch,
		})
	}
	return urls, nil
}

// enumerateProject walks a single project's file tree.
func (e *GitLabEnumerator) enumerateProject(ctx context.Context, project *gitlab.Project, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// Get repository tree recursively
	opts := &gitlab.ListTreeOptions{
		Recursive:   gitlab.Ptr(true),
		ListOptions: gitlab.ListOptions{PerPage: 100},
	}

	var allNodes []*gitlab.TreeNode
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		nodes, resp, err := e.client.Repositories.ListTree(project.ID, opts)
		if err != nil {
			return fmt.Errorf("listing tree: %w", err)
		}
		allNodes = append(allNodes, nodes...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	// Process each file node
	for _, node := range allNodes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if node.Type != "blob" {
			continue
		}

		// Get file content
		content, _, err := e.client.RepositoryFiles.GetRawFile(project.ID, node.Path, &gitlab.GetRawFileOptions{})
		if err != nil {
			// Skip files we can't read
			continue
		}

		// Skip files over max size
		if e.config.MaxFileSize > 0 && int64(len(content)) > e.config.MaxFileSize {
			continue
		}

		// Skip binary files
		if isBinary(content) {
			continue
		}

		// Create blob ID from content hash
		blobID := types.ComputeBlobID(content)

		// Create provenance
		prov := types.GitProvenance{
			RepoPath: project.PathWithNamespace,
			BlobPath: node.Path,
		}

		if err := callback(content, blobID, prov); err != nil {
			return err
		}
	}

	return nil
}
