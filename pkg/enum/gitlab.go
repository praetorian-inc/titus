package enum

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

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
	warn   io.Writer // enumeration warnings; nil means os.Stderr
}

// NewGitLabEnumerator creates a new GitLab enumerator.
func NewGitLabEnumerator(cfg GitLabConfig) (*GitLabEnumerator, error) {
	if cfg.Project == "" && cfg.Group == "" && cfg.User == "" {
		return nil, fmt.Errorf("must specify project, group, or user")
	}

	var client *gitlab.Client
	var err error

	if cfg.BaseURL != "" {
		if _, err := ValidateBaseURL(cfg.BaseURL); err != nil {
			return nil, fmt.Errorf("GitLab URL: %w", err)
		}
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
		project, resp, err := e.client.Projects.GetProject(e.config.Project, nil, gitlab.WithContext(ctx))
		if err != nil {
			return nil, apiError(ctx, "getting project", gitlabHTTP(resp))
		}
		return []*gitlab.Project{project}, nil
	}

	// List group projects
	if e.config.Group != "" {
		opts := &gitlab.ListGroupProjectsOptions{
			IncludeSubGroups: gitlab.Ptr(true),
			ListOptions:      gitlab.ListOptions{PerPage: 100},
		}
		var allProjects []*gitlab.Project
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			projects, resp, err := e.client.Groups.ListGroupProjects(e.config.Group, opts, gitlab.WithContext(ctx))
			if err != nil {
				return nil, apiError(ctx, "listing group projects", gitlabHTTP(resp))
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
			projects, resp, err := e.client.Projects.ListUserProjects(e.config.User, opts, gitlab.WithContext(ctx))
			if err != nil {
				return nil, apiError(ctx, "listing user projects", gitlabHTTP(resp))
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

		nodes, resp, err := e.client.Repositories.ListTree(project.ID, opts, gitlab.WithContext(ctx))
		if err != nil {
			return apiError(ctx, "listing tree", gitlabHTTP(resp))
		}
		allNodes = append(allNodes, nodes...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	// Group paths by blob so each blob is fetched once and reported once,
	// with every path it appears at.
	var blobs blobPaths
	for _, node := range allNodes {
		if node.Type != "blob" {
			continue
		}
		blobs.add(node.ID, node.Path)
	}

	host, id := apiRepoIdentity(e.config.BaseURL, "gitlab.com", project.PathWithNamespace)
	for paths := range blobs.all() {
		if err := ctx.Err(); err != nil {
			return err
		}

		content, ok, err := e.fetchBlob(ctx, project.ID, id, paths)
		if err != nil {
			return err
		}
		// The tree listing carries no sizes, so the limit applies to the
		// fetched content; only one blob is held at a time.
		if !ok || overSizeLimit(len(content), e.config.MaxFileSize) {
			continue
		}

		// Skip binary files
		var isText bool
		if content, isText = textContent(content); !isText {
			continue
		}

		if err := callback(content, types.ComputeBlobID(content), apiProvenance(host, id, paths)); err != nil {
			return err
		}
	}

	return nil
}

// fetchBlob returns the content at the first of paths that can be read. When
// none can, or the content is over the size limit, it warns (id names the
// project) and returns ok=false. err is non-nil only when ctx is done.
func (e *GitLabEnumerator) fetchBlob(ctx context.Context, projectID int64, id string, paths []string) (content []byte, ok bool, err error) {
	var reason string
	for _, p := range paths {
		content, resp, err := e.getRawFile(ctx, projectID, p)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, false, ctxErr
		}
		if err == nil {
			return content, true, nil
		}
		if errors.Is(err, errOverSizeLimit) {
			// Every path holds the same blob; the others are no smaller.
			reason = errOverSizeLimit.Error()
			break
		}
		if r := gitlabHTTP(resp); r != nil && r.StatusCode >= 200 && r.StatusCode < 300 {
			// The status was fine and the body read failed; the error
			// itself may quote the request URL.
			reason = "read failed"
			continue
		}
		reason = httpFailure(gitlabHTTP(resp))
	}
	warnBlobSkipped(e.warn, id, paths, reason)
	return nil, false, nil
}

// getRawFile downloads one file. Unlike RepositoryFiles.GetRawFile, which
// reads the whole body into memory, it reads at most the size limit plus
// one byte (see cappedBuffer).
func (e *GitLabEnumerator) getRawFile(ctx context.Context, projectID int64, path string) ([]byte, *gitlab.Response, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	u := fmt.Sprintf("projects/%d/repository/files/%s/raw", projectID, gitlab.PathEscape(path))
	req, err := e.client.NewRequest(http.MethodGet, u, &gitlab.GetRawFileOptions{}, []gitlab.RequestOptionFunc{gitlab.WithContext(ctx)})
	if err != nil {
		return nil, nil, err
	}
	buf := &cappedBuffer{limit: e.config.MaxFileSize, stop: cancel}
	resp, err := e.client.Do(req, buf)
	if err != nil {
		return nil, resp, err
	}
	return buf.buf.Bytes(), resp, nil
}

// gitlabHTTP returns the HTTP response of a GitLab client call, or nil.
func gitlabHTTP(resp *gitlab.Response) *http.Response {
	if resp == nil {
		return nil
	}
	return resp.Response
}
