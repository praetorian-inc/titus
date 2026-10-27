package enum

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-github/v57/github"
	"golang.org/x/oauth2"

	"github.com/praetorian-inc/titus/pkg/types"
)

// GitHubConfig configures GitHub API enumeration.
type GitHubConfig struct {
	Token     string // GitHub API token (optional; unauthenticated if empty)
	BaseURL   string // GitHub Enterprise base URL (optional; defaults to github.com)
	Owner     string // Repository owner (for single repo)
	Repo      string // Repository name (for single repo)
	Org       string // Organization name (list all org repos)
	User      string // User name (list all user repos)
	SkipForks bool   // Skip forked repositories when scanning orgs/users
	Config           // Embedded base config
}

// GitHubEnumerator enumerates blobs from GitHub via API.
type GitHubEnumerator struct {
	client *github.Client
	config GitHubConfig
	warn   io.Writer // enumeration warnings; nil means os.Stderr
}

// NewGitHubEnumerator creates a new GitHub API enumerator.
func NewGitHubEnumerator(cfg GitHubConfig) (*GitHubEnumerator, error) {
	var client *github.Client

	if cfg.Token != "" {
		// Authenticated client
		ctx := context.Background()
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.Token})
		tc := oauth2.NewClient(ctx, ts)
		client = github.NewClient(tc)
	} else {
		// Unauthenticated client (60 req/hour, public repos only)
		client = github.NewClient(nil)
	}

	// Configure custom base URL for GitHub Enterprise
	if cfg.BaseURL != "" {
		if _, err := ValidateBaseURL(cfg.BaseURL); err != nil {
			return nil, fmt.Errorf("GitHub Enterprise URL: %w", err)
		}
		baseURL, err := url.Parse(strings.TrimSuffix(cfg.BaseURL, "/") + "/api/v3/")
		if err != nil {
			return nil, fmt.Errorf("parsing GitHub Enterprise URL: %w", withoutURL(err))
		}
		uploadURL, err := url.Parse(strings.TrimSuffix(cfg.BaseURL, "/") + "/api/uploads/")
		if err != nil {
			return nil, fmt.Errorf("parsing GitHub Enterprise upload URL: %w", withoutURL(err))
		}
		client.BaseURL = baseURL
		client.UploadURL = uploadURL
	}

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
		if e.config.SkipForks && repo.GetFork() {
			continue
		}
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

		repo, resp, err := e.client.Repositories.Get(ctx, e.config.Owner, e.config.Repo)
		if err != nil {
			return nil, apiError(ctx, "getting repository", githubHTTP(resp))
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
			return nil, apiError(ctx, "listing org repositories", githubHTTP(resp))
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
	var allRepos []*github.Repository
	if e.config.User != "" {
		opts := &github.RepositoryListByUserOptions{
			ListOptions: github.ListOptions{PerPage: 100},
		}
		for {
			repos, resp, err := e.client.Repositories.ListByUser(ctx, e.config.User, opts)
			if err != nil {
				return nil, apiError(ctx, "listing user repositories", githubHTTP(resp))
			}
			allRepos = append(allRepos, repos...)
			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
	} else {
		opts := &github.RepositoryListByAuthenticatedUserOptions{
			ListOptions: github.ListOptions{PerPage: 100},
		}
		for {
			repos, resp, err := e.client.Repositories.ListByAuthenticatedUser(ctx, opts)
			if err != nil {
				return nil, apiError(ctx, "listing user repositories", githubHTTP(resp))
			}
			allRepos = append(allRepos, repos...)
			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
	}
	return allRepos, nil
}

// ListRepoURLs returns clone URLs for repos matching the configuration.
func (e *GitHubEnumerator) ListRepoURLs(ctx context.Context) ([]RepoInfo, error) {
	repos, err := e.listRepos(ctx)
	if err != nil {
		return nil, err
	}

	var urls []RepoInfo
	for _, repo := range repos {
		if e.config.SkipForks && repo.GetFork() {
			continue
		}
		urls = append(urls, RepoInfo{
			Name:          repo.GetFullName(),
			CloneURL:      repo.GetCloneURL(),
			DefaultBranch: repo.GetDefaultBranch(),
		})
	}
	return urls, nil
}

// enumerateRepo enumerates all files in a repository.
func (e *GitHubEnumerator) enumerateRepo(ctx context.Context, repo *github.Repository, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// Get default branch
	branch := repo.GetDefaultBranch()
	if branch == "" {
		branch = "main" // Fallback to main if no default set
	}

	// Get repository tree recursively
	tree, resp, err := e.client.Git.GetTree(ctx, repo.GetOwner().GetLogin(), repo.GetName(), branch, true)
	if err != nil {
		return apiError(ctx, "getting tree", githubHTTP(resp))
	}

	// Warn if tree is truncated (>100K files) - secrets beyond limit will be missed
	if tree.GetTruncated() {
		return fmt.Errorf("repository tree for %s is truncated (>100K files); clone locally and use 'titus scan' for complete coverage", repo.GetFullName())
	}

	// Group paths by blob so each blob is fetched once and reported once,
	// with every path it appears at.
	var blobs blobPaths
	for _, entry := range tree.Entries {
		// Skip non-blob entries (trees/submodules)
		if entry.GetType() != "blob" {
			continue
		}
		// Apply size limit before fetching; re-checked on the content.
		if overSizeLimit(entry.GetSize(), e.config.MaxFileSize) {
			continue
		}
		blobs.add(entry.GetSHA(), entry.GetPath())
	}

	id := apiRepoIdentity(e.config.BaseURL, "github.com", repo.GetFullName())
	src := githubBlobSource{owner: repo.GetOwner().GetLogin(), name: repo.GetName(), ref: branch, id: id}
	for paths := range blobs.all() {
		if err := ctx.Err(); err != nil {
			return err
		}

		data, ok, err := e.fetchBlob(ctx, src, paths)
		if err != nil {
			return err
		}
		if !ok || overSizeLimit(len(data), e.config.MaxFileSize) {
			continue
		}

		// Skip binary files
		var isText bool
		if data, isText = textContent(data); !isText {
			continue
		}

		// Commit metadata is not available from the tree API.
		if err := callback(data, types.ComputeBlobID(data), apiProvenance(id, paths)); err != nil {
			return err
		}
	}

	return nil
}

// githubBlobSource is where enumerateRepo fetches blob content from.
type githubBlobSource struct {
	owner, name, ref string
	id               string // repository identity, for warnings
}

// fetchBlob returns the content at the first of paths that can be read. When
// none can (permissions, files over the contents API's 1 MB inline limit,
// etc.) it warns and returns ok=false. err is non-nil only when ctx is done.
func (e *GitHubEnumerator) fetchBlob(ctx context.Context, src githubBlobSource, paths []string) (data []byte, ok bool, err error) {
	var reason string
	for _, p := range paths {
		file, _, resp, err := e.client.Repositories.GetContents(ctx, src.owner, src.name, p, &github.RepositoryContentGetOptions{Ref: src.ref})
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, false, ctxErr
		}
		if err != nil {
			reason = httpFailure(githubHTTP(resp))
			continue
		}
		// A symlink or submodule entry decodes to "", nil below; reporting
		// it would put a phantom empty blob at its paths.
		if file == nil || file.GetType() != "file" {
			reason = "not a file"
			continue
		}
		// GetContent decodes base64 (newlines included) and rejects the
		// "none" encoding the API uses when it omits content.
		s, err := file.GetContent()
		if err != nil {
			reason = fmt.Sprintf("content not returned (encoding %q)", file.GetEncoding())
			continue
		}
		return []byte(s), true, nil
	}
	warnBlobSkipped(e.warn, src.id, paths, reason)
	return nil, false, nil
}

// githubHTTP returns the HTTP response of a go-github call, or nil.
func githubHTTP(resp *github.Response) *http.Response {
	if resp == nil {
		return nil
	}
	return resp.Response
}
