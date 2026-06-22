package enum

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/praetorian-inc/titus/pkg/types"
)

// JiraConfig configures the Jira instance enumerator.
type JiraConfig struct {
	BaseURL           string    // Jira base URL (e.g., https://mysite.atlassian.net)
	Token             string    // API token or PAT
	Username          string    // Username for Cloud basic auth (empty = PAT/Bearer)
	RateLimit         float64   // requests per second (default 5)
	Projects          string    // comma-separated project key filter (empty = all)
	AllowInsecureHTTP bool      // allow plaintext HTTP base URLs
	Verbose           io.Writer // progress output (nil = silent)
}

// JiraEnumerator enumerates blobs from a Jira instance via the REST API.
type JiraEnumerator struct {
	config  JiraConfig
	client  *http.Client
	limiter *rate.Limiter
	apiBase string
}

// NewJiraEnumerator creates a new Jira enumerator.
func NewJiraEnumerator(cfg JiraConfig) (*JiraEnumerator, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("jira API token is required")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("jira base URL is required")
	}
	insecure, err := ValidateBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("jira base URL: %w", err)
	}
	if insecure && !cfg.AllowInsecureHTTP {
		return nil, fmt.Errorf("jira base URL uses plaintext HTTP, which exposes credentials; use HTTPS or set AllowInsecureHTTP")
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 5.0
	}

	apiBase := strings.TrimRight(cfg.BaseURL, "/") + "/rest/api/3"

	return &JiraEnumerator{
		config:  cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
		apiBase: apiBase,
	}, nil
}

// jiraProvenance builds an ExtendedProvenance for a Jira entity.
func jiraProvenance(entityType, key, summary, issueURL, project string) types.ExtendedProvenance {
	return types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source":     "jira",
			"entityType": entityType,
			"identifier": key,
			"title":      summary,
			"url":        issueURL,
			"path":       issueURL,
			"project":    project,
		},
	}
}

// logf writes a progress message when verbose output is enabled.
func (e *JiraEnumerator) logf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, format+"\n", args...)
	}
}

// progressf writes an in-place progress update using \r.
func (e *JiraEnumerator) progressf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, "\r%-80s", fmt.Sprintf(format, args...))
	}
}

var (
	jiraHTMLTagRe = regexp.MustCompile(`<[^>]*>`)
)

// jiraStripHTML removes HTML tags and unescapes HTML entities from Jira rendered content.
func jiraStripHTML(s string) string {
	stripped := jiraHTMLTagRe.ReplaceAllString(s, "")
	return html.UnescapeString(stripped)
}

// jiraComment holds author and body of a Jira comment.
type jiraComment struct {
	Author string
	Body   string
}

// jiraBuildIssueBlob assembles a Jira issue into a single blob for scanning.
func jiraBuildIssueBlob(key, summary, issueURL, project, description string, comments []jiraComment) []byte {
	var sb strings.Builder
	sb.WriteString("Key: " + key + "\n")
	sb.WriteString("Summary: " + summary + "\n")
	sb.WriteString("URL: " + issueURL + "\n")
	sb.WriteString("Project: " + project + "\n")
	sb.WriteString("---\n")
	sb.WriteString(description + "\n")
	if len(comments) > 0 {
		sb.WriteString("\n--- Comments ---\n")
		for _, c := range comments {
			sb.WriteString("\n[" + c.Author + "]:\n")
			sb.WriteString(c.Body + "\n")
		}
	}
	return []byte(sb.String())
}

// jiraSearchResponse represents the paginated response from Jira issue search.
type jiraSearchResponse struct {
	StartAt    int              `json:"startAt"`
	MaxResults int              `json:"maxResults"`
	Total      int              `json:"total"`
	Issues     []jiraIssueShort `json:"issues"`
}

// jiraIssueShort is a minimal issue representation from search results.
type jiraIssueShort struct {
	Key    string `json:"key"`
	Fields struct {
		Summary string `json:"summary"`
		Project struct {
			Key  string `json:"key"`
			Name string `json:"name"`
		} `json:"project"`
		Description json.RawMessage `json:"description"` // ADF in v3, may be null
	} `json:"fields"`
	RenderedFields struct {
		Description string `json:"description"` // HTML rendered
	} `json:"renderedFields"`
}

// jiraCommentResponse represents the paginated response from the issue comments endpoint.
type jiraCommentResponse struct {
	StartAt    int                `json:"startAt"`
	MaxResults int                `json:"maxResults"`
	Total      int                `json:"total"`
	Comments   []jiraCommentEntry `json:"comments"`
}

// jiraCommentEntry is a single comment from the Jira API.
type jiraCommentEntry struct {
	Author struct {
		DisplayName string `json:"displayName"`
	} `json:"author"`
	RenderedBody string `json:"renderedBody"`
	Body         json.RawMessage `json:"body"` // ADF in v3
}

// jiraGet performs a rate-limited GET request with auth and retry logic.
func (e *JiraEnumerator) jiraGet(ctx context.Context, reqURL string) ([]byte, error) {
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := e.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}

		// Auth: Basic (username:token) for Cloud, Bearer (PAT) for Server/DC
		if e.config.Username != "" {
			encoded := base64.StdEncoding.EncodeToString([]byte(e.config.Username + ":" + e.config.Token))
			req.Header.Set("Authorization", "Basic "+encoded)
		} else {
			req.Header.Set("Authorization", "Bearer "+e.config.Token)
		}
		req.Header.Set("Accept", "application/json")

		resp, err := e.client.Do(req)
		if err != nil {
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(2 * time.Second):
				}
				continue
			}
			return nil, fmt.Errorf("http request: %w", err)
		}

		// Retry on 429 (rate limit) or 5xx (server error)
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(2 * time.Second):
				}
				continue
			}
			return nil, fmt.Errorf("jira API returned %d after %d attempts", resp.StatusCode, maxAttempts)
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("jira API returned unexpected status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}
		return body, nil
	}
	return nil, fmt.Errorf("jiraGet: exceeded max attempts")
}

// jiraSearchIssues performs a paginated JQL search and returns all matching issues.
func (e *JiraEnumerator) jiraSearchIssues(ctx context.Context, jql string) ([]jiraIssueShort, error) {
	var allIssues []jiraIssueShort
	startAt := 0
	maxResults := 50
	for {
		reqURL := fmt.Sprintf("%s/search?jql=%s&startAt=%d&maxResults=%d&expand=renderedFields&fields=summary,project,description",
			e.apiBase, url.QueryEscape(jql), startAt, maxResults)
		body, err := e.jiraGet(ctx, reqURL)
		if err != nil {
			return nil, fmt.Errorf("search issues: %w", err)
		}

		var resp jiraSearchResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode search response: %w", err)
		}

		allIssues = append(allIssues, resp.Issues...)

		if startAt+len(resp.Issues) >= resp.Total || len(resp.Issues) == 0 {
			break
		}
		startAt += len(resp.Issues)
	}
	return allIssues, nil
}

// jiraFetchComments retrieves all comments on an issue.
func (e *JiraEnumerator) jiraFetchComments(ctx context.Context, issueKey string) ([]jiraComment, error) {
	var allComments []jiraComment
	startAt := 0
	maxResults := 50
	for {
		reqURL := fmt.Sprintf("%s/issue/%s/comment?startAt=%d&maxResults=%d&expand=renderedBody",
			e.apiBase, issueKey, startAt, maxResults)
		body, err := e.jiraGet(ctx, reqURL)
		if err != nil {
			return nil, fmt.Errorf("fetch comments for %s: %w", issueKey, err)
		}

		var resp jiraCommentResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode comments response: %w", err)
		}

		for _, c := range resp.Comments {
			commentBody := jiraStripHTML(c.RenderedBody)
			if commentBody == "" {
				// Fall back to extracting text from ADF body if rendered body is empty
				commentBody = jiraExtractADFText(c.Body)
			}
			author := c.Author.DisplayName
			if author == "" {
				author = "unknown"
			}
			allComments = append(allComments, jiraComment{
				Author: author,
				Body:   commentBody,
			})
		}

		if startAt+len(resp.Comments) >= resp.Total || len(resp.Comments) == 0 {
			break
		}
		startAt += len(resp.Comments)
	}
	return allComments, nil
}

// jiraExtractADFText extracts plain text from an Atlassian Document Format (ADF) JSON body.
// ADF is used in Jira Cloud v3. This performs a best-effort recursive text extraction.
func jiraExtractADFText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}

	var node map[string]json.RawMessage
	if err := json.Unmarshal(raw, &node); err != nil {
		// Try as plain string fallback
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
		return ""
	}

	var text string
	if t, ok := node["text"]; ok {
		var s string
		if json.Unmarshal(t, &s) == nil {
			text += s
		}
	}

	if content, ok := node["content"]; ok {
		var children []json.RawMessage
		if json.Unmarshal(content, &children) == nil {
			for _, child := range children {
				text += jiraExtractADFText(child)
			}
		}
	}

	return text
}

// Enumerate discovers issues from a Jira instance and yields blobs.
func (e *JiraEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// Build JQL query
	jql := "ORDER BY created DESC"
	if e.config.Projects != "" {
		var projectKeys []string
		for _, p := range strings.Split(e.config.Projects, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				projectKeys = append(projectKeys, p)
			}
		}
		if len(projectKeys) > 0 {
			jql = fmt.Sprintf("project IN (%s) ORDER BY created DESC", strings.Join(projectKeys, ","))
		}
	}

	issues, err := e.jiraSearchIssues(ctx, jql)
	if err != nil {
		return err
	}
	e.logf("Found %d issues, scanning for secrets...", len(issues))

	var count atomic.Int64
	var errs []string

	for _, issue := range issues {
		// Extract description text
		description := jiraStripHTML(issue.RenderedFields.Description)
		if description == "" {
			description = jiraExtractADFText(issue.Fields.Description)
		}

		// Fetch comments
		comments, err := e.jiraFetchComments(ctx, issue.Key)
		if err != nil {
			errs = append(errs, fmt.Sprintf("comments for %s: %v", issue.Key, err))
		}

		issueURL := strings.TrimRight(e.config.BaseURL, "/") + "/browse/" + issue.Key
		projectKey := issue.Fields.Project.Key

		blob := jiraBuildIssueBlob(issue.Key, issue.Fields.Summary, issueURL, projectKey, description, comments)
		blobID := types.ComputeBlobID(blob)
		prov := jiraProvenance("issue", issue.Key, issue.Fields.Summary, issueURL, projectKey)

		n := count.Add(1)
		e.progressf("Scanning issues: %d/%d", n, len(issues))

		if err := callback(blob, blobID, prov); err != nil {
			return err
		}
	}

	e.logf("Scanned %d issues", count.Load())

	if len(errs) > 0 {
		return fmt.Errorf("enumeration errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
