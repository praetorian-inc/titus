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
	"strconv"
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
	apiBase string // resolved at construction or after version detection
}

// NewJiraEnumerator creates a new Jira enumerator.
// The API version (v2 vs v3) is auto-detected on the first API call.
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

	// apiBase is set empty; resolved lazily via detectAPIVersion on first use.
	return &JiraEnumerator{
		config:  cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
	}, nil
}

// detectAPIVersion probes the Jira instance to determine whether to use v3 (Cloud) or v2 (Server/DC).
// It tries /rest/api/3/serverInfo first; if that fails, falls back to /rest/api/2.
func (e *JiraEnumerator) detectAPIVersion(ctx context.Context) error {
	if e.apiBase != "" {
		return nil // already resolved (or overridden in tests)
	}

	base := strings.TrimRight(e.config.BaseURL, "/")

	// Try v3 first (Jira Cloud)
	v3URL := base + "/rest/api/3/serverInfo"
	if _, err := e.jiraGetRaw(ctx, v3URL); err == nil {
		e.apiBase = base + "/rest/api/3"
		e.logf("Detected Jira Cloud (API v3)")
		return nil
	}

	// Fall back to v2 (Jira Server/Data Center)
	v2URL := base + "/rest/api/2/serverInfo"
	if _, err := e.jiraGetRaw(ctx, v2URL); err == nil {
		e.apiBase = base + "/rest/api/2"
		e.logf("Detected Jira Server/Data Center (API v2)")
		return nil
	}

	return fmt.Errorf("could not detect Jira API version: neither /rest/api/3 nor /rest/api/2 responded successfully at %s", base)
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
		Description json.RawMessage `json:"description"` // ADF in v3, plain text in v2, may be null
		Created     string          `json:"created"`      // ISO timestamp, used for cursor-based pagination
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
	RenderedBody string          `json:"renderedBody"`
	Body         json.RawMessage `json:"body"` // ADF in v3
}

// jiraGetRaw performs a single rate-limited GET with auth. Used for version probing.
func (e *JiraEnumerator) jiraGetRaw(ctx context.Context, reqURL string) ([]byte, error) {
	if err := e.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	if e.config.Username != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(e.config.Username + ":" + e.config.Token))
		req.Header.Set("Authorization", "Basic "+encoded)
	} else {
		req.Header.Set("Authorization", "Bearer "+e.config.Token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// jiraGet performs a rate-limited GET request with auth and retry logic.
// Respects Retry-After header on 429 responses.
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
			retryDelay := 2 * time.Second
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, parseErr := strconv.Atoi(ra); parseErr == nil && secs > 0 {
					retryDelay = time.Duration(secs) * time.Second
				}
			}
			resp.Body.Close()
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(retryDelay):
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

// jiraProjectKeyRe validates Jira project keys (alphanumeric + underscore, starts with letter).
var jiraProjectKeyRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// jiraSanitizeProjectKey validates a project key to prevent JQL injection.
func jiraSanitizeProjectKey(key string) (string, error) {
	if !jiraProjectKeyRe.MatchString(key) {
		return "", fmt.Errorf("invalid Jira project key %q: must be alphanumeric starting with a letter", key)
	}
	return key, nil
}

// jiraMaxStartAt is the Jira Cloud hard limit for offset-based pagination.
const jiraMaxStartAt = 10000

// jiraEnumerateIssues performs paginated JQL search and calls the callback for each issue.
// It streams results per-page to avoid loading all issues into memory at once.
// When hitting the Jira Cloud 10k offset limit, it switches to date-based cursor pagination.
func (e *JiraEnumerator) jiraEnumerateIssues(ctx context.Context, baseJQL string, callback func(issue jiraIssueShort) error) (int, error) {
	var total int
	startAt := 0
	maxResults := 50
	var lastCreated string // for cursor-based fallback

	for {
		// If approaching the 10k offset limit, switch to date-based cursor
		jql := baseJQL
		if startAt >= jiraMaxStartAt && lastCreated != "" {
			// Append a created <= filter to continue from where we left off
			if strings.Contains(strings.ToUpper(baseJQL), "ORDER BY") {
				// Insert before ORDER BY
				idx := strings.Index(strings.ToUpper(baseJQL), "ORDER BY")
				prefix := strings.TrimSpace(baseJQL[:idx])
				if prefix == "" {
					jql = fmt.Sprintf("created <= \"%s\" ORDER BY created DESC", lastCreated)
				} else {
					jql = fmt.Sprintf("%s AND created <= \"%s\" ORDER BY created DESC", prefix, lastCreated)
				}
			} else {
				jql = fmt.Sprintf("%s AND created <= \"%s\"", baseJQL, lastCreated)
			}
			startAt = 0
		}

		reqURL := fmt.Sprintf("%s/search?jql=%s&startAt=%d&maxResults=%d&expand=renderedFields&fields=summary,project,description,created",
			e.apiBase, url.QueryEscape(jql), startAt, maxResults)
		body, err := e.jiraGet(ctx, reqURL)
		if err != nil {
			return total, fmt.Errorf("search issues: %w", err)
		}

		var resp jiraSearchResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return total, fmt.Errorf("decode search response: %w", err)
		}

		for i := range resp.Issues {
			if err := callback(resp.Issues[i]); err != nil {
				return total, err
			}
			total++
			if resp.Issues[i].Fields.Created != "" {
				lastCreated = resp.Issues[i].Fields.Created
			}
		}

		if len(resp.Issues) == 0 || startAt+len(resp.Issues) >= resp.Total {
			break
		}
		startAt += len(resp.Issues)
	}
	return total, nil
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
// Block-level nodes (paragraph, heading, etc.) are separated by newlines to preserve
// word boundaries for regex-based secret matching.
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

	// Determine if this is a block-level node
	var nodeType string
	if t, ok := node["type"]; ok {
		_ = json.Unmarshal(t, &nodeType)
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
				childText := jiraExtractADFText(child)
				if childText != "" {
					if text != "" {
						text += "\n"
					}
					text += childText
				}
			}
		}
	}

	return text
}

// Enumerate discovers issues from a Jira instance and yields blobs.
func (e *JiraEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// Auto-detect API version (v2 vs v3)
	if err := e.detectAPIVersion(ctx); err != nil {
		return err
	}

	// Build JQL query with sanitized project keys
	jql := "ORDER BY created DESC"
	if e.config.Projects != "" {
		var projectKeys []string
		for _, p := range strings.Split(e.config.Projects, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				sanitized, err := jiraSanitizeProjectKey(p)
				if err != nil {
					return err
				}
				projectKeys = append(projectKeys, sanitized)
			}
		}
		if len(projectKeys) > 0 {
			jql = fmt.Sprintf("project IN (%s) ORDER BY created DESC", strings.Join(projectKeys, ","))
		}
	}

	var count atomic.Int64
	var errs []string

	total, err := e.jiraEnumerateIssues(ctx, jql, func(issue jiraIssueShort) error {
		// Extract description text
		description := jiraStripHTML(issue.RenderedFields.Description)
		if description == "" {
			description = jiraExtractADFText(issue.Fields.Description)
		}

		// Fetch comments
		comments, commentErr := e.jiraFetchComments(ctx, issue.Key)
		if commentErr != nil {
			errs = append(errs, fmt.Sprintf("comments for %s: %v", issue.Key, commentErr))
		}

		issueURL := strings.TrimRight(e.config.BaseURL, "/") + "/browse/" + issue.Key
		projectKey := issue.Fields.Project.Key

		blob := jiraBuildIssueBlob(issue.Key, issue.Fields.Summary, issueURL, projectKey, description, comments)
		blobID := types.ComputeBlobID(blob)
		prov := jiraProvenance("issue", issue.Key, issue.Fields.Summary, issueURL, projectKey)

		n := count.Add(1)
		e.progressf("Scanning issues: %d", n)

		return callback(blob, blobID, prov)
	})

	if err != nil {
		return err
	}

	e.logf("Scanned %d issues", total)

	if len(errs) > 0 {
		return fmt.Errorf("enumeration errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
