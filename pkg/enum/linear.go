package enum

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/praetorian-inc/titus/pkg/types"
)

const linearAPIEndpoint = "https://api.linear.app/graphql"

// LinearConfig configures the Linear workspace enumerator.
type LinearConfig struct {
	Token     string    // Linear API key (lin_api_...)
	RateLimit float64   // requests per second (default 2)
	Verbose   io.Writer // progress output (nil = silent)
}

// LinearEnumerator enumerates blobs from a Linear workspace via the GraphQL API.
type LinearEnumerator struct {
	config   LinearConfig
	client   *http.Client
	limiter  *rate.Limiter
	endpoint string
}

// NewLinearEnumerator creates a new Linear enumerator.
func NewLinearEnumerator(cfg LinearConfig) (*LinearEnumerator, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("linear API token is required")
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 2.0
	}
	return &LinearEnumerator{
		config:   cfg,
		client:   &http.Client{Timeout: 30 * time.Second},
		limiter:  rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
		endpoint: linearAPIEndpoint,
	}, nil
}

// linearProvenance builds an ExtendedProvenance for a Linear entity.
func linearProvenance(entityType, identifier, title, url, team, project string) types.ExtendedProvenance {
	return types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source":     "linear",
			"entityType": entityType,
			"identifier": identifier,
			"title":      title,
			"url":        url,
			"team":       team,
			"project":    project,
		},
	}
}

// logf writes a progress message when verbose output is enabled.
func (e *LinearEnumerator) logf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, format+"\n", args...)
	}
}

// progressf writes an in-place progress update using \r.
func (e *LinearEnumerator) progressf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, "\r%-80s", fmt.Sprintf(format, args...))
	}
}

// countsResponse maps the discovery count query.
type countsResponse struct {
	Teams struct {
		Nodes []struct {
			IssueCount int `json:"issueCount"`
		} `json:"nodes"`
	} `json:"teams"`
}

const linearCountsQuery = `{
  teams {
    nodes {
      issueCount
    }
  }
}`

// discoverCounts queries the workspace for entity counts to drive progress reporting.
// Returns total issue count (sum of all teams' issueCount).
func (e *LinearEnumerator) discoverCounts(ctx context.Context) int {
	var resp countsResponse
	if err := e.graphql(ctx, linearCountsQuery, nil, &resp); err != nil {
		return 0
	}
	total := 0
	for _, t := range resp.Teams.Nodes {
		total += t.IssueCount
	}
	return total
}

type graphqlRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type graphqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message    string `json:"message"`
		Extensions struct {
			Code string `json:"code"`
		} `json:"extensions"`
	} `json:"errors"`
}

// lComment holds author and body of a Linear comment.
type lComment struct {
	Author string
	Body   string
}

// pageInfo carries Relay cursor pagination state.
type pageInfo struct {
	HasNextPage bool   `json:"hasNextPage"`
	EndCursor   string `json:"endCursor"`
}

// issuesResponse maps the GraphQL issues query response.
type issuesResponse struct {
	Issues struct {
		Nodes []struct {
			ID          string `json:"id"`
			Identifier  string `json:"identifier"`
			Title       string `json:"title"`
			Description string `json:"description"`
			URL         string `json:"url"`
			Team        struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"team"`
			Project *struct {
				Name string `json:"name"`
			} `json:"project"`
			Comments struct {
				Nodes []struct {
					ID   string `json:"id"`
					Body string `json:"body"`
					User struct {
						Name  string `json:"name"`
						Email string `json:"email"`
					} `json:"user"`
				} `json:"nodes"`
				PageInfo pageInfo `json:"pageInfo"`
			} `json:"comments"`
		} `json:"nodes"`
		PageInfo pageInfo `json:"pageInfo"`
	} `json:"issues"`
}

// issueCommentsResponse maps the follow-up comment pagination response.
type issueCommentsResponse struct {
	Issue struct {
		Comments struct {
			Nodes []struct {
				ID   string `json:"id"`
				Body string `json:"body"`
				User struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"user"`
			} `json:"nodes"`
			PageInfo pageInfo `json:"pageInfo"`
		} `json:"comments"`
	} `json:"issue"`
}

const linearIssuesQuery = `
query($after: String) {
  issues(first: 50, after: $after) {
    nodes {
      id identifier title description url
      team { key name }
      project { name }
      comments(first: 50) {
        nodes {
          id body
          user { name email }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}`

const linearIssueCommentsQuery = `
query($issueId: String!, $after: String) {
  issue(id: $issueId) {
    comments(first: 50, after: $after) {
      nodes {
        id body
        user { name email }
      }
      pageInfo { hasNextPage endCursor }
    }
  }
}`

// lBuildIssueBlob assembles a Linear issue into a single blob.
func lBuildIssueBlob(identifier, title, url, team, project, description string, comments []lComment) []byte {
	var sb strings.Builder
	sb.WriteString("Title: " + title + "\n")
	sb.WriteString("URL: " + url + "\n")
	sb.WriteString("Identifier: " + identifier + "\n")
	sb.WriteString("Team: " + team + "\n")
	if project != "" {
		sb.WriteString("Project: " + project + "\n")
	}
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

// fetchRemainingComments paginates through remaining comments for an issue.
func (e *LinearEnumerator) fetchRemainingComments(ctx context.Context, issueID, cursor string) ([]lComment, error) {
	var all []lComment
	for {
		vars := map[string]interface{}{
			"issueId": issueID,
			"after":   cursor,
		}
		var resp issueCommentsResponse
		if err := e.graphql(ctx, linearIssueCommentsQuery, vars, &resp); err != nil {
			return nil, fmt.Errorf("fetch comments for issue %s: %w", issueID, err)
		}
		for _, node := range resp.Issue.Comments.Nodes {
			author := node.User.Email
			if author == "" {
				author = node.User.Name
			}
			if author == "" {
				author = "Unknown"
			}
			all = append(all, lComment{Author: author, Body: node.Body})
		}
		if !resp.Issue.Comments.PageInfo.HasNextPage {
			break
		}
		newCursor := resp.Issue.Comments.PageInfo.EndCursor
		if newCursor == cursor {
			break // cursor didn't advance, avoid infinite loop
		}
		cursor = newCursor
	}
	return all, nil
}

// enumerateIssues paginates through all Linear issues and emits one blob per issue.
func (e *LinearEnumerator) enumerateIssues(ctx context.Context, total int, count *atomic.Int64, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	var cursor string
	for {
		vars := map[string]interface{}{"after": cursor}
		if cursor == "" {
			vars = map[string]interface{}{}
		}
		var resp issuesResponse
		if err := e.graphql(ctx, linearIssuesQuery, vars, &resp); err != nil {
			return fmt.Errorf("fetch issues: %w", err)
		}

		for _, node := range resp.Issues.Nodes {
			// Collect comments from the initial page
			var comments []lComment
			for _, cn := range node.Comments.Nodes {
				author := cn.User.Email
				if author == "" {
					author = cn.User.Name
				}
				if author == "" {
					author = "Unknown"
				}
				comments = append(comments, lComment{Author: author, Body: cn.Body})
			}
			// Fetch remaining comment pages if needed
			if node.Comments.PageInfo.HasNextPage {
				more, err := e.fetchRemainingComments(ctx, node.ID, node.Comments.PageInfo.EndCursor)
				if err != nil {
					return err
				}
				comments = append(comments, more...)
			}

			team := node.Team.Name
			project := ""
			if node.Project != nil {
				project = node.Project.Name
			}

			blob := lBuildIssueBlob(node.Identifier, node.Title, node.URL, team, project, node.Description, comments)
			blobID := types.ComputeBlobID(blob)
			prov := linearProvenance("issue", node.Identifier, node.Title, node.URL, team, project)
			n := count.Add(1)
			if total > 0 {
				e.progressf("Scanning issues: %d/%d (%d%%)", n, total, n*100/int64(total))
			} else {
				e.progressf("Scanning issues: %d", n)
			}
			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}

		if !resp.Issues.PageInfo.HasNextPage {
			break
		}
		newCursor := resp.Issues.PageInfo.EndCursor
		if newCursor == cursor {
			break // cursor didn't advance, avoid infinite loop
		}
		cursor = newCursor
	}
	if total > 0 {
		e.progressf("Scanning issues: %d/%d (100%%)\n", count.Load(), total)
	} else {
		e.progressf("Scanning issues: %d\n", count.Load())
	}
	return nil
}

// documentsResponse maps the GraphQL documents query response.
type documentsResponse struct {
	Documents struct {
		Nodes []struct {
			ID      string `json:"id"`
			Title   string `json:"title"`
			Content string `json:"content"`
			SlugID  string `json:"slugId"`
			URL     string `json:"url"`
			Project *struct {
				Name string `json:"name"`
			} `json:"project"`
		} `json:"nodes"`
		PageInfo pageInfo `json:"pageInfo"`
	} `json:"documents"`
}

// projectUpdatesResponse maps the GraphQL projectUpdates query response.
type projectUpdatesResponse struct {
	ProjectUpdates struct {
		Nodes []struct {
			ID           string `json:"id"`
			Body         string `json:"body"`
			DiffMarkdown string `json:"diffMarkdown"`
			URL          string `json:"url"`
			Project      struct {
				Name string `json:"name"`
			} `json:"project"`
		} `json:"nodes"`
		PageInfo pageInfo `json:"pageInfo"`
	} `json:"projectUpdates"`
}

const linearDocumentsQuery = `
query($after: String) {
  documents(first: 50, after: $after) {
    nodes {
      id title content slugId url
      project { name }
    }
    pageInfo { hasNextPage endCursor }
  }
}`

const linearProjectUpdatesQuery = `
query($after: String) {
  projectUpdates(first: 50, after: $after) {
    nodes {
      id body diffMarkdown url
      project { name }
    }
    pageInfo { hasNextPage endCursor }
  }
}`

// lWalkProseMirror recursively walks a ProseMirror node tree, writing text to sb.
func lWalkProseMirror(node map[string]interface{}, sb *strings.Builder) {
	nodeType, _ := node["type"].(string)
	if nodeType == "text" {
		if text, ok := node["text"].(string); ok {
			sb.WriteString(text)
		}
		return
	}
	content, ok := node["content"].([]interface{})
	if !ok {
		return
	}
	for _, child := range content {
		childMap, ok := child.(map[string]interface{})
		if !ok {
			continue
		}
		lWalkProseMirror(childMap, sb)
		// Add a newline after block-level nodes
		childType, _ := childMap["type"].(string)
		if childType != "text" {
			sb.WriteString("\n")
		}
	}
}

// lExtractProseMirrorText extracts all text nodes from ProseMirror JSON.
func lExtractProseMirrorText(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var node map[string]interface{}
	if err := json.Unmarshal(data, &node); err != nil {
		return ""
	}
	var sb strings.Builder
	lWalkProseMirror(node, &sb)
	return strings.TrimSpace(sb.String())
}

// lBuildDocBlob formats a Linear document as a blob.
func lBuildDocBlob(title, url, project, content string) []byte {
	var sb strings.Builder
	sb.WriteString("Title: " + title + "\n")
	sb.WriteString("URL: " + url + "\n")
	if project != "" {
		sb.WriteString("Project: " + project + "\n")
	}
	sb.WriteString("---\n")
	sb.WriteString(content)
	return []byte(sb.String())
}

// lBuildProjectUpdateBlob formats a Linear project update as a blob.
func lBuildProjectUpdateBlob(project, url, body, diff string) []byte {
	var sb strings.Builder
	sb.WriteString("Project: " + project + "\n")
	sb.WriteString("URL: " + url + "\n")
	sb.WriteString("---\n")
	sb.WriteString(body)
	if diff != "" {
		sb.WriteString("\n\n--- Diff ---\n")
		sb.WriteString(diff)
	}
	return []byte(sb.String())
}

// enumerateDocuments paginates through all Linear documents and emits one blob per document.
func (e *LinearEnumerator) enumerateDocuments(ctx context.Context, count *atomic.Int64, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	var cursor string
	for {
		vars := map[string]interface{}{"after": cursor}
		if cursor == "" {
			vars = map[string]interface{}{}
		}
		var resp documentsResponse
		if err := e.graphql(ctx, linearDocumentsQuery, vars, &resp); err != nil {
			return fmt.Errorf("fetch documents: %w", err)
		}

		for _, doc := range resp.Documents.Nodes {
			textContent := lExtractProseMirrorText([]byte(doc.Content))
			if doc.Title == "" && textContent == "" {
				continue
			}
			project := ""
			if doc.Project != nil {
				project = doc.Project.Name
			}
			blob := lBuildDocBlob(doc.Title, doc.URL, project, textContent)
			blobID := types.ComputeBlobID(blob)
			prov := linearProvenance("document", doc.SlugID, doc.Title, doc.URL, "", project)
			count.Add(1)
			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}

		if !resp.Documents.PageInfo.HasNextPage {
			break
		}
		newCursor := resp.Documents.PageInfo.EndCursor
		if newCursor == cursor {
			break // cursor didn't advance, avoid infinite loop
		}
		cursor = newCursor
	}
	return nil
}

// enumerateProjectUpdates paginates through all Linear project updates and emits one blob per update.
func (e *LinearEnumerator) enumerateProjectUpdates(ctx context.Context, count *atomic.Int64, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	var cursor string
	for {
		vars := map[string]interface{}{"after": cursor}
		if cursor == "" {
			vars = map[string]interface{}{}
		}
		var resp projectUpdatesResponse
		if err := e.graphql(ctx, linearProjectUpdatesQuery, vars, &resp); err != nil {
			return fmt.Errorf("fetch project updates: %w", err)
		}

		for _, pu := range resp.ProjectUpdates.Nodes {
			if pu.Body == "" && pu.DiffMarkdown == "" {
				continue
			}
			blob := lBuildProjectUpdateBlob(pu.Project.Name, pu.URL, pu.Body, pu.DiffMarkdown)
			blobID := types.ComputeBlobID(blob)
			prov := linearProvenance("projectUpdate", pu.ID, "", pu.URL, "", pu.Project.Name)
			count.Add(1)
			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}

		if !resp.ProjectUpdates.PageInfo.HasNextPage {
			break
		}
		newCursor := resp.ProjectUpdates.PageInfo.EndCursor
		if newCursor == cursor {
			break // cursor didn't advance, avoid infinite loop
		}
		cursor = newCursor
	}
	return nil
}

// graphql sends a GraphQL query to Linear's API with rate limiting and retry.
// It retries up to 3 times on rate-limit errors (HTTP 400 with RATELIMITED code).
func (e *LinearEnumerator) graphql(ctx context.Context, query string, variables map[string]interface{}, dest interface{}) error {
	body, err := json.Marshal(graphqlRequest{Query: query, Variables: variables})
	if err != nil {
		return fmt.Errorf("marshal graphql request: %w", err)
	}

	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := e.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", e.config.Token)

		resp, err := e.client.Do(req)
		if err != nil {
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(2 * time.Second):
				}
				continue
			}
			return fmt.Errorf("http request: %w", err)
		}

		// Retry on server errors (5xx)
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(2 * time.Second):
				}
				continue
			}
			return fmt.Errorf("linear API returned %d after %d attempts", resp.StatusCode, maxAttempts)
		}

		// Non-200/400 is unexpected — don't retry
		if resp.StatusCode != 200 && resp.StatusCode != 400 {
			resp.Body.Close()
			return fmt.Errorf("linear API returned unexpected status %d", resp.StatusCode)
		}

		var gqlResp graphqlResponse
		if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
			resp.Body.Close()
			return fmt.Errorf("decode response: %w", err)
		}
		resp.Body.Close()

		// Check for rate limit errors (Linear returns HTTP 400 with RATELIMITED code)
		rateLimited := false
		for _, gqlErr := range gqlResp.Errors {
			if gqlErr.Extensions.Code == "RATELIMITED" {
				rateLimited = true
				break
			}
		}
		if rateLimited {
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(2 * time.Second):
				}
				continue
			}
			return fmt.Errorf("linear API rate limited after %d attempts", maxAttempts)
		}

		// Check for other GraphQL errors
		if len(gqlResp.Errors) > 0 {
			return fmt.Errorf("graphql error: %s", gqlResp.Errors[0].Message)
		}

		// Unmarshal data into dest
		if err := json.Unmarshal(gqlResp.Data, dest); err != nil {
			return fmt.Errorf("unmarshal data: %w", err)
		}
		return nil
	}
	return fmt.Errorf("graphql: exceeded max attempts")
}

// Enumerate discovers content from a Linear workspace and yields blobs.
func (e *LinearEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// Discovery phase: get issue count for progress reporting.
	issueTotal := e.discoverCounts(ctx)
	if issueTotal > 0 {
		e.logf("Found %d issues, scanning for secrets...", issueTotal)
	} else {
		e.logf("Scanning for secrets...")
	}

	var callbackMu sync.Mutex
	safeCallback := func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		callbackMu.Lock()
		defer callbackMu.Unlock()
		return callback(content, blobID, prov)
	}

	var issueCount, docCount, updateCount atomic.Int64

	type result struct {
		name string
		err  error
	}

	ch := make(chan result, 3)

	go func() {
		ch <- result{"issues", e.enumerateIssues(ctx, issueTotal, &issueCount, safeCallback)}
	}()
	go func() {
		ch <- result{"documents", e.enumerateDocuments(ctx, &docCount, safeCallback)}
	}()
	go func() {
		ch <- result{"projectUpdates", e.enumerateProjectUpdates(ctx, &updateCount, safeCallback)}
	}()

	var errs []string
	for i := 0; i < 3; i++ {
		r := <-ch
		if r.err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", r.name, r.err))
		}
	}

	e.logf("Scanned %d issues, %d documents, %d project updates", issueCount.Load(), docCount.Load(), updateCount.Load())

	if len(errs) > 0 {
		return fmt.Errorf("enumeration errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
