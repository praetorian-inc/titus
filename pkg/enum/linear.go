package enum

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/praetorian-inc/titus/pkg/types"
)

const linearAPIEndpoint = "https://api.linear.app/graphql"

// LinearConfig configures the Linear workspace enumerator.
type LinearConfig struct {
	Token       string    // Linear API key (lin_api_...)
	Concurrency int       // parallel workers (default 3)
	RateLimit   float64   // requests per second (default 2)
	Verbose     io.Writer // progress output (nil = silent)
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
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 3
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
		fmt.Fprintf(e.config.Verbose, format+"\n", args...)
	}
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
			all = append(all, lComment{Author: author, Body: node.Body})
		}
		if !resp.Issue.Comments.PageInfo.HasNextPage {
			break
		}
		cursor = resp.Issue.Comments.PageInfo.EndCursor
	}
	return all, nil
}

// enumerateIssues paginates through all Linear issues and emits one blob per issue.
func (e *LinearEnumerator) enumerateIssues(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
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
			e.logf("linear: issue %s (%s)", node.Identifier, node.Title)
			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}

		if !resp.Issues.PageInfo.HasNextPage {
			break
		}
		cursor = resp.Issues.PageInfo.EndCursor
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
	return fmt.Errorf("not implemented")
}
