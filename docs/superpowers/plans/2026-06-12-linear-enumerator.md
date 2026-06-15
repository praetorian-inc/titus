# Linear Enumerator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Linear workspace enumerator to titus that scans issues (with nested comments), documents, and project updates for secrets.

**Architecture:** The `LinearEnumerator` uses Linear's GraphQL API (`https://api.linear.app/graphql`) with Relay-style cursor pagination. It follows the Notion enumerator pattern: raw `net/http` calls, `golang.org/x/time/rate.Limiter` for throttling, concurrent workers with mutex-protected callback, and `ExtendedProvenance` for non-git provenance. Each issue is one blob (title + description + all comments rendered as markdown). Documents and project updates are separate blob types.

**Tech Stack:** Go stdlib (`net/http`, `encoding/json`, `sync`, `context`), `golang.org/x/time/rate` (already a dependency), `github.com/spf13/cobra`, `github.com/stretchr/testify`

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `pkg/enum/linear.go` | Create | `LinearEnumerator` — config, constructor, GraphQL client, pagination, blob assembly, `Enumerate()` |
| `pkg/enum/linear_test.go` | Create | Unit tests — construction, interface compliance, provenance, blob assembly, GraphQL response parsing, pagination |
| `cmd/titus/linear.go` | Create | Cobra command — flags, env var resolution, wiring enumerator to matcher/store pipeline |
| `cmd/titus/root.go` | Modify (line 35) | Register `linearCmd` |

---

### Task 1: LinearEnumerator scaffold — config, constructor, interface compliance

**Files:**
- Create: `pkg/enum/linear_test.go`
- Create: `pkg/enum/linear.go`

This task establishes the type skeleton. No API calls yet — just the struct, config, constructor, and proof that it satisfies the `Enumerator` interface.

- [ ] **Step 1: Write failing tests for construction and interface compliance**

```go
// pkg/enum/linear_test.go
package enum

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinearEnumerator_Construction(t *testing.T) {
	e, err := NewLinearEnumerator(LinearConfig{Token: "lin_api_test"})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestLinearEnumerator_RequiresToken(t *testing.T) {
	_, err := NewLinearEnumerator(LinearConfig{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestLinearEnumerator_Defaults(t *testing.T) {
	e, err := NewLinearEnumerator(LinearConfig{Token: "lin_api_test"})
	require.NoError(t, err)
	assert.Equal(t, 3, e.config.Concurrency)
	assert.Equal(t, 2.0, e.config.RateLimit)
}

func TestLinearEnumerator_Interface(t *testing.T) {
	e, err := NewLinearEnumerator(LinearConfig{Token: "lin_api_test"})
	require.NoError(t, err)
	var _ Enumerator = e
}

func TestLinearProvenance(t *testing.T) {
	prov := linearProvenance("issue", "ISS-123", "Bug title", "https://linear.app/team/ISS-123", "MyTeam", "MyProject")
	assert.Equal(t, "extended", prov.Kind())
	assert.Equal(t, "linear", prov.Payload["source"])
	assert.Equal(t, "issue", prov.Payload["entityType"])
	assert.Equal(t, "ISS-123", prov.Payload["identifier"])
	assert.Equal(t, "Bug title", prov.Payload["title"])
	assert.Equal(t, "https://linear.app/team/ISS-123", prov.Payload["url"])
	assert.Equal(t, "MyTeam", prov.Payload["team"])
	assert.Equal(t, "MyProject", prov.Payload["project"])
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/carterross/Tools/titus-linear && go test ./pkg/enum/ -run 'TestLinear' -v`
Expected: compilation errors — `NewLinearEnumerator`, `LinearConfig`, `linearProvenance` undefined

- [ ] **Step 3: Write minimal implementation**

```go
// pkg/enum/linear.go
package enum

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
	config  LinearConfig
	client  *http.Client
	limiter *rate.Limiter
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
		config:  cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
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

// Enumerate discovers content from a Linear workspace and yields blobs.
func (e *LinearEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	return fmt.Errorf("not implemented")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/carterross/Tools/titus-linear && go test ./pkg/enum/ -run 'TestLinear' -v`
Expected: all 5 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/carterross/Tools/titus-linear
git add pkg/enum/linear.go pkg/enum/linear_test.go
git commit -m "feat(enum): scaffold LinearEnumerator with config, constructor, and provenance"
```

---

### Task 2: GraphQL client — request helper with rate limiting and retry

**Files:**
- Modify: `pkg/enum/linear_test.go`
- Modify: `pkg/enum/linear.go`

This task adds the HTTP transport layer: a `graphql()` method that sends GraphQL queries to Linear's API with rate limiting, retry on rate-limit errors, and JSON response parsing. Linear returns rate limit errors as HTTP 400 with `"code": "RATELIMITED"` in the GraphQL extensions (not HTTP 429).

- [ ] **Step 1: Write failing tests for the GraphQL client**

```go
// Append to pkg/enum/linear_test.go

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	// ... existing imports
)

func TestLinearGraphQL_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "lin_api_test", r.Header.Get("Authorization"))

		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, "{ viewer { id } }", body["query"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"viewer": map[string]interface{}{"id": "user-1"},
			},
		})
	}))
	defer server.Close()

	e := testLinearEnumerator(t, server.URL)

	var result struct {
		Viewer struct{ ID string } `json:"viewer"`
	}
	err := e.graphql(context.Background(), "{ viewer { id } }", nil, &result)
	require.NoError(t, err)
	assert.Equal(t, "user-1", result.Viewer.ID)
}

func TestLinearGraphQL_RateLimitRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []map[string]interface{}{
					{
						"message":    "rate limited",
						"extensions": map[string]interface{}{"code": "RATELIMITED"},
					},
				},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"viewer": map[string]interface{}{"id": "ok"}},
		})
	}))
	defer server.Close()

	e := testLinearEnumerator(t, server.URL)

	var result struct {
		Viewer struct{ ID string } `json:"viewer"`
	}
	err := e.graphql(context.Background(), "{ viewer { id } }", nil, &result)
	require.NoError(t, err)
	assert.Equal(t, 2, attempts)
	assert.Equal(t, "ok", result.Viewer.ID)
}

func TestLinearGraphQL_GraphQLErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []map[string]interface{}{
				{"message": "Authentication required"},
			},
		})
	}))
	defer server.Close()

	e := testLinearEnumerator(t, server.URL)

	var result struct{}
	err := e.graphql(context.Background(), "{ viewer { id } }", nil, &result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Authentication required")
}

// testLinearEnumerator creates a LinearEnumerator pointing at a test server.
func testLinearEnumerator(t *testing.T, url string) *LinearEnumerator {
	t.Helper()
	e, err := NewLinearEnumerator(LinearConfig{
		Token:     "lin_api_test",
		RateLimit: 1000, // no throttling in tests
	})
	require.NoError(t, err)
	e.endpoint = url
	return e
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/carterross/Tools/titus-linear && go test ./pkg/enum/ -run 'TestLinearGraphQL' -v`
Expected: compilation errors — `graphql` method and `endpoint` field undefined

- [ ] **Step 3: Implement the GraphQL client**

Add an `endpoint` field to `LinearEnumerator` (defaulting to `linearAPIEndpoint` in the constructor) and add the `graphql` method:

```go
// Add to LinearEnumerator struct:
//   endpoint string

// In NewLinearEnumerator, after creating the struct:
//   e.endpoint = linearAPIEndpoint

// graphqlRequest is the payload sent to Linear's GraphQL API.
type graphqlRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// graphqlResponse wraps a raw GraphQL response for error detection.
type graphqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message    string `json:"message"`
		Extensions struct {
			Code string `json:"code"`
		} `json:"extensions"`
	} `json:"errors"`
}

// graphql sends a GraphQL query with rate limiting and retry on RATELIMITED errors.
// The result is unmarshaled into dest from the response "data" field.
func (e *LinearEnumerator) graphql(ctx context.Context, query string, variables map[string]interface{}, dest interface{}) error {
	reqBody := graphqlRequest{Query: query, Variables: variables}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshaling query: %w", err)
	}

	for attempt := 0; attempt < 3; attempt++ {
		if err := e.limiter.Wait(ctx); err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", e.config.Token)

		resp, err := e.client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		var gqlResp graphqlResponse
		if err := json.Unmarshal(body, &gqlResp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		// Check for rate limit error (Linear returns 400, not 429).
		if len(gqlResp.Errors) > 0 && gqlResp.Errors[0].Extensions.Code == "RATELIMITED" {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}

		// Check for other GraphQL errors.
		if len(gqlResp.Errors) > 0 {
			return fmt.Errorf("linear API error: %s", gqlResp.Errors[0].Message)
		}

		if dest != nil && gqlResp.Data != nil {
			if err := json.Unmarshal(gqlResp.Data, dest); err != nil {
				return fmt.Errorf("parsing data: %w", err)
			}
		}
		return nil
	}

	return fmt.Errorf("linear API failed after 3 attempts")
}
```

Don't forget to add `"bytes"` to the import list in `linear.go`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/carterross/Tools/titus-linear && go test ./pkg/enum/ -run 'TestLinear' -v`
Expected: all 8 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/carterross/Tools/titus-linear
git add pkg/enum/linear.go pkg/enum/linear_test.go
git commit -m "feat(enum): add Linear GraphQL client with rate limiting and retry"
```

---

### Task 3: Issue enumeration — paginated query with nested comments

**Files:**
- Modify: `pkg/enum/linear_test.go`
- Modify: `pkg/enum/linear.go`

This task adds the core enumeration logic: paginating through all issues, fetching nested comments (with follow-up pagination for 50+ comment threads), and assembling each issue into a single blob.

- [ ] **Step 1: Write failing tests for issue enumeration and blob assembly**

```go
// Append to pkg/enum/linear_test.go

func TestLinearBuildIssueBlob(t *testing.T) {
	blob := lBuildIssueBlob("ENG-42", "Fix auth bug", "https://linear.app/team/ENG-42", "Engineering", "Auth Rewrite",
		"The login flow is broken when...",
		[]lComment{
			{Author: "alice@co.com", Body: "I see the same issue with API key abc123"},
			{Author: "bob@co.com", Body: "Fixed in latest deploy"},
		},
	)

	text := string(blob)
	assert.Contains(t, text, "Title: Fix auth bug")
	assert.Contains(t, text, "URL: https://linear.app/team/ENG-42")
	assert.Contains(t, text, "Identifier: ENG-42")
	assert.Contains(t, text, "Team: Engineering")
	assert.Contains(t, text, "Project: Auth Rewrite")
	assert.Contains(t, text, "The login flow is broken when...")
	assert.Contains(t, text, "alice@co.com")
	assert.Contains(t, text, "abc123")
	assert.Contains(t, text, "bob@co.com")
}

func TestLinearEnumerateIssues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		query := body["query"].(string)

		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(query, "issues(") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"issues": map[string]interface{}{
						"nodes": []map[string]interface{}{
							{
								"id": "issue-1", "identifier": "ENG-1",
								"title": "Secret in desc", "description": "key=sk_live_abc123",
								"url": "https://linear.app/team/ENG-1",
								"team":    map[string]interface{}{"key": "ENG", "name": "Engineering"},
								"project": nil,
								"comments": map[string]interface{}{
									"nodes": []map[string]interface{}{
										{"id": "c1", "body": "token: ghp_secret456", "user": map[string]interface{}{"name": "Alice", "email": "alice@co.com"}},
									},
									"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
								},
							},
						},
						"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
					},
				},
			})
		}
	}))
	defer server.Close()

	e := testLinearEnumerator(t, server.URL)

	var blobs []string
	err := e.enumerateIssues(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, string(content))
		return nil
	})
	require.NoError(t, err)
	require.Len(t, blobs, 1)
	assert.Contains(t, blobs[0], "sk_live_abc123")
	assert.Contains(t, blobs[0], "ghp_secret456")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/carterross/Tools/titus-linear && go test ./pkg/enum/ -run 'TestLinearBuild|TestLinearEnumerate' -v`
Expected: compilation errors — `lBuildIssueBlob`, `lComment`, `enumerateIssues` undefined

- [ ] **Step 3: Implement issue enumeration**

Add to `pkg/enum/linear.go`:

```go
// lComment holds a rendered comment for blob assembly.
type lComment struct {
	Author string
	Body   string
}

// lBuildIssueBlob assembles an issue blob with metadata header, description, and comments.
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
	if description != "" {
		sb.WriteString(description + "\n")
	}
	if len(comments) > 0 {
		sb.WriteString("\n--- Comments ---\n")
		for _, c := range comments {
			sb.WriteString("\n[" + c.Author + "]:\n")
			sb.WriteString(c.Body + "\n")
		}
	}
	return []byte(sb.String())
}

// issuesResponse maps the GraphQL response for paginated issues.
type issuesResponse struct {
	Issues struct {
		Nodes []struct {
			ID          string `json:"id"`
			Identifier  string `json:"identifier"`
			Title       string `json:"title"`
			Description string `json:"description"`
			URL         string `json:"url"`
			Team        *struct {
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
					User *struct {
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

// pageInfo is the Relay-style pagination cursor.
type pageInfo struct {
	HasNextPage bool   `json:"hasNextPage"`
	EndCursor   string `json:"endCursor"`
}

const issuesQuery = `query($after: String) {
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

const issueCommentsQuery = `query($issueId: String!, $after: String) {
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

// enumerateIssues paginates through all issues and yields one blob per issue.
func (e *LinearEnumerator) enumerateIssues(ctx context.Context, callback func([]byte, types.BlobID, types.Provenance) error) error {
	var after *string

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		vars := map[string]interface{}{}
		if after != nil {
			vars["after"] = *after
		}

		var resp issuesResponse
		if err := e.graphql(ctx, issuesQuery, vars, &resp); err != nil {
			return fmt.Errorf("fetching issues: %w", err)
		}

		for _, issue := range resp.Issues.Nodes {
			// Collect comments from the initial fetch.
			var comments []lComment
			for _, c := range issue.Comments.Nodes {
				author := ""
				if c.User != nil {
					author = c.User.Email
					if author == "" {
						author = c.User.Name
					}
				}
				comments = append(comments, lComment{Author: author, Body: c.Body})
			}

			// Paginate remaining comments if needed.
			if issue.Comments.PageInfo.HasNextPage {
				more, err := e.fetchRemainingComments(ctx, issue.ID, issue.Comments.PageInfo.EndCursor)
				if err != nil {
					e.logf("warning: failed to fetch all comments for %s: %v", issue.Identifier, err)
				}
				comments = append(comments, more...)
			}

			teamName := ""
			if issue.Team != nil {
				teamName = issue.Team.Name
			}
			projectName := ""
			if issue.Project != nil {
				projectName = issue.Project.Name
			}

			blob := lBuildIssueBlob(issue.Identifier, issue.Title, issue.URL, teamName, projectName, issue.Description, comments)
			blobID := types.ComputeBlobID(blob)
			prov := linearProvenance("issue", issue.Identifier, issue.Title, issue.URL, teamName, projectName)

			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}

		if !resp.Issues.PageInfo.HasNextPage {
			break
		}
		after = &resp.Issues.PageInfo.EndCursor
	}
	return nil
}

// issueCommentsResponse maps the follow-up comment pagination response.
type issueCommentsResponse struct {
	Issue struct {
		Comments struct {
			Nodes []struct {
				ID   string `json:"id"`
				Body string `json:"body"`
				User *struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"user"`
			} `json:"nodes"`
			PageInfo pageInfo `json:"pageInfo"`
		} `json:"comments"`
	} `json:"issue"`
}

// fetchRemainingComments paginates through remaining comments for an issue.
func (e *LinearEnumerator) fetchRemainingComments(ctx context.Context, issueID, cursor string) ([]lComment, error) {
	var all []lComment
	after := cursor

	for {
		vars := map[string]interface{}{
			"issueId": issueID,
			"after":   after,
		}

		var resp issueCommentsResponse
		if err := e.graphql(ctx, issueCommentsQuery, vars, &resp); err != nil {
			return all, err
		}

		for _, c := range resp.Issue.Comments.Nodes {
			author := ""
			if c.User != nil {
				author = c.User.Email
				if author == "" {
					author = c.User.Name
				}
			}
			all = append(all, lComment{Author: author, Body: c.Body})
		}

		if !resp.Issue.Comments.PageInfo.HasNextPage {
			break
		}
		after = resp.Issue.Comments.PageInfo.EndCursor
	}
	return all, nil
}
```

Don't forget to add `"strings"` to the import list.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/carterross/Tools/titus-linear && go test ./pkg/enum/ -run 'TestLinear' -v`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/carterross/Tools/titus-linear
git add pkg/enum/linear.go pkg/enum/linear_test.go
git commit -m "feat(enum): add Linear issue enumeration with nested comment pagination"
```

---

### Task 4: Document and project update enumeration

**Files:**
- Modify: `pkg/enum/linear_test.go`
- Modify: `pkg/enum/linear.go`

This task adds enumeration for Linear documents (wiki-style pages) and project updates (status reports). Documents store content as ProseMirror JSON, so we need a text extractor. Project updates use markdown in `body`.

- [ ] **Step 1: Write failing tests for document and project update enumeration**

```go
// Append to pkg/enum/linear_test.go

func TestLinearExtractProseMirrorText(t *testing.T) {
	// ProseMirror JSON with nested paragraphs
	doc := `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"API key: sk_live_abc"}]},{"type":"paragraph","content":[{"type":"text","text":"Deploy to production"}]}]}`
	text := lExtractProseMirrorText([]byte(doc))
	assert.Contains(t, text, "API key: sk_live_abc")
	assert.Contains(t, text, "Deploy to production")
}

func TestLinearExtractProseMirrorText_Empty(t *testing.T) {
	assert.Equal(t, "", lExtractProseMirrorText(nil))
	assert.Equal(t, "", lExtractProseMirrorText([]byte("")))
	assert.Equal(t, "", lExtractProseMirrorText([]byte("not json")))
}

func TestLinearBuildDocBlob(t *testing.T) {
	blob := lBuildDocBlob("Runbook", "https://linear.app/docs/abc", "Eng", "extracted text here")
	text := string(blob)
	assert.Contains(t, text, "Title: Runbook")
	assert.Contains(t, text, "URL: https://linear.app/docs/abc")
	assert.Contains(t, text, "Project: Eng")
	assert.Contains(t, text, "extracted text here")
}

func TestLinearBuildProjectUpdateBlob(t *testing.T) {
	blob := lBuildProjectUpdateBlob("Auth Rewrite", "https://linear.app/updates/1", "Status update body with secret key=abc", "diff content")
	text := string(blob)
	assert.Contains(t, text, "Project: Auth Rewrite")
	assert.Contains(t, text, "secret key=abc")
	assert.Contains(t, text, "diff content")
}

func TestLinearEnumerateDocuments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		query := body["query"].(string)

		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(query, "documents(") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"documents": map[string]interface{}{
						"nodes": []map[string]interface{}{
							{
								"id": "doc-1", "title": "Setup Guide", "slugId": "setup",
								"url":     "https://linear.app/docs/setup",
								"content": `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"password=hunter2"}]}]}`,
								"project": map[string]interface{}{"name": "Infra"},
							},
						},
						"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
					},
				},
			})
		}
	}))
	defer server.Close()

	e := testLinearEnumerator(t, server.URL)

	var blobs []string
	err := e.enumerateDocuments(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, string(content))
		return nil
	})
	require.NoError(t, err)
	require.Len(t, blobs, 1)
	assert.Contains(t, blobs[0], "password=hunter2")
}

func TestLinearEnumerateProjectUpdates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"projectUpdates": map[string]interface{}{
					"nodes": []map[string]interface{}{
						{
							"id": "pu-1", "body": "Deployed with DB_PASS=secret",
							"url":          "https://linear.app/updates/1",
							"diffMarkdown": "changed config",
							"project":      map[string]interface{}{"name": "Backend"},
						},
					},
					"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
				},
			},
		})
	}))
	defer server.Close()

	e := testLinearEnumerator(t, server.URL)

	var blobs []string
	err := e.enumerateProjectUpdates(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, string(content))
		return nil
	})
	require.NoError(t, err)
	require.Len(t, blobs, 1)
	assert.Contains(t, blobs[0], "DB_PASS=secret")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/carterross/Tools/titus-linear && go test ./pkg/enum/ -run 'TestLinearExtract|TestLinearBuildDoc|TestLinearBuildProject|TestLinearEnumerateDoc|TestLinearEnumerateProject' -v`
Expected: compilation errors — `lExtractProseMirrorText`, `lBuildDocBlob`, `lBuildProjectUpdateBlob`, `enumerateDocuments`, `enumerateProjectUpdates` undefined

- [ ] **Step 3: Implement ProseMirror extraction, blob builders, and enumeration methods**

Add to `pkg/enum/linear.go`:

```go
// lExtractProseMirrorText recursively extracts all text nodes from ProseMirror JSON.
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

// lWalkProseMirror recursively walks ProseMirror nodes extracting text.
func lWalkProseMirror(node map[string]interface{}, sb *strings.Builder) {
	if t, ok := node["type"].(string); ok && t == "text" {
		if text, ok := node["text"].(string); ok {
			sb.WriteString(text)
		}
		return
	}
	content, _ := node["content"].([]interface{})
	for i, child := range content {
		cm, ok := child.(map[string]interface{})
		if !ok {
			continue
		}
		lWalkProseMirror(cm, sb)
		// Add newline between block-level nodes.
		nodeType, _ := cm["type"].(string)
		if nodeType != "text" && i < len(content)-1 {
			sb.WriteString("\n")
		}
	}
}

// lBuildDocBlob assembles a document blob.
func lBuildDocBlob(title, url, project, content string) []byte {
	var sb strings.Builder
	sb.WriteString("Title: " + title + "\n")
	sb.WriteString("URL: " + url + "\n")
	if project != "" {
		sb.WriteString("Project: " + project + "\n")
	}
	sb.WriteString("---\n")
	if content != "" {
		sb.WriteString(content + "\n")
	}
	return []byte(sb.String())
}

// lBuildProjectUpdateBlob assembles a project update blob.
func lBuildProjectUpdateBlob(project, url, body, diff string) []byte {
	var sb strings.Builder
	sb.WriteString("Project: " + project + "\n")
	sb.WriteString("URL: " + url + "\n")
	sb.WriteString("---\n")
	if body != "" {
		sb.WriteString(body + "\n")
	}
	if diff != "" {
		sb.WriteString("\n--- Diff ---\n")
		sb.WriteString(diff + "\n")
	}
	return []byte(sb.String())
}

// documentsResponse maps the GraphQL response for paginated documents.
type documentsResponse struct {
	Documents struct {
		Nodes []struct {
			ID      string `json:"id"`
			Title   string `json:"title"`
			Content string `json:"content"` // ProseMirror JSON
			SlugID  string `json:"slugId"`
			URL     string `json:"url"`
			Project *struct {
				Name string `json:"name"`
			} `json:"project"`
		} `json:"nodes"`
		PageInfo pageInfo `json:"pageInfo"`
	} `json:"documents"`
}

const documentsQuery = `query($after: String) {
  documents(first: 50, after: $after) {
    nodes {
      id title content slugId url
      project { name }
    }
    pageInfo { hasNextPage endCursor }
  }
}`

// enumerateDocuments paginates through all documents and yields one blob per document.
func (e *LinearEnumerator) enumerateDocuments(ctx context.Context, callback func([]byte, types.BlobID, types.Provenance) error) error {
	var after *string

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		vars := map[string]interface{}{}
		if after != nil {
			vars["after"] = *after
		}

		var resp documentsResponse
		if err := e.graphql(ctx, documentsQuery, vars, &resp); err != nil {
			return fmt.Errorf("fetching documents: %w", err)
		}

		for _, doc := range resp.Documents.Nodes {
			text := lExtractProseMirrorText([]byte(doc.Content))
			if text == "" && doc.Title == "" {
				continue
			}

			projectName := ""
			if doc.Project != nil {
				projectName = doc.Project.Name
			}

			blob := lBuildDocBlob(doc.Title, doc.URL, projectName, text)
			blobID := types.ComputeBlobID(blob)
			prov := linearProvenance("document", doc.SlugID, doc.Title, doc.URL, "", projectName)

			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}

		if !resp.Documents.PageInfo.HasNextPage {
			break
		}
		after = &resp.Documents.PageInfo.EndCursor
	}
	return nil
}

// projectUpdatesResponse maps the GraphQL response for paginated project updates.
type projectUpdatesResponse struct {
	ProjectUpdates struct {
		Nodes []struct {
			ID           string `json:"id"`
			Body         string `json:"body"`
			DiffMarkdown string `json:"diffMarkdown"`
			URL          string `json:"url"`
			Project      *struct {
				Name string `json:"name"`
			} `json:"project"`
		} `json:"nodes"`
		PageInfo pageInfo `json:"pageInfo"`
	} `json:"projectUpdates"`
}

const projectUpdatesQuery = `query($after: String) {
  projectUpdates(first: 50, after: $after) {
    nodes {
      id body diffMarkdown url
      project { name }
    }
    pageInfo { hasNextPage endCursor }
  }
}`

// enumerateProjectUpdates paginates through all project updates and yields one blob per update.
func (e *LinearEnumerator) enumerateProjectUpdates(ctx context.Context, callback func([]byte, types.BlobID, types.Provenance) error) error {
	var after *string

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		vars := map[string]interface{}{}
		if after != nil {
			vars["after"] = *after
		}

		var resp projectUpdatesResponse
		if err := e.graphql(ctx, projectUpdatesQuery, vars, &resp); err != nil {
			return fmt.Errorf("fetching project updates: %w", err)
		}

		for _, pu := range resp.ProjectUpdates.Nodes {
			if pu.Body == "" && pu.DiffMarkdown == "" {
				continue
			}

			projectName := ""
			if pu.Project != nil {
				projectName = pu.Project.Name
			}

			blob := lBuildProjectUpdateBlob(projectName, pu.URL, pu.Body, pu.DiffMarkdown)
			blobID := types.ComputeBlobID(blob)
			prov := linearProvenance("projectUpdate", pu.ID, projectName, pu.URL, "", projectName)

			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}

		if !resp.ProjectUpdates.PageInfo.HasNextPage {
			break
		}
		after = &resp.ProjectUpdates.PageInfo.EndCursor
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/carterross/Tools/titus-linear && go test ./pkg/enum/ -run 'TestLinear' -v`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/carterross/Tools/titus-linear
git add pkg/enum/linear.go pkg/enum/linear_test.go
git commit -m "feat(enum): add Linear document and project update enumeration"
```

---

### Task 5: Wire up Enumerate() — orchestrate all entity types

**Files:**
- Modify: `pkg/enum/linear_test.go`
- Modify: `pkg/enum/linear.go`

This task replaces the stub `Enumerate()` method with the real orchestrator that runs issue, document, and project update enumeration concurrently, matching the Notion enumerator's worker pattern.

- [ ] **Step 1: Write a failing integration test for Enumerate()**

```go
// Append to pkg/enum/linear_test.go

func TestLinearEnumerate_FullIntegration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		query := body["query"].(string)

		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(query, "issues("):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"issues": map[string]interface{}{
						"nodes": []map[string]interface{}{
							{
								"id": "i1", "identifier": "ENG-1", "title": "Issue 1",
								"description": "desc", "url": "https://linear.app/ENG-1",
								"team": map[string]interface{}{"key": "ENG", "name": "Eng"},
								"project": nil,
								"comments": map[string]interface{}{
									"nodes":    []interface{}{},
									"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
								},
							},
						},
						"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
					},
				},
			})
		case strings.Contains(query, "documents("):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"documents": map[string]interface{}{
						"nodes": []map[string]interface{}{
							{
								"id": "d1", "title": "Doc 1", "slugId": "doc-1",
								"url":     "https://linear.app/docs/1",
								"content": `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"doc content"}]}]}`,
								"project": nil,
							},
						},
						"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
					},
				},
			})
		case strings.Contains(query, "projectUpdates("):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"projectUpdates": map[string]interface{}{
						"nodes": []map[string]interface{}{
							{
								"id": "pu1", "body": "update body", "diffMarkdown": "",
								"url":     "https://linear.app/updates/1",
								"project": map[string]interface{}{"name": "Proj"},
							},
						},
						"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
					},
				},
			})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}})
		}
	}))
	defer server.Close()

	e := testLinearEnumerator(t, server.URL)

	var blobs []string
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, string(content))
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, blobs, 3, "expected 1 issue + 1 doc + 1 project update")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/carterross/Tools/titus-linear && go test ./pkg/enum/ -run 'TestLinearEnumerate_Full' -v`
Expected: FAIL — `Enumerate` returns "not implemented" error

- [ ] **Step 3: Replace the stub Enumerate() with the real orchestrator**

Replace the existing `Enumerate()` method in `pkg/enum/linear.go`:

```go
// Enumerate discovers content from a Linear workspace and yields blobs.
// It enumerates issues (with nested comments), documents, and project updates.
func (e *LinearEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	var callbackMu sync.Mutex
	safeCallback := func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		callbackMu.Lock()
		defer callbackMu.Unlock()
		return callback(content, blobID, prov)
	}

	type result struct {
		name string
		err  error
	}

	ch := make(chan result, 3)

	go func() {
		e.logf("Enumerating issues...")
		ch <- result{"issues", e.enumerateIssues(ctx, safeCallback)}
	}()
	go func() {
		e.logf("Enumerating documents...")
		ch <- result{"documents", e.enumerateDocuments(ctx, safeCallback)}
	}()
	go func() {
		e.logf("Enumerating project updates...")
		ch <- result{"projectUpdates", e.enumerateProjectUpdates(ctx, safeCallback)}
	}()

	var errs []string
	for i := 0; i < 3; i++ {
		r := <-ch
		if r.err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", r.name, r.err))
		} else {
			e.logf("Finished enumerating %s", r.name)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("enumeration errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
```

Add `"sync"` to the imports.

- [ ] **Step 4: Run all tests to verify they pass**

Run: `cd /Users/carterross/Tools/titus-linear && go test ./pkg/enum/ -run 'TestLinear' -v -count=1`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/carterross/Tools/titus-linear
git add pkg/enum/linear.go pkg/enum/linear_test.go
git commit -m "feat(enum): wire up Linear Enumerate() with concurrent entity type scanning"
```

---

### Task 6: CLI command and registration

**Files:**
- Create: `cmd/titus/linear.go`
- Modify: `cmd/titus/root.go` (line 35)

This task adds the cobra command that wires the `LinearEnumerator` to the standard matcher/store pipeline, and registers it in the root command.

- [ ] **Step 1: Create the Linear command file**

Create `cmd/titus/linear.go`:

```go
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
)

var (
	linearToken        string
	linearConcurrency  int
	linearOutputPath   string
	linearOutputFormat string
)

var linearCmd = &cobra.Command{
	Use:   "linear",
	Short: "Scan a Linear workspace for secrets",
	Long: `Scan an entire Linear workspace for secrets via the GraphQL API.
Enumerates issues (with comments), documents, and project updates.

Authentication:
  Use --token or LINEAR_TOKEN env var with a Linear API key.
  Create one at: https://linear.app/settings/api

Examples:
  titus linear --token lin_api_xxx
  LINEAR_TOKEN=lin_api_xxx titus linear
  titus linear --token lin_api_xxx --output linear-scan.db --format json`,
	RunE: runLinearScan,
}

func init() {
	linearCmd.Flags().StringVar(&linearToken, "token", "", "Linear API key (or LINEAR_TOKEN env)")
	linearCmd.Flags().IntVar(&linearConcurrency, "concurrency", 3, "Number of parallel entity fetchers")
	linearCmd.Flags().StringVar(&linearOutputPath, "output", "titus.db", "Output database path")
	linearCmd.Flags().StringVar(&linearOutputFormat, "format", "human", "Output format: json, human")
}

func runLinearScan(cmd *cobra.Command, args []string) error {
	token := linearToken
	if token == "" {
		token = os.Getenv("LINEAR_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("linear API key is required: use --token or LINEAR_TOKEN env var")
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewLinearEnumerator(enum.LinearConfig{
		Token:       token,
		Concurrency: linearConcurrency,
		Verbose:     verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating Linear enumerator: %w", err)
	}

	rules, err := loadRules("", "", "", scanRuleset, false)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	m, err := matcher.New(matcher.Config{
		Rules:        rules,
		ContextLines: 3,
	})
	if err != nil {
		return fmt.Errorf("creating matcher: %w", err)
	}
	defer m.Close()

	s, err := store.New(store.Config{
		Path: linearOutputPath,
	})
	if err != nil {
		return fmt.Errorf("creating store: %w", err)
	}
	defer s.Close()

	for _, r := range rules {
		if err := s.AddRule(r); err != nil {
			return fmt.Errorf("storing rule: %w", err)
		}
	}

	ctx := context.Background()
	matchCount := 0
	findingCount := 0

	err = enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		if err := s.AddBlob(blobID, int64(len(content))); err != nil {
			return fmt.Errorf("storing blob: %w", err)
		}

		if err := s.AddProvenance(blobID, prov); err != nil {
			return fmt.Errorf("storing provenance: %w", err)
		}

		matches, err := m.MatchWithBlobID(content, blobID)
		if err != nil {
			return fmt.Errorf("matching content: %w", err)
		}

		for _, match := range matches {
			startLine, startCol := types.ComputeLineColumn(content, int(match.Location.Offset.Start))
			endLine, endCol := types.ComputeLineColumn(content, int(match.Location.Offset.End))
			match.Location.Source.Start.Line = startLine
			match.Location.Source.Start.Column = startCol
			match.Location.Source.End.Line = endLine
			match.Location.Source.End.Column = endCol
		}

		for _, match := range matches {
			matchCount++

			if err := s.AddMatch(match); err != nil {
				return fmt.Errorf("storing match: %w", err)
			}

			rule, ok := ruleMap[match.RuleID]
			if !ok {
				return fmt.Errorf("rule not found: %s", match.RuleID)
			}
			findingID := types.ComputeFindingID(rule.StructuralID, match.Groups)
			exists, err := s.FindingExists(findingID)
			if err != nil {
				return fmt.Errorf("checking finding: %w", err)
			}

			if !exists {
				findingCount++
				finding := &types.Finding{
					ID:     findingID,
					RuleID: match.RuleID,
					Groups: match.Groups,
				}
				if err := s.AddFinding(finding); err != nil {
					return fmt.Errorf("storing finding: %w", err)
				}
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("scanning Linear: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Linear scan complete: %d matches, %d findings\n", matchCount, findingCount)
	fmt.Fprintf(cmd.OutOrStdout(), "Results stored in: %s\n", linearOutputPath)

	if linearOutputFormat == "json" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputMatches(cmd, matches)
	}

	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}
	return outputFindings(cmd, findings)
}
```

- [ ] **Step 2: Register the command in root.go**

In `cmd/titus/root.go`, add `rootCmd.AddCommand(linearCmd)` after the existing `AddCommand` calls (around line 35):

```go
rootCmd.AddCommand(linearCmd)
```

- [ ] **Step 3: Verify it compiles**

Run: `cd /Users/carterross/Tools/titus-linear && go build ./cmd/titus/`
Expected: clean build, no errors

- [ ] **Step 4: Verify the command appears in help**

Run: `cd /Users/carterross/Tools/titus-linear && go run ./cmd/titus/ --help 2>&1 | grep -i linear`
Expected: output includes `linear     Scan a Linear workspace for secrets`

- [ ] **Step 5: Verify flag help**

Run: `cd /Users/carterross/Tools/titus-linear && go run ./cmd/titus/ linear --help`
Expected: shows `--token`, `--concurrency`, `--output`, `--format` flags with descriptions

- [ ] **Step 6: Run all tests to ensure nothing is broken**

Run: `cd /Users/carterross/Tools/titus-linear && go test ./... 2>&1 | tail -20`
Expected: all tests PASS (no regressions)

- [ ] **Step 7: Commit**

```bash
cd /Users/carterross/Tools/titus-linear
git add cmd/titus/linear.go cmd/titus/root.go
git commit -m "feat(enum): add Linear CLI command and register in root"
```

---

### Task 7: End-to-end smoke test

**Files:**
- Modify: `pkg/enum/linear_test.go`

This task adds a test that exercises the full `Enumerate()` → blob → provenance pipeline with multi-page pagination to verify the cursor logic works correctly.

- [ ] **Step 1: Write multi-page pagination test**

```go
// Append to pkg/enum/linear_test.go

func TestLinearEnumerate_Pagination(t *testing.T) {
	issuePage := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		query := body["query"].(string)
		vars, _ := body["variables"].(map[string]interface{})

		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(query, "issues("):
			issuePage++
			if issuePage == 1 {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"issues": map[string]interface{}{
							"nodes": []map[string]interface{}{
								{
									"id": "i1", "identifier": "ENG-1", "title": "First",
									"description": "page1", "url": "https://linear.app/ENG-1",
									"team": map[string]interface{}{"key": "ENG", "name": "Eng"},
									"project": nil,
									"comments": map[string]interface{}{
										"nodes":    []interface{}{},
										"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
									},
								},
							},
							"pageInfo": map[string]interface{}{"hasNextPage": true, "endCursor": "cursor-1"},
						},
					},
				})
			} else {
				assert.Equal(t, "cursor-1", vars["after"])
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"issues": map[string]interface{}{
							"nodes": []map[string]interface{}{
								{
									"id": "i2", "identifier": "ENG-2", "title": "Second",
									"description": "page2", "url": "https://linear.app/ENG-2",
									"team": map[string]interface{}{"key": "ENG", "name": "Eng"},
									"project": nil,
									"comments": map[string]interface{}{
										"nodes":    []interface{}{},
										"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
									},
								},
							},
							"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
						},
					},
				})
			}
		case strings.Contains(query, "documents("):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"documents": map[string]interface{}{
						"nodes":    []interface{}{},
						"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
					},
				},
			})
		case strings.Contains(query, "projectUpdates("):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"projectUpdates": map[string]interface{}{
						"nodes":    []interface{}{},
						"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
					},
				},
			})
		}
	}))
	defer server.Close()

	e := testLinearEnumerator(t, server.URL)

	var blobs []string
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, string(content))
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, blobs, 2)
	assert.Contains(t, blobs[0], "page1")
	assert.Contains(t, blobs[1], "page2")
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `cd /Users/carterross/Tools/titus-linear && go test ./pkg/enum/ -run 'TestLinearEnumerate_Pagination' -v`
Expected: PASS — cursor pagination correctly fetches both pages

- [ ] **Step 3: Run full test suite**

Run: `cd /Users/carterross/Tools/titus-linear && go test ./pkg/enum/ -run 'TestLinear' -v -count=1`
Expected: all Linear tests PASS

- [ ] **Step 4: Commit**

```bash
cd /Users/carterross/Tools/titus-linear
git add pkg/enum/linear_test.go
git commit -m "test(enum): add Linear pagination integration test"
```
