package enum

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

// Compile-time assertion that *LinearEnumerator satisfies Enumerator.
var _ Enumerator = (*LinearEnumerator)(nil)

// Ensure types package is referenced so imports stay tidy.
var _ types.Provenance = types.ExtendedProvenance{}

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

func TestLinearBuildIssueBlob(t *testing.T) {
	comments := []lComment{
		{Author: "alice@example.com", Body: "First comment"},
		{Author: "Bob Smith", Body: "Second comment"},
	}
	blob := lBuildIssueBlob("ENG-42", "Fix the bug", "https://linear.app/eng/ENG-42", "Engineering", "Alpha", "Bug description here.", comments)

	content := string(blob)
	assert.Contains(t, content, "Title: Fix the bug")
	assert.Contains(t, content, "URL: https://linear.app/eng/ENG-42")
	assert.Contains(t, content, "Identifier: ENG-42")
	assert.Contains(t, content, "Team: Engineering")
	assert.Contains(t, content, "Project: Alpha")
	assert.Contains(t, content, "Bug description here.")
	assert.Contains(t, content, "[alice@example.com]:")
	assert.Contains(t, content, "First comment")
	assert.Contains(t, content, "[Bob Smith]:")
	assert.Contains(t, content, "Second comment")
}

func TestLinearBuildIssueBlob_NoProject(t *testing.T) {
	blob := lBuildIssueBlob("ENG-1", "Title", "https://linear.app/eng/ENG-1", "Engineering", "", "Description.", nil)
	content := string(blob)
	assert.NotContains(t, content, "Project:")
}

func TestLinearEnumerateIssues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		query, _ := body["query"].(string)

		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(query, "issues(") {
			// Return one issue with one comment, no further pages
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"issues": map[string]interface{}{
						"nodes": []map[string]interface{}{
							{
								"id":          "issue-1",
								"identifier":  "ENG-1",
								"title":       "Test Issue",
								"description": "Issue description",
								"url":         "https://linear.app/eng/ENG-1",
								"team": map[string]interface{}{
									"key":  "ENG",
									"name": "Engineering",
								},
								"project": map[string]interface{}{
									"name": "Alpha",
								},
								"comments": map[string]interface{}{
									"nodes": []map[string]interface{}{
										{
											"id":   "comment-1",
											"body": "Great issue!",
											"user": map[string]interface{}{
												"name":  "Alice",
												"email": "alice@example.com",
											},
										},
									},
									"pageInfo": map[string]interface{}{
										"hasNextPage": false,
										"endCursor":   "",
									},
								},
							},
						},
						"pageInfo": map[string]interface{}{
							"hasNextPage": false,
							"endCursor":   "",
						},
					},
				},
			})
		} else {
			// Unexpected query
			http.Error(w, "unexpected query", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	e := testLinearEnumerator(t, server.URL)

	var blobs [][]byte
	var count atomic.Int64
	err := e.enumerateIssues(context.Background(), 0, &count, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, content)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, blobs, 1)

	content := string(blobs[0])
	assert.Contains(t, content, "Title: Test Issue")
	assert.Contains(t, content, "Identifier: ENG-1")
	assert.Contains(t, content, "Issue description")
	assert.Contains(t, content, "[alice@example.com]:")
	assert.Contains(t, content, "Great issue!")
}

func TestLinearExtractProseMirrorText(t *testing.T) {
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
	var count atomic.Int64
	err := e.enumerateDocuments(context.Background(), &count, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
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
	var count atomic.Int64
	err := e.enumerateProjectUpdates(context.Background(), &count, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, string(content))
		return nil
	})
	require.NoError(t, err)
	require.Len(t, blobs, 1)
	assert.Contains(t, blobs[0], "DB_PASS=secret")
}

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
