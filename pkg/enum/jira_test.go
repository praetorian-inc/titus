package enum

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJiraEnumerator_Construction(t *testing.T) {
	e, err := NewJiraEnumerator(JiraConfig{
		Token:   "test-token",
		BaseURL: "https://example.atlassian.net",
	})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestJiraEnumerator_RequiresToken(t *testing.T) {
	_, err := NewJiraEnumerator(JiraConfig{
		BaseURL: "https://example.atlassian.net",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestJiraEnumerator_RequiresBaseURL(t *testing.T) {
	_, err := NewJiraEnumerator(JiraConfig{
		Token: "test-token",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "base URL")
}

func TestJiraEnumerator_Interface(t *testing.T) {
	e, err := NewJiraEnumerator(JiraConfig{
		Token:   "test-token",
		BaseURL: "https://example.atlassian.net",
	})
	require.NoError(t, err)
	var _ Enumerator = e
}

// Compile-time assertion that *JiraEnumerator satisfies Enumerator.
var _ Enumerator = (*JiraEnumerator)(nil)

func TestJiraProvenance(t *testing.T) {
	prov := jiraProvenance("issue", "DEV-123", "Fix login bug", "https://example.atlassian.net/browse/DEV-123", "DEV")
	assert.Equal(t, "extended", prov.Kind())
	assert.Equal(t, "jira", prov.Payload["source"])
	assert.Equal(t, "issue", prov.Payload["entityType"])
	assert.Equal(t, "DEV-123", prov.Payload["identifier"])
	assert.Equal(t, "Fix login bug", prov.Payload["title"])
	assert.Equal(t, "https://example.atlassian.net/browse/DEV-123", prov.Payload["url"])
	assert.Equal(t, "DEV", prov.Payload["project"])
}

func TestJiraBuildIssueBlob(t *testing.T) {
	comments := []jiraComment{
		{Author: "alice", Body: "First comment"},
		{Author: "bob", Body: "Second comment"},
	}
	blob := jiraBuildIssueBlob("DEV-123", "Fix login bug", "https://example.atlassian.net/browse/DEV-123", "DEV", "Issue description body.", comments)

	content := string(blob)
	assert.Contains(t, content, "Key: DEV-123")
	assert.Contains(t, content, "Summary: Fix login bug")
	assert.Contains(t, content, "URL: https://example.atlassian.net/browse/DEV-123")
	assert.Contains(t, content, "Project: DEV")
	assert.Contains(t, content, "Issue description body.")
	assert.Contains(t, content, "[alice]:")
	assert.Contains(t, content, "First comment")
	assert.Contains(t, content, "[bob]:")
	assert.Contains(t, content, "Second comment")
}

func TestJiraBuildIssueBlob_NoComments(t *testing.T) {
	blob := jiraBuildIssueBlob("DEV-1", "Test", "https://example.atlassian.net/browse/DEV-1", "DEV", "Body.", nil)
	content := string(blob)
	assert.Contains(t, content, "Key: DEV-1")
	assert.NotContains(t, content, "--- Comments ---")
}

func TestJiraStripHTML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "basic HTML",
			input:    "<p>Hello <b>world</b></p>",
			expected: "Hello world",
		},
		{
			name:     "HTML entities",
			input:    "foo &amp; bar &lt;baz&gt;",
			expected: "foo & bar <baz>",
		},
		{
			name:     "mixed",
			input:    "<div class=\"x\">key=&quot;secret&quot;</div>",
			expected: "key=\"secret\"",
		},
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, jiraStripHTML(tt.input))
		})
	}
}

func TestJiraExtractADFText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains []string
	}{
		{
			name:     "null",
			input:    "null",
			contains: nil,
		},
		{
			name:     "empty",
			input:    "",
			contains: nil,
		},
		{
			name: "simple ADF paragraph",
			input: `{
				"type": "doc",
				"content": [
					{
						"type": "paragraph",
						"content": [
							{"type": "text", "text": "API_KEY=sk_live_abc123"}
						]
					}
				]
			}`,
			contains: []string{"API_KEY=sk_live_abc123"},
		},
		{
			name: "multiple paragraphs preserve word boundaries",
			input: `{
				"type": "doc",
				"content": [
					{
						"type": "paragraph",
						"content": [
							{"type": "text", "text": "Line 1"}
						]
					},
					{
						"type": "paragraph",
						"content": [
							{"type": "text", "text": "Line 2"}
						]
					}
				]
			}`,
			contains: []string{"Line 1", "Line 2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := jiraExtractADFText(json.RawMessage(tt.input))
			if tt.contains == nil {
				assert.Empty(t, result)
			} else {
				for _, s := range tt.contains {
					assert.Contains(t, result, s)
				}
			}
		})
	}
}

func TestJiraExtractADFText_PreservesWordBoundaries(t *testing.T) {
	input := `{
		"type": "doc",
		"content": [
			{
				"type": "paragraph",
				"content": [{"type": "text", "text": "password"}]
			},
			{
				"type": "paragraph",
				"content": [{"type": "text", "text": "hunter2"}]
			}
		]
	}`
	result := jiraExtractADFText(json.RawMessage(input))
	// Should NOT be "passwordhunter2" - must have separator
	assert.NotEqual(t, "passwordhunter2", result)
	assert.Contains(t, result, "password")
	assert.Contains(t, result, "hunter2")
}

func TestJiraEnumerator_RejectsInsecureHTTP(t *testing.T) {
	_, err := NewJiraEnumerator(JiraConfig{
		Token:   "test-token",
		BaseURL: "http://example.com",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "plaintext HTTP")
}

func TestJiraEnumerator_AllowsInsecureHTTP(t *testing.T) {
	e, err := NewJiraEnumerator(JiraConfig{
		Token:             "test-token",
		BaseURL:           "http://example.com",
		AllowInsecureHTTP: true,
	})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestJiraSanitizeProjectKey(t *testing.T) {
	tests := []struct {
		key     string
		wantErr bool
	}{
		{"DEV", false},
		{"OPS", false},
		{"MY_PROJECT", false},
		{"A1", false},
		{"1NVALID", true},   // starts with digit
		{"NO SPACE", true},  // contains space
		{"INJ;ECT", true},   // contains semicolon
		{"DROP\"TABLE", true}, // contains quote
		{"", true},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			result, err := jiraSanitizeProjectKey(tt.key)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.key, result)
			}
		})
	}
}

// testJiraEnumerator creates a JiraEnumerator pointing at a test server.
// Sets apiBase directly to bypass version detection in tests.
func testJiraEnumerator(t *testing.T, serverURL string) *JiraEnumerator {
	t.Helper()
	e, err := NewJiraEnumerator(JiraConfig{
		Token:     "test-token",
		BaseURL:   "https://example.atlassian.net",
		RateLimit: 1000, // no throttling in tests
	})
	require.NoError(t, err)
	e.apiBase = serverURL // bypass version detection
	return e
}

func TestJiraAPI_BearerAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jiraSearchResponse{
			StartAt:    0,
			MaxResults: 50,
			Total:      0,
			Issues:     nil,
		})
	}))
	defer server.Close()

	e := testJiraEnumerator(t, server.URL)
	total, err := e.jiraEnumerateIssues(context.Background(), "ORDER BY created DESC", func(issue jiraIssueShort) error {
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 0, total)
}

func TestJiraAPI_BasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		assert.True(t, ok, "expected Basic auth")
		assert.Equal(t, "user@example.com", user)
		assert.Equal(t, "test-token", pass)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jiraSearchResponse{
			StartAt:    0,
			MaxResults: 50,
			Total:      0,
			Issues:     nil,
		})
	}))
	defer server.Close()

	e := testJiraEnumerator(t, server.URL)
	e.config.Username = "user@example.com"
	total, err := e.jiraEnumerateIssues(context.Background(), "ORDER BY created DESC", func(issue jiraIssueShort) error {
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 0, total)
}

func TestJiraAPI_RateLimitRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jiraSearchResponse{
			StartAt:    0,
			MaxResults: 50,
			Total:      1,
			Issues: []jiraIssueShort{
				{Key: "DEV-1"},
			},
		})
	}))
	defer server.Close()

	e := testJiraEnumerator(t, server.URL)
	var count int
	_, err := e.jiraEnumerateIssues(context.Background(), "ORDER BY created DESC", func(issue jiraIssueShort) error {
		count++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 2, attempts, "should have retried after 429")
	assert.Equal(t, 1, count)
}

func TestJiraAPI_RetryAfterHeader(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jiraSearchResponse{
			Total:  0,
			Issues: nil,
		})
	}))
	defer server.Close()

	e := testJiraEnumerator(t, server.URL)
	_, err := e.jiraEnumerateIssues(context.Background(), "ORDER BY created DESC", func(issue jiraIssueShort) error {
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 2, attempts, "should retry respecting Retry-After")
}

func TestJiraDetectAPIVersion_V3(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/rest/api/3/serverInfo") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"baseUrl":"https://example.atlassian.net","version":"9.0.0"}`))
			return
		}
		http.Error(w, "not found", 404)
	}))
	defer server.Close()

	e, err := NewJiraEnumerator(JiraConfig{
		Token:             "test-token",
		BaseURL:           server.URL,
		AllowInsecureHTTP: true,
		RateLimit:         1000,
	})
	require.NoError(t, err)

	err = e.detectAPIVersion(context.Background())
	require.NoError(t, err)
	assert.Contains(t, e.apiBase, "/rest/api/3")
}

func TestJiraDetectAPIVersion_V2Fallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/rest/api/3/serverInfo") {
			http.Error(w, "not found", 404)
			return
		}
		if strings.Contains(r.URL.Path, "/rest/api/2/serverInfo") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"baseUrl":"https://jira.internal","version":"8.20.0"}`))
			return
		}
		http.Error(w, "not found", 404)
	}))
	defer server.Close()

	e, err := NewJiraEnumerator(JiraConfig{
		Token:             "test-token",
		BaseURL:           server.URL,
		AllowInsecureHTTP: true,
		RateLimit:         1000,
	})
	require.NoError(t, err)

	err = e.detectAPIVersion(context.Background())
	require.NoError(t, err)
	assert.Contains(t, e.apiBase, "/rest/api/2")
}

func TestJiraDetectAPIVersion_BothFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", 404)
	}))
	defer server.Close()

	e, err := NewJiraEnumerator(JiraConfig{
		Token:             "test-token",
		BaseURL:           server.URL,
		AllowInsecureHTTP: true,
		RateLimit:         1000,
	})
	require.NoError(t, err)

	err = e.detectAPIVersion(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not detect")
}

func TestJiraEnumerate_FullIntegration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case strings.HasSuffix(path, "/search"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"startAt":    0,
				"maxResults": 50,
				"total":      2,
				"issues": []map[string]interface{}{
					{
						"key": "DEV-101",
						"fields": map[string]interface{}{
							"summary": "Setup credentials",
							"project": map[string]interface{}{
								"key":  "DEV",
								"name": "Development",
							},
							"description": nil,
							"created":     "2026-01-15T10:00:00.000+0000",
						},
						"renderedFields": map[string]interface{}{
							"description": "<p>API_KEY=sk_live_abc123</p>",
						},
					},
					{
						"key": "OPS-42",
						"fields": map[string]interface{}{
							"summary": "Deploy config",
							"project": map[string]interface{}{
								"key":  "OPS",
								"name": "Operations",
							},
							"description": nil,
							"created":     "2026-01-14T09:00:00.000+0000",
						},
						"renderedFields": map[string]interface{}{
							"description": "<p>Deploy notes here</p>",
						},
					},
				},
			})

		case strings.Contains(path, "/comment"):
			if strings.Contains(path, "DEV-101") {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"startAt":    0,
					"maxResults": 50,
					"total":      1,
					"comments": []map[string]interface{}{
						{
							"author": map[string]interface{}{
								"displayName": "admin",
							},
							"renderedBody": "<p>Updated the key to prod</p>",
							"body":         nil,
						},
					},
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"startAt":    0,
					"maxResults": 50,
					"total":      0,
					"comments":   []interface{}{},
				})
			}

		default:
			http.Error(w, "unexpected request: "+path, http.StatusBadRequest)
		}
	}))
	defer server.Close()

	e := testJiraEnumerator(t, server.URL)

	var blobs []string
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, string(content))
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, blobs, 2, "expected 2 issues")

	// Verify first issue blob content
	assert.Contains(t, blobs[0], "Key: DEV-101")
	assert.Contains(t, blobs[0], "Summary: Setup credentials")
	assert.Contains(t, blobs[0], "Project: DEV")
	assert.Contains(t, blobs[0], "API_KEY=sk_live_abc123")
	assert.Contains(t, blobs[0], "[admin]:")
	assert.Contains(t, blobs[0], "Updated the key to prod")

	// Verify second issue blob content
	assert.Contains(t, blobs[1], "Key: OPS-42")
	assert.Contains(t, blobs[1], "Summary: Deploy config")
	assert.Contains(t, blobs[1], "Deploy notes here")
	assert.NotContains(t, blobs[1], "--- Comments ---")
}

func TestJiraEnumerate_StreamsPerPage(t *testing.T) {
	// Verify issues are yielded per-page, not all at once
	pageRequests := 0
	callbackCalls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(r.URL.Path, "/comment") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"startAt": 0, "maxResults": 50, "total": 0,
				"comments": []interface{}{},
			})
			return
		}

		pageRequests++
		startAt := 0
		if q := r.URL.Query().Get("startAt"); q != "" {
			startAt, _ = strconv.Atoi(q)
		}

		if startAt == 0 {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"startAt": 0, "maxResults": 1, "total": 2,
				"issues": []map[string]interface{}{
					{"key": "P-1", "fields": map[string]interface{}{
						"summary": "Issue 1", "project": map[string]interface{}{"key": "P"}, "created": "2026-01-01T00:00:00.000+0000",
					}, "renderedFields": map[string]interface{}{"description": "desc1"}},
				},
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"startAt": 1, "maxResults": 1, "total": 2,
				"issues": []map[string]interface{}{
					{"key": "P-2", "fields": map[string]interface{}{
						"summary": "Issue 2", "project": map[string]interface{}{"key": "P"}, "created": "2026-01-02T00:00:00.000+0000",
					}, "renderedFields": map[string]interface{}{"description": "desc2"}},
				},
			})
		}
	}))
	defer server.Close()

	e := testJiraEnumerator(t, server.URL)
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		callbackCalls++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 2, callbackCalls, "should yield 2 issues via callback")
	assert.Equal(t, 2, pageRequests, "should have made 2 paginated requests")
}

// Ensure types package is referenced so imports stay tidy.
var _ types.Provenance = types.ExtendedProvenance{}
