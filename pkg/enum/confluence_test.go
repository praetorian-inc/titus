package enum

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfluenceEnumerator_Construction(t *testing.T) {
	e, err := NewConfluenceEnumerator(ConfluenceConfig{
		Token:   "test-token",
		BaseURL: "https://example.atlassian.net/wiki",
	})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestConfluenceEnumerator_RequiresToken(t *testing.T) {
	_, err := NewConfluenceEnumerator(ConfluenceConfig{
		BaseURL: "https://example.atlassian.net/wiki",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestConfluenceEnumerator_RequiresBaseURL(t *testing.T) {
	_, err := NewConfluenceEnumerator(ConfluenceConfig{
		Token: "test-token",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "base URL")
}

func TestConfluenceEnumerator_Interface(t *testing.T) {
	e, err := NewConfluenceEnumerator(ConfluenceConfig{
		Token:   "test-token",
		BaseURL: "https://example.atlassian.net/wiki",
	})
	require.NoError(t, err)
	var _ Enumerator = e
}

// Compile-time assertion that *ConfluenceEnumerator satisfies Enumerator.
var _ Enumerator = (*ConfluenceEnumerator)(nil)

// Ensure types package is referenced so imports stay tidy.
var _ types.Provenance = types.ExtendedProvenance{}

func TestConfluenceProvenance(t *testing.T) {
	prov := confluenceProvenance("page", "12345", "My Page", "https://example.atlassian.net/wiki/display/DEV/My+Page", "DEV")
	assert.Equal(t, "extended", prov.Kind())
	assert.Equal(t, "confluence", prov.Payload["source"])
	assert.Equal(t, "page", prov.Payload["entityType"])
	assert.Equal(t, "12345", prov.Payload["identifier"])
	assert.Equal(t, "My Page", prov.Payload["title"])
	assert.Equal(t, "https://example.atlassian.net/wiki/display/DEV/My+Page", prov.Payload["url"])
	assert.Equal(t, "DEV", prov.Payload["space"])
}

func TestConfluenceBuildPageBlob(t *testing.T) {
	comments := []cfComment{
		{Author: "alice", Body: "First comment"},
		{Author: "bob", Body: "Second comment"},
	}
	blob := cfBuildPageBlob("Test Page", "https://example.atlassian.net/wiki/display/DEV/Test+Page", "DEV", "page", "Page body content.", comments)

	content := string(blob)
	assert.Contains(t, content, "Title: Test Page")
	assert.Contains(t, content, "URL: https://example.atlassian.net/wiki/display/DEV/Test+Page")
	assert.Contains(t, content, "Space: DEV")
	assert.Contains(t, content, "Type: page")
	assert.Contains(t, content, "Page body content.")
	assert.Contains(t, content, "[alice]:")
	assert.Contains(t, content, "First comment")
	assert.Contains(t, content, "[bob]:")
	assert.Contains(t, content, "Second comment")
}

func TestConfluenceStripHTML(t *testing.T) {
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
			name:     "CDATA in code macro",
			input:    `<ac:structured-macro ac:name="code"><ac:plain-text-body><![CDATA[API_KEY=secret123]]></ac:plain-text-body></ac:structured-macro>`,
			expected: "API_KEY=secret123",
		},
		{
			name:     "CDATA with HTML around it",
			input:    `<p>Config:</p><ac:plain-text-body><![CDATA[DB_PASS=hunter2]]></ac:plain-text-body><p>End</p>`,
			expected: "Config:DB_PASS=hunter2End",
		},
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, cfStripHTML(tt.input))
		})
	}
}

// testConfluenceEnumerator creates a ConfluenceEnumerator pointing at a test server.
func testConfluenceEnumerator(t *testing.T, url string) *ConfluenceEnumerator {
	t.Helper()
	e, err := NewConfluenceEnumerator(ConfluenceConfig{
		Token:     "test-token",
		BaseURL:   "https://example.atlassian.net/wiki",
		RateLimit: 1000, // no throttling in tests
	})
	require.NoError(t, err)
	e.apiBase = url
	return e
}

func TestConfluenceAPI_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer")
		assert.Contains(t, r.URL.Path, "/space")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"results": []map[string]interface{}{
				{"key": "DEV", "name": "Development"},
				{"key": "OPS", "name": "Operations"},
			},
			"start": 0,
			"limit": 25,
			"size":  2,
			"_links": map[string]interface{}{
				"next": "",
			},
		})
	}))
	defer server.Close()

	e := testConfluenceEnumerator(t, server.URL)
	spaces, err := e.cfFetchSpaces(context.Background())
	require.NoError(t, err)
	assert.Len(t, spaces, 2)
	assert.Equal(t, "DEV", spaces[0].Key)
	assert.Equal(t, "OPS", spaces[1].Key)
}

func TestConfluenceEnumerator_RejectsInsecureHTTP(t *testing.T) {
	_, err := NewConfluenceEnumerator(ConfluenceConfig{
		Token:   "test-token",
		BaseURL: "http://example.com/wiki",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "plaintext HTTP")
}

func TestConfluenceEnumerator_AllowsInsecureHTTP(t *testing.T) {
	e, err := NewConfluenceEnumerator(ConfluenceConfig{
		Token:             "test-token",
		BaseURL:           "http://example.com/wiki",
		AllowInsecureHTTP: true,
	})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestConfluenceAPI_BasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		assert.True(t, ok, "expected Basic auth")
		assert.Equal(t, "user@example.com", user)
		assert.Equal(t, "test-token", pass)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"results": []map[string]interface{}{},
			"start":   0,
			"limit":   25,
			"size":    0,
			"_links":  map[string]interface{}{"next": ""},
		})
	}))
	defer server.Close()

	e := testConfluenceEnumerator(t, server.URL)
	e.config.Username = "user@example.com"
	spaces, err := e.cfFetchSpaces(context.Background())
	require.NoError(t, err)
	assert.Len(t, spaces, 0)
}

func TestConfluenceAPI_RateLimitRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(429)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"results": []map[string]interface{}{
				{"key": "DEV", "name": "Development"},
			},
			"start":  0,
			"limit":  25,
			"size":   1,
			"_links": map[string]interface{}{"next": ""},
		})
	}))
	defer server.Close()

	e := testConfluenceEnumerator(t, server.URL)
	spaces, err := e.cfFetchSpaces(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, attempts)
	assert.Len(t, spaces, 1)
}

func TestConfluenceEnumerate_FullIntegration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		query := r.URL.Query()

		switch {
		case strings.HasSuffix(path, "/space"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"results": []map[string]interface{}{
					{"key": "DEV", "name": "Development"},
				},
				"start":  0,
				"limit":  25,
				"size":   1,
				"_links": map[string]interface{}{"next": ""},
			})

		case strings.HasSuffix(path, "/content") && query.Get("type") == "page":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"results": []map[string]interface{}{
					{
						"id":    "101",
						"title": "Setup Guide",
						"type":  "page",
						"body": map[string]interface{}{
							"storage": map[string]interface{}{
								"value": "<p>API_KEY=sk_live_abc123</p>",
							},
						},
						"_links": map[string]interface{}{
							"webui": "/display/DEV/Setup+Guide",
						},
					},
				},
				"start":  0,
				"limit":  25,
				"size":   1,
				"_links": map[string]interface{}{"next": ""},
			})

		case strings.HasSuffix(path, "/content") && query.Get("type") == "blogpost":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"results": []map[string]interface{}{
					{
						"id":    "201",
						"title": "Launch Day",
						"type":  "blogpost",
						"body": map[string]interface{}{
							"storage": map[string]interface{}{
								"value": "<p>Blog content here</p>",
							},
						},
						"_links": map[string]interface{}{
							"webui": "/display/DEV/Launch+Day",
						},
					},
				},
				"start":  0,
				"limit":  25,
				"size":   1,
				"_links": map[string]interface{}{"next": ""},
			})

		case strings.Contains(path, "/child/comment"):
			if strings.Contains(path, "/101/") {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"results": []map[string]interface{}{
						{
							"id":    "c1",
							"title": "admin",
							"type":  "comment",
							"body": map[string]interface{}{
								"storage": map[string]interface{}{
									"value": "<p>Updated the key</p>",
								},
							},
							"_links": map[string]interface{}{"webui": ""},
						},
					},
					"start":  0,
					"limit":  25,
					"size":   1,
					"_links": map[string]interface{}{"next": ""},
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"results": []interface{}{},
					"start":   0,
					"limit":   25,
					"size":    0,
					"_links":  map[string]interface{}{"next": ""},
				})
			}

		default:
			http.Error(w, "unexpected request: "+path, http.StatusBadRequest)
		}
	}))
	defer server.Close()

	e := testConfluenceEnumerator(t, server.URL)

	var blobs []string
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, string(content))
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, blobs, 2, "expected 1 page + 1 blogpost")

	// Verify page blob content
	assert.Contains(t, blobs[0], "Title: Setup Guide")
	assert.Contains(t, blobs[0], "Space: DEV")
	assert.Contains(t, blobs[0], "Type: page")
	assert.Contains(t, blobs[0], "API_KEY=sk_live_abc123")
	assert.Contains(t, blobs[0], "[admin]:")
	assert.Contains(t, blobs[0], "Updated the key")

	// Verify blogpost blob content
	assert.Contains(t, blobs[1], "Title: Launch Day")
	assert.Contains(t, blobs[1], "Type: blogpost")
	assert.Contains(t, blobs[1], "Blog content here")
}
