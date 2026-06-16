package enum

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSlackEnumerator_Construction(t *testing.T) {
	e, err := NewSlackEnumerator(SlackConfig{Token: "xoxb-test-token"})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestSlackEnumerator_RequiresToken(t *testing.T) {
	_, err := NewSlackEnumerator(SlackConfig{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestSlackEnumerator_Interface(t *testing.T) {
	e, err := NewSlackEnumerator(SlackConfig{Token: "xoxb-test-token"})
	require.NoError(t, err)
	var _ Enumerator = e
}

func TestSlackProvenance(t *testing.T) {
	prov := slackProvenance("general", "C12345", "https://app.slack.com/client/C12345", "https://app.slack.com/client/C12345")
	assert.Equal(t, "extended", prov.Kind())
	assert.Equal(t, "slack", prov.Payload["source"])
	assert.Equal(t, "general", prov.Payload["channel"])
	assert.Equal(t, "C12345", prov.Payload["channelID"])
	assert.Equal(t, "https://app.slack.com/client/C12345", prov.Payload["url"])
	assert.Equal(t, "https://app.slack.com/client/C12345", prov.Payload["path"])
}

// Compile-time assertion that *SlackEnumerator satisfies Enumerator.
var _ Enumerator = (*SlackEnumerator)(nil)

// Ensure types package is referenced so imports stay tidy.
var _ types.Provenance = types.ExtendedProvenance{}

func TestSlackBuildChannelBlob(t *testing.T) {
	messages := []slMessage{
		{User: "U001", TS: "1234567890.000100", Text: "Hello world"},
		{User: "U002", TS: "1234567890.000200", Text: "API_KEY=sk_live_abc123"},
	}
	blob := slBuildChannelBlob("general", "https://app.slack.com/client/C12345", "C12345", messages)

	content := string(blob)
	assert.Contains(t, content, "Channel: general")
	assert.Contains(t, content, "URL: https://app.slack.com/client/C12345")
	assert.Contains(t, content, "ID: C12345")
	assert.Contains(t, content, "---")
	assert.Contains(t, content, "[U001] [1234567890.000100]: Hello world")
	assert.Contains(t, content, "[U002] [1234567890.000200]: API_KEY=sk_live_abc123")
}

func TestSlackAPI_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "Bearer xoxb-test-token", r.Header.Get("Authorization"))
		assert.Contains(t, r.URL.Path, "conversations.list")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true,
			"channels": []map[string]interface{}{
				{
					"id":          "C12345",
					"name":        "general",
					"is_channel":  true,
					"is_archived": false,
				},
			},
			"response_metadata": map[string]interface{}{
				"next_cursor": "",
			},
		})
	}))
	defer server.Close()

	e := testSlackEnumerator(t, server.URL+"/")

	conversations, err := e.slListConversations(context.Background())
	require.NoError(t, err)
	require.Len(t, conversations, 1)
	assert.Equal(t, "C12345", conversations[0].ID)
	assert.Equal(t, "general", conversations[0].Name)
}

func TestSlackAPI_RateLimitRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":    false,
				"error": "ratelimited",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true,
			"channels": []map[string]interface{}{
				{
					"id":         "C12345",
					"name":       "general",
					"is_channel": true,
				},
			},
			"response_metadata": map[string]interface{}{
				"next_cursor": "",
			},
		})
	}))
	defer server.Close()

	e := testSlackEnumerator(t, server.URL+"/")

	conversations, err := e.slListConversations(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, attempts)
	require.Len(t, conversations, 1)
	assert.Equal(t, "general", conversations[0].Name)
}

func TestSlackEnumerate_FullIntegration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case pathContains(path, "conversations.list"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"channels": []map[string]interface{}{
					{
						"id":         "C12345",
						"name":       "engineering",
						"is_channel": true,
					},
				},
				"response_metadata": map[string]interface{}{
					"next_cursor": "",
				},
			})

		case pathContains(path, "conversations.replies"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"messages": []map[string]interface{}{
					{
						"user": "U001",
						"text": "thread parent",
						"ts":   "1000.0001",
					},
					{
						"user": "U002",
						"text": "thread reply with SECRET_KEY=abc123",
						"ts":   "1000.0002",
					},
				},
				"has_more": false,
				"response_metadata": map[string]interface{}{
					"next_cursor": "",
				},
			})

		case pathContains(path, "conversations.history"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"messages": []map[string]interface{}{
					{
						"user":        "U001",
						"text":        "thread parent",
						"ts":          "1000.0001",
						"reply_count": 1,
					},
					{
						"user": "U003",
						"text": "standalone message with PASSWORD=hunter2",
						"ts":   "1000.0003",
					},
				},
				"has_more": false,
				"response_metadata": map[string]interface{}{
					"next_cursor": "",
				},
			})

		default:
			http.Error(w, "unexpected endpoint: "+path, http.StatusBadRequest)
		}
	}))
	defer server.Close()

	e := testSlackEnumerator(t, server.URL+"/")

	var blobs []string
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, string(content))
		return nil
	})
	require.NoError(t, err)
	require.Len(t, blobs, 1)

	content := blobs[0]
	assert.Contains(t, content, "Channel: engineering")
	assert.Contains(t, content, "ID: C12345")
	assert.Contains(t, content, "thread parent")
	assert.Contains(t, content, "SECRET_KEY=abc123")
	assert.Contains(t, content, "PASSWORD=hunter2")
}

// pathContains checks if the URL path contains the given substring.
func pathContains(path, sub string) bool {
	return len(path) >= len(sub) && contains(path, sub)
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// testSlackEnumerator creates a SlackEnumerator pointing at a test server.
func testSlackEnumerator(t *testing.T, url string) *SlackEnumerator {
	t.Helper()
	e, err := NewSlackEnumerator(SlackConfig{
		Token:     "xoxb-test-token",
		RateLimit: 1000, // no throttling in tests
	})
	require.NoError(t, err)
	e.baseURL = url
	return e
}
