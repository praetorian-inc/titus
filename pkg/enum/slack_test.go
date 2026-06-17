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

func TestSlackBuildMessageBlob(t *testing.T) {
	msg := slMessage{
		User: "U001",
		TS:   "1234567890.000100",
		Text: "Hello world",
		Attachments: []slAttachment{
			{Text: "attached content", Fallback: "fallback text"},
		},
	}
	replies := []slMessage{
		{User: "U002", TS: "1234567890.000200", Text: "API_KEY=sk_live_abc123"},
	}
	blob := slBuildMessageBlob("general", "https://app.slack.com/client/C12345", "C12345", msg, replies)

	content := string(blob)
	assert.Contains(t, content, "Channel: general")
	assert.Contains(t, content, "URL: https://app.slack.com/client/C12345")
	assert.Contains(t, content, "ID: C12345")
	assert.Contains(t, content, "---")
	assert.Contains(t, content, "[U001] [1234567890.000100]: Hello world")
	assert.Contains(t, content, "[attachment]: attached content")
	assert.Contains(t, content, "[attachment-fallback]: fallback text")
	assert.Contains(t, content, "[U002] [1234567890.000200]: API_KEY=sk_live_abc123")
}

func TestSlackBuildMessageBlob_NoAttachments(t *testing.T) {
	msg := slMessage{User: "U001", TS: "1000.0001", Text: "plain message"}
	blob := slBuildMessageBlob("general", "https://app.slack.com/client/C12345", "C12345", msg, nil)
	content := string(blob)
	assert.Contains(t, content, "[U001] [1000.0001]: plain message")
	assert.NotContains(t, content, "[attachment]")
}

func TestSlackBuildMessageBlob_AttachmentSameTextAndFallback(t *testing.T) {
	msg := slMessage{
		User: "U001",
		TS:   "1000.0001",
		Text: "msg",
		Attachments: []slAttachment{
			{Text: "same", Fallback: "same"},
		},
	}
	blob := slBuildMessageBlob("general", "https://app.slack.com/client/C12345", "C12345", msg, nil)
	content := string(blob)
	assert.Contains(t, content, "[attachment]: same")
	// Fallback should be omitted when it matches text
	assert.NotContains(t, content, "[attachment-fallback]")
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

func TestSlackPaginationCursorURLEncoded(t *testing.T) {
	// Slack cursors are base64 and may contain +, /, = characters.
	// Verify they are URL-encoded in the request.
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")

		if callCount == 1 {
			// First page: return a cursor with special characters
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"channels": []map[string]interface{}{
					{"id": "C001", "name": "chan1", "is_channel": true},
				},
				"response_metadata": map[string]interface{}{
					"next_cursor": "dXNlcjpV+MDM/Nw==",
				},
			})
			return
		}

		// Second page: verify cursor was URL-encoded
		cursorParam := r.URL.Query().Get("cursor")
		assert.Equal(t, "dXNlcjpV+MDM/Nw==", cursorParam, "cursor should be properly decoded from URL-encoded form")

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true,
			"channels": []map[string]interface{}{
				{"id": "C002", "name": "chan2", "is_channel": true},
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
	assert.Equal(t, 2, callCount)
	require.Len(t, conversations, 2)
}

func TestSlackEnumerate_NotInChannelSkipped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case strings.Contains(path, "conversations.list"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"channels": []map[string]interface{}{
					{"id": "C_INACCESSIBLE", "name": "private-chan", "is_channel": true},
					{"id": "C_OK", "name": "public-chan", "is_channel": true},
				},
				"response_metadata": map[string]interface{}{
					"next_cursor": "",
				},
			})

		case strings.Contains(path, "conversations.history"):
			channelID := r.URL.Query().Get("channel")
			if channelID == "C_INACCESSIBLE" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"ok":    false,
					"error": "not_in_channel",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"messages": []map[string]interface{}{
					{"user": "U001", "text": "hello from public", "ts": "1000.0001"},
				},
				"has_more": false,
				"response_metadata": map[string]interface{}{"next_cursor": ""},
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
	require.NoError(t, err, "not_in_channel should be skipped, not abort the scan")
	require.Len(t, blobs, 1, "should have one blob from the accessible channel")
	assert.Contains(t, blobs[0], "hello from public")
}

func TestSlackEnumerate_FullIntegration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case strings.Contains(path, "conversations.list"):
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

		case strings.Contains(path, "conversations.replies"):
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

		case strings.Contains(path, "conversations.history"):
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
	// Per-message blobs: one for the thread parent (with reply), one for the standalone
	require.Len(t, blobs, 2)

	// First blob: thread parent with its reply
	assert.Contains(t, blobs[0], "Channel: engineering")
	assert.Contains(t, blobs[0], "thread parent")
	assert.Contains(t, blobs[0], "SECRET_KEY=abc123")

	// Second blob: standalone message
	assert.Contains(t, blobs[1], "Channel: engineering")
	assert.Contains(t, blobs[1], "PASSWORD=hunter2")
}

func TestSlackEnumerate_Attachments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case strings.Contains(path, "conversations.list"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"channels": []map[string]interface{}{
					{"id": "C001", "name": "general", "is_channel": true},
				},
				"response_metadata": map[string]interface{}{"next_cursor": ""},
			})

		case strings.Contains(path, "conversations.history"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"messages": []map[string]interface{}{
					{
						"user": "U001",
						"text": "check this out",
						"ts":   "1000.0001",
						"attachments": []map[string]interface{}{
							{"text": "SECRET=attached_secret_value", "fallback": "attachment fallback"},
						},
					},
				},
				"has_more": false,
				"response_metadata": map[string]interface{}{"next_cursor": ""},
			})

		default:
			http.Error(w, "unexpected: "+path, http.StatusBadRequest)
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
	assert.Contains(t, blobs[0], "SECRET=attached_secret_value")
	assert.Contains(t, blobs[0], "attachment fallback")
}

func TestSlackIsAccessError(t *testing.T) {
	assert.True(t, slIsAccessError("conversations.history error: not_in_channel"))
	assert.True(t, slIsAccessError("channel_not_found"))
	assert.True(t, slIsAccessError("account_inactive"))
	assert.True(t, slIsAccessError("is_archived"))
	assert.True(t, slIsAccessError("missing_scope"))
	assert.False(t, slIsAccessError("some other error"))
	assert.False(t, slIsAccessError(""))
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
