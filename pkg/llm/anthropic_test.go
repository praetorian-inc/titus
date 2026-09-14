package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnthropicClient_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/messages", r.URL.Path)
		assert.Equal(t, "test-key", r.Header.Get("x-api-key"))
		assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))

		body, _ := io.ReadAll(r.Body)
		var reqBody map[string]any
		json.Unmarshal(body, &reqBody)
		assert.Equal(t, "claude-haiku-4-5-20251001", reqBody["model"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": `{"status":"valid","confidence":0.9,"reason":"token works"}`},
			},
			"model": "claude-haiku-4-5-20251001",
			"usage": map[string]any{"input_tokens": 100, "output_tokens": 50},
		})
	}))
	defer srv.Close()

	c, err := NewClient("anthropic", "test-key", "claude-haiku-4-5-20251001", WithBaseURL(srv.URL))
	require.NoError(t, err)

	resp, err := c.Complete(context.Background(), &Request{
		System:    "You classify secrets.",
		Messages:  []Message{{Role: "user", Content: "Is this valid?"}},
		MaxTokens: 256,
	})
	require.NoError(t, err)
	assert.Contains(t, resp.Content, "valid")
	assert.Equal(t, 100, resp.Usage.InputTokens)
	assert.Equal(t, 50, resp.Usage.OutputTokens)
}

func TestAnthropicClient_429Retry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			w.Write([]byte(`{"error":{"type":"rate_limit","message":"slow down"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{{"type": "text", "text": "ok"}},
			"model":   "claude-haiku-4-5-20251001",
			"usage":   map[string]any{"input_tokens": 10, "output_tokens": 5},
		})
	}))
	defer srv.Close()

	c, err := NewClient("anthropic", "test-key", "claude-haiku-4-5-20251001", WithBaseURL(srv.URL))
	require.NoError(t, err)
	resp, err := c.Complete(context.Background(), &Request{
		Messages:  []Message{{Role: "user", Content: "test"}},
		MaxTokens: 100,
	})
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Content)
	assert.Equal(t, 2, calls)
}

func TestAnthropicClient_529Retry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(529)
			w.Write([]byte(`{"error":{"type":"overloaded","message":"overloaded"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{{"type": "text", "text": "ok"}},
			"model":   "claude-haiku-4-5-20251001",
			"usage":   map[string]any{"input_tokens": 10, "output_tokens": 5},
		})
	}))
	defer srv.Close()

	c, err := NewClient("anthropic", "test-key", "claude-haiku-4-5-20251001", WithBaseURL(srv.URL))
	require.NoError(t, err)
	resp, err := c.Complete(context.Background(), &Request{
		Messages:  []Message{{Role: "user", Content: "test"}},
		MaxTokens: 100,
	})
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Content)
	assert.Equal(t, 2, calls)
}

func TestAnthropicClient_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":{"type":"authentication_error","message":"invalid key"}}`))
	}))
	defer srv.Close()

	c, err := NewClient("anthropic", "bad-key", "claude-haiku-4-5-20251001", WithBaseURL(srv.URL))
	require.NoError(t, err)
	_, err = c.Complete(context.Background(), &Request{
		Messages:  []Message{{Role: "user", Content: "test"}},
		MaxTokens: 100,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestAnthropicClient_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	c, err := NewClient("anthropic", "test-key", "claude-haiku-4-5-20251001",
		WithBaseURL(srv.URL), WithTimeout(100*time.Millisecond))
	require.NoError(t, err)
	_, err = c.Complete(context.Background(), &Request{
		Messages:  []Message{{Role: "user", Content: "test"}},
		MaxTokens: 100,
	})
	assert.Error(t, err)
}
