package scoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithRetry_429_RetriesOnce(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0") // immediate retry for test speed
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	auth := scorerAuth{} // no auth needed for this test
	resp, err := withRetry(context.Background(), func() (*cachedHTTPResponse, error) {
		return makeHTTPRequest(context.Background(), "GET", srv.URL, nil, "", auth, nil)
	})
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, int32(2), calls.Load(), "should have made exactly 2 calls")
}

func TestWithRetry_5xx_RetriesOnce(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	resp, err := withRetry(context.Background(), func() (*cachedHTTPResponse, error) {
		return makeHTTPRequest(context.Background(), "GET", srv.URL, nil, "", scorerAuth{}, nil)
	})
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, int32(2), calls.Load())
}

func TestWithRetry_429_DoesNotRetryTwice(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(429)
	}))
	defer srv.Close()

	resp, err := withRetry(context.Background(), func() (*cachedHTTPResponse, error) {
		return makeHTTPRequest(context.Background(), "GET", srv.URL, nil, "", scorerAuth{}, nil)
	})
	// After one retry still 429 — should return the 429 resp, no error
	require.NoError(t, err)
	assert.Equal(t, 429, resp.StatusCode)
	assert.Equal(t, int32(2), calls.Load(), "max 2 attempts")
}
