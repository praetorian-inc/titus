package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetryHTTPClient_SuccessNoRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	rc := NewRetryHTTPClient(srv.Client(), nil)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, int32(1), calls.Load())
}

func TestRetryHTTPClient_429RetriesOnce(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	rc := NewRetryHTTPClient(srv.Client(), nil)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, int32(2), calls.Load())
}

func TestRetryHTTPClient_429RetryAfterCapped(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "9999")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	rc := NewRetryHTTPClient(srv.Client(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, int32(2), calls.Load())
}

func TestRetryHTTPClient_5xxRetriesOnce(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	rc := NewRetryHTTPClient(srv.Client(), nil)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, int32(2), calls.Load())
}

func TestRetryHTTPClient_4xxNoRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(401)
	}))
	defer srv.Close()

	rc := NewRetryHTTPClient(srv.Client(), nil)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 401, resp.StatusCode)
	assert.Equal(t, int32(1), calls.Load())
}

func TestRetryHTTPClient_5xxPersistsReturnsLast(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(503)
	}))
	defer srv.Close()

	rc := NewRetryHTTPClient(srv.Client(), nil)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 503, resp.StatusCode)
	assert.Equal(t, int32(2), calls.Load())
}

func TestRetryHTTPClient_BackoffRecordsErrorAndSuccess(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	bc := NewBackoffController(3, 100*time.Millisecond, 1*time.Second)
	rc := NewRetryHTTPClient(srv.Client(), bc)

	bc.RecordError()
	bc.RecordError()
	assert.Equal(t, int64(2), bc.ConsecutiveErrors())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, int64(0), bc.ConsecutiveErrors(), "success should reset backoff")
}
