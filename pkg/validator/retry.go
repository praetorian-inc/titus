package validator

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	retryMaxAttempts  = 2
	retryBackoffDelay = 1 * time.Second
	retryAfterCap     = 30 * time.Second
)

// RetryHTTPClient wraps an *http.Client with single-retry logic for
// transient failures: 429 (respecting Retry-After, capped), 5xx responses,
// and connection errors. It is a drop-in replacement for *http.Client.Do.
// An optional BackoffController records errors/successes and is consulted
// before each attempt to apply adaptive backoff across concurrent callers.
type RetryHTTPClient struct {
	inner   *http.Client
	backoff *BackoffController
}

// NewRetryHTTPClient creates a RetryHTTPClient wrapping inner (or
// http.DefaultClient if nil), optionally coordinating with backoff (may be
// nil to disable adaptive backoff).
func NewRetryHTTPClient(inner *http.Client, backoff *BackoffController) *RetryHTTPClient {
	if inner == nil {
		inner = http.DefaultClient
	}
	return &RetryHTTPClient{inner: inner, backoff: backoff}
}

// Do executes req, retrying once on 429/5xx/connection error. On success
// (2xx/3xx) or a non-retryable status (4xx other than 429), the response is
// returned immediately. If retries are exhausted, the last response (or
// error) is returned.
func (c *RetryHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if c.backoff != nil {
		if err := c.backoff.Wait(req.Context()); err != nil {
			return nil, err
		}
	}

	var lastResp *http.Response
	var lastErr error

	for attempt := 0; attempt < retryMaxAttempts; attempt++ {
		if attempt > 0 && lastResp != nil {
			_, _ = io.Copy(io.Discard, lastResp.Body)
			_ = lastResp.Body.Close()
			lastResp = nil
		}

		resp, err := c.inner.Do(req)
		if err != nil {
			if c.backoff != nil {
				c.backoff.RecordError()
			}
			lastErr = err
			lastResp = nil
			if attempt < retryMaxAttempts-1 {
				if c.backoff != nil {
					if waitErr := c.backoff.Wait(req.Context()); waitErr != nil {
						return nil, waitErr
					}
				} else {
					if sleepErr := sleepCtx(req.Context(), retryBackoffDelay); sleepErr != nil {
						return nil, sleepErr
					}
				}
			}
			continue
		}

		lastResp = resp
		lastErr = nil

		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			if c.backoff != nil {
				c.backoff.RecordError()
			}
			if attempt < retryMaxAttempts-1 {
				delay := parseRetryAfter(resp.Header.Get("Retry-After"))
				if sleepErr := sleepCtx(req.Context(), delay); sleepErr != nil {
					return resp, nil
				}
				continue
			}
		case resp.StatusCode >= 500:
			if c.backoff != nil {
				c.backoff.RecordError()
			}
			if attempt < retryMaxAttempts-1 {
				if sleepErr := sleepCtx(req.Context(), retryBackoffDelay); sleepErr != nil {
					return resp, nil
				}
				continue
			}
		default:
			if c.backoff != nil {
				c.backoff.RecordSuccess()
			}
			return resp, nil
		}
	}

	if lastResp != nil {
		if c.backoff != nil {
			c.backoff.RecordSuccess()
		}
		return lastResp, nil
	}
	return nil, lastErr
}

// parseRetryAfter parses an HTTP Retry-After header value (seconds form)
// into a duration, capped at retryAfterCap. An empty, invalid, or negative
// value falls back to retryBackoffDelay.
func parseRetryAfter(val string) time.Duration {
	if val == "" {
		return retryBackoffDelay
	}
	secs, err := strconv.Atoi(val)
	if err != nil || secs < 0 {
		return retryBackoffDelay
	}
	d := time.Duration(secs) * time.Second
	if d > retryAfterCap {
		d = retryAfterCap
	}
	return d
}

// sleepCtx sleeps for d, or returns ctx.Err() early if ctx is done first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
