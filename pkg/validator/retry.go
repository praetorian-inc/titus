package validator

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"
)

// RoundTrip implements http.RoundTripper so a RetryHTTPClient can be
// installed as a client's Transport (see WrapHTTPClient).
func (c *RetryHTTPClient) RoundTrip(req *http.Request) (*http.Response, error) {
	return c.Do(req)
}

// WrapHTTPClient returns a shallow copy of inner whose Transport retries
// transient failures via RetryHTTPClient, coordinating with backoff when
// non-nil. inner is not mutated. A nil inner uses http.DefaultClient.
func WrapHTTPClient(inner *http.Client, backoff *BackoffController) *http.Client {
	if inner == nil {
		inner = http.DefaultClient
	}
	if _, ok := inner.Transport.(*RetryHTTPClient); ok {
		return inner
	}
	wrapped := *inner
	wrapped.Transport = NewRetryHTTPClient(inner, backoff)
	return &wrapped
}

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
	rt      http.RoundTripper
	backoff *BackoffController
}

// NewRetryHTTPClient creates a RetryHTTPClient wrapping inner's Transport (or
// http.DefaultTransport if nil), optionally coordinating with backoff (may be
// nil to disable adaptive backoff).
func NewRetryHTTPClient(inner *http.Client, backoff *BackoffController) *RetryHTTPClient {
	var rt http.RoundTripper
	if inner != nil {
		rt = inner.Transport
	}
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &RetryHTTPClient{rt: rt, backoff: backoff}
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
		if attempt > 0 {
			if lastResp != nil {
				_, _ = io.Copy(io.Discard, lastResp.Body)
				_ = lastResp.Body.Close()
				lastResp = nil
			}
			if !canReplay(req) {
				break
			}
			if err := rewindBody(req); err != nil {
				if lastErr != nil {
					return nil, lastErr
				}
				return nil, err
			}
		}

		// Validators intentionally contact caller-supplied endpoints; this
		// wrapper replays the request it was given.
		resp, err := c.rt.RoundTrip(req) //nolint:gosec // G107: URL comes from the validator request, not from this wrapper.
		if err != nil {
			if c.backoff != nil {
				c.backoff.RecordError()
			}
			lastErr = err
			lastResp = nil
			if attempt < retryMaxAttempts-1 {
				if waitErr := c.waitForRetry(req.Context(), retryBackoffDelay); waitErr != nil {
					return nil, waitErr
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
			if attempt < retryMaxAttempts-1 && canReplay(req) {
				delay := parseRetryAfter(resp.Header.Get("Retry-After"))
				if sleepErr := sleepCtx(req.Context(), delay); sleepErr != nil {
					return resp, sleepErr
				}
				continue
			}
		case resp.StatusCode >= 500:
			if c.backoff != nil {
				c.backoff.RecordError()
			}
			if attempt < retryMaxAttempts-1 && canReplay(req) {
				if sleepErr := sleepCtx(req.Context(), retryBackoffDelay); sleepErr != nil {
					return resp, sleepErr
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
		return lastResp, nil
	}
	return nil, lastErr
}

func canReplay(req *http.Request) bool {
	return req.Body == nil || req.GetBody != nil
}

func rewindBody(req *http.Request) error {
	if req.GetBody == nil {
		return nil
	}
	body, err := req.GetBody()
	if err != nil {
		return err
	}
	req.Body = body
	return nil
}

func (c *RetryHTTPClient) waitForRetry(ctx context.Context, d time.Duration) error {
	if c.backoff != nil {
		return c.backoff.Wait(ctx)
	}
	return sleepCtx(ctx, d)
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
