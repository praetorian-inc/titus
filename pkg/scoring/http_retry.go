package scoring

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

const maxRetryAfter = 30 * time.Second
const serverErrorBackoff = 1 * time.Second

// withRetry wraps a single HTTP call with the M3 retry policy:
//   - 429: retry once after Retry-After (capped at 30s)
//   - 5xx: retry once after 1s
//   - all other errors/codes: return immediately, no retry
//
// The function does NOT handle context cancellation — the context passed to
// makeHTTPRequest inside fn already does that.
func withRetry(ctx context.Context, fn func() (*cachedHTTPResponse, error)) (*cachedHTTPResponse, error) {
	resp, err := fn()
	if err != nil || resp == nil {
		return resp, err
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		delay := parseRetryAfter(resp.Headers["retry-after"])
		if delay > maxRetryAfter {
			delay = maxRetryAfter
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return fn()

	case resp.StatusCode >= 500 && resp.StatusCode < 600:
		select {
		case <-time.After(serverErrorBackoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return fn()
	}

	return resp, nil
}

// parseRetryAfter parses the Retry-After header value (seconds integer).
// Returns 0 on parse failure.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs < 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}
