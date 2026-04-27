package scoring

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/titus/pkg/types"
)

// firesWhenLeaf is the interface for a single fires_when: condition.
// It is evaluated against an already-fetched cachedHTTPResponse.
type firesWhenLeaf interface {
	evaluate(resp *cachedHTTPResponse) (bool, error)
}

// httpCondition is a dynamic Condition that makes an HTTP call then delegates
// to a firesWhenLeaf for the actual decision. It implements Condition and
// therefore satisfies the M3 Condition interface (with context).
type httpCondition struct {
	method    string
	url       string       // may contain {{group}} placeholders
	headers   []scorerHeader
	body      string
	auth      scorerAuth
	firesWhen firesWhenLeaf
	cache     *httpResponseCache // per-scan cache; shared via engine
}

// Evaluate executes the HTTP call (or uses cache) then applies firesWhen.
func (c *httpCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	if m == nil {
		return false, nil
	}

	// Resolve secret bytes for cache key
	secretBytes := m.NamedGroups[c.auth.SecretGroup]
	expandedURL := substituteVarsInURL(c.url, m.NamedGroups)
	key := httpCacheKey(c.method, expandedURL, secretBytes)

	resp, found := c.cache.get(key)
	if !found {
		var err error
		resp, err = withRetry(ctx, func() (*cachedHTTPResponse, error) {
			return makeHTTPRequest(ctx, c.method, c.url, c.headers, c.body, c.auth, m.NamedGroups)
		})
		if err != nil {
			return false, fmt.Errorf("http condition request: %w", err)
		}
		c.cache.put(key, resp)
	}

	return c.firesWhen.evaluate(resp)
}

// ----------------------------------------------------------------
// fires_when leaf implementations (status_code, status_code_in)
// ----------------------------------------------------------------

type statusCodeLeaf struct{ Code int }

func (l *statusCodeLeaf) evaluate(resp *cachedHTTPResponse) (bool, error) {
	return resp.StatusCode == l.Code, nil
}

type statusCodeInLeaf struct{ Codes []int }

func (l *statusCodeInLeaf) evaluate(resp *cachedHTTPResponse) (bool, error) {
	for _, c := range l.Codes {
		if resp.StatusCode == c {
			return true, nil
		}
	}
	return false, nil
}
