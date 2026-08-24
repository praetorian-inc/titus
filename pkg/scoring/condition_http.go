package scoring

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

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
//
// The cache is passed as an explicit argument to evaluateWithCache rather than
// stored as a field. This avoids the data race that occurred when Score()
// goroutines concurrently wrote to the cache field of shared *httpCondition
// instances.
type httpCondition struct {
	method    string
	url       string         // may contain {{group}} placeholders
	headers   []scorerHeader
	body      string
	auth      scorerAuth
	firesWhen firesWhenLeaf
}

// markDynamic implements the networkCondition marker interface.
// This gates HTTP conditions behind --score-scope.
func (c *httpCondition) markDynamic() {}

// Evaluate executes the HTTP call using the condition's own local cache.
// This is used by test fixtures that call the condition directly.
// Production code calls evaluateWithCache instead to use the engine's shared
// cache without mutating this struct's fields.
func (c *httpCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	return c.evaluateWithCache(ctx, m, newHTTPResponseCache())
}

// evaluateWithCache executes the HTTP call (or uses the provided cache) then
// applies firesWhen. The cache parameter is the engine's shared per-scan cache;
// passing it as an argument avoids any mutation of the shared *httpCondition
// state, which would be a data race when Score() runs concurrently.
func (c *httpCondition) evaluateWithCache(ctx context.Context, m *types.Match, cache *httpResponseCache) (bool, error) {
	if m == nil {
		return false, nil
	}

	// Use the template URL (c.url) not the expanded URL as the cache key so
	// plaintext secrets don't appear in in-memory cache keys. The secret bytes
	// already provide per-secret uniqueness in the key hash.
	secretBytes := m.NamedGroups[c.auth.SecretGroup]
	key := httpCacheKey(c.method, c.url, secretBytes)

	resp, found := cache.get(key)
	if !found {
		var err error
		resp, err = withRetry(ctx, func() (*cachedHTTPResponse, error) {
			return makeHTTPRequest(ctx, c.method, c.url, c.headers, c.body, c.auth, m.NamedGroups)
		})
		if err != nil {
			return false, fmt.Errorf("http condition request: %w", err)
		}
		// Always cache the response — including 429/5xx — so that subsequent
		// calls for the same secret/URL fast-fail without hitting the network
		// again.  Classify persistent 429/5xx as sentinel errors so trackError
		// can increment the correct stats counter.
		cache.put(key, resp)
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return false, classifyHTTPError(resp.StatusCode, nil)
		}
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

// ----------------------------------------------------------------
// fires_when leaf implementations (response_body_contains, header_contains)
// ----------------------------------------------------------------

type responseBodyContainsLeaf struct{ Value string }

func (l *responseBodyContainsLeaf) evaluate(resp *cachedHTTPResponse) (bool, error) {
	return strings.Contains(string(resp.Body), l.Value), nil
}

type headerContainsLeaf struct {
	Name  string // header name (case-insensitive lookup)
	Value string // substring to find in header value
}

func (l *headerContainsLeaf) evaluate(resp *cachedHTTPResponse) (bool, error) {
	v, ok := resp.Headers[strings.ToLower(l.Name)]
	if !ok {
		return false, nil
	}
	return strings.Contains(v, l.Value), nil
}

// ----------------------------------------------------------------
// fires_when leaf implementations (json_path_equals, json_path_matches,
// json_array_length_gte)
// ----------------------------------------------------------------

type jsonPathEqualsLeaf struct {
	Path  string
	Value interface{} // string or number from YAML
}

func (l *jsonPathEqualsLeaf) evaluate(resp *cachedHTTPResponse) (bool, error) {
	v, err := jsonGet(resp.Body, l.Path)
	if err != nil {
		return false, err
	}
	// Compare as string for simplicity — YAML values are strings/numbers
	return fmt.Sprintf("%v", v) == fmt.Sprintf("%v", l.Value), nil
}

type jsonPathMatchesLeaf struct {
	Path  string
	Regex string
	re    *regexp.Regexp // compiled at load time; lazily compiled if nil
}

func (l *jsonPathMatchesLeaf) evaluate(resp *cachedHTTPResponse) (bool, error) {
	v, err := jsonGet(resp.Body, l.Path)
	if err != nil {
		return false, err
	}
	re := l.re
	if re == nil {
		compiled, err := regexp.Compile(l.Regex)
		if err != nil {
			return false, fmt.Errorf("json_path_matches: invalid regex %q: %w", l.Regex, err)
		}
		re = compiled
	}
	return re.MatchString(fmt.Sprintf("%v", v)), nil
}

type jsonArrayLengthGteLeaf struct {
	Path  string
	Value int
}

func (l *jsonArrayLengthGteLeaf) evaluate(resp *cachedHTTPResponse) (bool, error) {
	v, err := jsonGet(resp.Body, l.Path)
	if err != nil {
		return false, err
	}
	arr, ok := v.([]interface{})
	if !ok {
		return false, fmt.Errorf("json_array_length_gte: path %q is not an array", l.Path)
	}
	return len(arr) >= l.Value, nil
}

// ----------------------------------------------------------------
// negated leaf (`negative: true`)
// ----------------------------------------------------------------

// negatedLeaf inverts the result of the leaf it wraps, giving the DSL the
// absence and upper-bound tests it otherwise lacks (e.g. negative: +
// json_array_length_gte reads as "fewer than N").
//
// Errors are propagated unchanged, never inverted: jsonGet returns an error for
// a missing path rather than false, so inverting errors would make a negated
// json_path_* condition fire on any response that lacks the field — including
// the error body returned by a revoked credential. Prefer response_body_contains
// for absence checks, as it cannot error.
type negatedLeaf struct{ inner firesWhenLeaf }

func (l *negatedLeaf) evaluate(resp *cachedHTTPResponse) (bool, error) {
	fired, err := l.inner.evaluate(resp)
	if err != nil {
		return false, err
	}
	return !fired, nil
}
