package scoring

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// cachedHTTPResponse holds the parts of an HTTP response needed by fires_when conditions.
type cachedHTTPResponse struct {
	StatusCode int
	Body       []byte
	Headers    map[string]string // lower-cased header names
}

// httpResponseCache is a per-scan, thread-safe cache keyed by the rendered
// request (see httpCacheKey). It is NOT shared across scans; the engine creates
// one per Score() invocation group.
type httpResponseCache struct {
	mu      sync.RWMutex
	entries map[string]*cachedHTTPResponse
}

func newHTTPResponseCache() *httpResponseCache {
	return &httpResponseCache{entries: make(map[string]*cachedHTTPResponse)}
}

// httpCacheKey returns a deterministic key identifying one rendered request.
//
// Every component must be the value actually sent, not the template it came
// from. Keying on an un-rendered URL made two requests that differ only in a
// non-secret template variable — a region, an account id — collide, so the
// second silently received the first one's response. Headers and body are part
// of request identity for the same reason.
//
// The whole key is a single hash, so credentials never appear in map keys even
// though the rendered URL, headers and body may contain them.
//
// Header order is significant. Headers come from the YAML in declaration order,
// so this is deterministic for a given modifier; two modifiers declaring the
// same headers in a different order simply miss the shared entry, costing an
// extra request rather than returning a wrong one.
func httpCacheKey(method, url string, headers []scorerHeader, body string, secretBytes []byte) string {
	h := sha256.New()
	write := func(s string) {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0})
	}
	write(method)
	write(url)
	for _, hdr := range headers {
		write(hdr.Name)
		write(hdr.Value)
	}
	write(body)
	_, _ = h.Write(secretBytes)
	return hex.EncodeToString(h.Sum(nil))
}

func (c *httpResponseCache) get(key string) (*cachedHTTPResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.entries[key]
	return v, ok
}

func (c *httpResponseCache) put(key string, resp *cachedHTTPResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = resp
}
