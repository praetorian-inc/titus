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

// httpResponseCache is a per-scan, thread-safe cache keyed by (method, url, secret_hash).
// It is NOT shared across scans; the engine creates one per Score() invocation group.
type httpResponseCache struct {
	mu      sync.RWMutex
	entries map[string]*cachedHTTPResponse
}

func newHTTPResponseCache() *httpResponseCache {
	return &httpResponseCache{entries: make(map[string]*cachedHTTPResponse)}
}

// httpCacheKey returns a deterministic key for (method, url, secretBytes).
// secretBytes is hashed so credentials never appear in map keys.
func httpCacheKey(method, url string, secretBytes []byte) string {
	h := sha256.Sum256(secretBytes)
	return method + "\x00" + url + "\x00" + hex.EncodeToString(h[:])
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

func (c *httpResponseCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cachedHTTPResponse)
}
