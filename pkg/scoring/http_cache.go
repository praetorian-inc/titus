package scoring

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
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
// Auth is part of request identity too: the same URL and secret sent as a
// bearer header, a custom header, or a query parameter are three different
// requests.
//
// Fields are length-prefixed rather than delimited. A delimiter is ambiguous
// for values that can contain it — with NUL separators, no headers and a body
// of "a\x00b\x00" hashes identically to one header {a: b} with an empty body.
// The header count is written too, so a header pair cannot be confused with the
// body that follows it.
//
// Header order is significant. Headers come from the YAML in declaration order,
// so this is deterministic for a given modifier; two modifiers declaring the
// same headers in a different order simply miss the shared entry, costing an
// extra request rather than returning a wrong one.
func httpCacheKey(r renderedRequest, auth scorerAuth, secretBytes []byte) string {
	h := sha256.New()
	write := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		_, _ = h.Write(n[:])
		_, _ = h.Write(b)
	}
	writeStr := func(s string) { write([]byte(s)) }

	writeStr(r.method)
	writeStr(r.url)
	writeStr(strconv.Itoa(len(r.headers)))
	for _, hdr := range r.headers {
		writeStr(hdr.Name)
		writeStr(hdr.Value)
	}
	writeStr(r.body)

	// Effective auth: the scheme and everything that shapes where the secret goes.
	writeStr(auth.Type)
	writeStr(auth.SecretGroup)
	writeStr(auth.HeaderName)
	writeStr(auth.QueryParam)
	writeStr(auth.Username)
	writeStr(auth.KeyPrefix)

	write(secretBytes)
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
