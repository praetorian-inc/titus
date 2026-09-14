package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
)

// ResponseCache is a thread-safe, in-memory cache of LLM responses keyed by
// a deterministic hash of the system and user prompt. It avoids duplicate
// LLM calls for the same secret across repeated validation runs.
type ResponseCache struct {
	mu      sync.RWMutex
	entries map[string]*Response
	hits    atomic.Int64
}

// NewResponseCache creates an empty ResponseCache.
func NewResponseCache() *ResponseCache {
	return &ResponseCache{
		entries: make(map[string]*Response),
	}
}

// CacheKey computes a deterministic SHA256-based cache key from the system
// prompt and user message.
func CacheKey(system, userMsg string) string {
	h := sha256.New()
	h.Write([]byte(system))
	h.Write([]byte{0})
	h.Write([]byte(userMsg))
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns the cached response for key, or nil if not present. A
// successful lookup increments the hit counter.
func (c *ResponseCache) Get(key string) *Response {
	c.mu.RLock()
	defer c.mu.RUnlock()
	resp, ok := c.entries[key]
	if ok {
		c.hits.Add(1)
	}
	return resp
}

// Set stores resp under key.
func (c *ResponseCache) Set(key string, resp *Response) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = resp
}

// Hits returns the number of cache hits recorded so far.
func (c *ResponseCache) Hits() int64 {
	return c.hits.Load()
}
