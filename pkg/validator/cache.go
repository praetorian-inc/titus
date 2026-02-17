// pkg/validator/cache.go
package validator

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/praetorian-inc/titus/pkg/types"
)

// ValidationCache caches validation results by secret value.
// Key is SHA256(secret_value) for consistent deduplication.
type ValidationCache struct {
	results map[string]*types.ValidationResult
	mu      sync.RWMutex
}

// NewValidationCache creates a new validation cache.
func NewValidationCache() *ValidationCache {
	return &ValidationCache{
		results: make(map[string]*types.ValidationResult),
	}
}

// Get retrieves a cached result for the given secret.
// Returns nil if not found.
func (c *ValidationCache) Get(secret []byte) *types.ValidationResult {
	key := computeCacheKey(secret)
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.results[key]
}

// Set stores a validation result for the given secret.
func (c *ValidationCache) Set(secret []byte, result *types.ValidationResult) {
	key := computeCacheKey(secret)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results[key] = result
}

// computeCacheKey returns SHA256 hash of secret as hex string.
func computeCacheKey(secret []byte) string {
	h := sha256.Sum256(secret)
	return hex.EncodeToString(h[:])
}
