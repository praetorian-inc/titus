// pkg/validator/cache_test.go
package validator

import (
	"fmt"
	"sync"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestValidationCache_GetSet(t *testing.T) {
	cache := NewValidationCache()

	secret := []byte("AKIAIOSFODNN7EXAMPLE")

	// Initially empty
	result := cache.Get(secret)
	assert.Nil(t, result)

	// Set a result
	expected := types.NewValidationResult(types.StatusValid, 1.0, "valid")
	cache.Set(secret, expected)

	// Should be retrievable
	result = cache.Get(secret)
	assert.NotNil(t, result)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestValidationCache_SameSecretSameKey(t *testing.T) {
	cache := NewValidationCache()

	secret1 := []byte("test-secret-value")
	secret2 := []byte("test-secret-value") // Same content

	expected := types.NewValidationResult(types.StatusInvalid, 1.0, "invalid")
	cache.Set(secret1, expected)

	// Same secret value should hit cache
	result := cache.Get(secret2)
	assert.NotNil(t, result)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestValidationCache_DifferentSecretsDifferentKeys(t *testing.T) {
	cache := NewValidationCache()

	secret1 := []byte("secret-one")
	secret2 := []byte("secret-two")

	cache.Set(secret1, types.NewValidationResult(types.StatusValid, 1.0, "one"))
	cache.Set(secret2, types.NewValidationResult(types.StatusInvalid, 1.0, "two"))

	result1 := cache.Get(secret1)
	result2 := cache.Get(secret2)

	assert.Equal(t, types.StatusValid, result1.Status)
	assert.Equal(t, types.StatusInvalid, result2.Status)
}

func TestValidationCache_Concurrent(t *testing.T) {
	cache := NewValidationCache()

	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			secret := []byte(fmt.Sprintf("secret-%d", n))
			cache.Set(secret, types.NewValidationResult(types.StatusValid, 1.0, ""))
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			secret := []byte(fmt.Sprintf("secret-%d", n))
			cache.Get(secret)
		}(i)
	}

	wg.Wait()

	// No race condition errors = pass
	assert.True(t, true)
}
