package llm

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResponseCache_HitAndMiss(t *testing.T) {
	c := NewResponseCache()
	key := CacheKey("system", "hello")

	got := c.Get(key)
	assert.Nil(t, got, "miss expected")

	resp := &Response{Content: "world", Usage: Usage{InputTokens: 10}}
	c.Set(key, resp)

	got = c.Get(key)
	require.NotNil(t, got)
	assert.Equal(t, "world", got.Content)
	assert.Equal(t, int64(1), c.Hits())
}

func TestResponseCache_DifferentKeys(t *testing.T) {
	c := NewResponseCache()
	k1 := CacheKey("sys", "msg1")
	k2 := CacheKey("sys", "msg2")

	c.Set(k1, &Response{Content: "one"})
	c.Set(k2, &Response{Content: "two"})

	assert.Equal(t, "one", c.Get(k1).Content)
	assert.Equal(t, "two", c.Get(k2).Content)
}

func TestCacheKey_Deterministic(t *testing.T) {
	k1 := CacheKey("system", "user message")
	k2 := CacheKey("system", "user message")
	assert.Equal(t, k1, k2)
}

func TestCacheKey_DifferentInputsDifferentKeys(t *testing.T) {
	k1 := CacheKey("system", "msg1")
	k2 := CacheKey("system", "msg2")
	assert.NotEqual(t, k1, k2)
}

func TestResponseCache_ConcurrentAccess(t *testing.T) {
	c := NewResponseCache()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := CacheKey("sys", string(rune('a'+n%26)))
			c.Set(key, &Response{Content: "val"})
			c.Get(key)
		}(i)
	}
	wg.Wait()
}
