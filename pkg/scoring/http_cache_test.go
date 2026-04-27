package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPResponseCache_StoresAndRetrievesResponse(t *testing.T) {
	c := newHTTPResponseCache()
	key := httpCacheKey("GET", "https://api.github.com/user", []byte("ghp_secret"))

	_, found := c.get(key)
	assert.False(t, found, "cache should be empty initially")

	resp := &cachedHTTPResponse{StatusCode: 200, Body: []byte(`{"login":"octocat"}`), Headers: map[string]string{"x-oauth-scopes": "repo"}}
	c.put(key, resp)

	got, found := c.get(key)
	require.True(t, found)
	assert.Equal(t, 200, got.StatusCode)
	assert.Equal(t, []byte(`{"login":"octocat"}`), got.Body)
	assert.Equal(t, "repo", got.Headers["x-oauth-scopes"])
}

func TestHTTPCacheKey_DifferentSecretsGiveDifferentKeys(t *testing.T) {
	k1 := httpCacheKey("GET", "https://api.github.com/user", []byte("token-A"))
	k2 := httpCacheKey("GET", "https://api.github.com/user", []byte("token-B"))
	assert.NotEqual(t, k1, k2)
}

func TestHTTPCacheKey_DifferentURLsGiveDifferentKeys(t *testing.T) {
	k1 := httpCacheKey("GET", "https://api.github.com/user", []byte("tok"))
	k2 := httpCacheKey("GET", "https://api.github.com/user/orgs", []byte("tok"))
	assert.NotEqual(t, k1, k2)
}

func TestHTTPResponseCache_MissOnUnknownKey(t *testing.T) {
	c := newHTTPResponseCache()
	_, found := c.get(httpCacheKey("GET", "https://example.com", nil))
	assert.False(t, found)
}
