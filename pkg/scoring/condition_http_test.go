package scoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/praetorian-inc/titus/pkg/types"
)

// helper: build a minimal Match with NamedGroups
func matchWithGroups(groups map[string][]byte) *types.Match {
	return &types.Match{NamedGroups: groups}
}

// helper: serve a fixed response
func httpConditionFixture(t *testing.T, status int, body string, hdrs map[string]string) (*httpCondition, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range hdrs {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	cond := &httpCondition{
		method:    "GET",
		url:       srv.URL,
		auth:      scorerAuth{},
		firesWhen: &statusCodeLeaf{Code: status},
		cache:     newHTTPResponseCache(),
	}
	return cond, srv.URL
}

func TestHTTPCondition_StatusCode_Fires(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{}`, nil)
	cond.firesWhen = &statusCodeLeaf{Code: 200}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestHTTPCondition_StatusCode_DoesNotFire(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{}`, nil)
	cond.firesWhen = &statusCodeLeaf{Code: 403}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestHTTPCondition_StatusCodeIn_Fires(t *testing.T) {
	cond, _ := httpConditionFixture(t, 201, `{}`, nil)
	cond.firesWhen = &statusCodeInLeaf{Codes: []int{200, 201, 204}}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestHTTPCondition_UsesCache(t *testing.T) {
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	cache := newHTTPResponseCache()
	cond := &httpCondition{method: "GET", url: srv.URL, auth: scorerAuth{}, firesWhen: &statusCodeLeaf{Code: 200}, cache: cache}
	m := matchWithGroups(nil)

	_, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	_, err = cond.Evaluate(context.Background(), m) // second call — should use cache
	require.NoError(t, err)

	assert.Equal(t, 1, callCount, "cache should prevent second HTTP call")
}

func TestHTTPCondition_BodyContains_Fires(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{"login":"octocat","plan":{"name":"enterprise"}}`, nil)
	cond.firesWhen = &responseBodyContainsLeaf{Value: "enterprise"}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestHTTPCondition_BodyContains_DoesNotFire(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{"plan":{"name":"free"}}`, nil)
	cond.firesWhen = &responseBodyContainsLeaf{Value: "enterprise"}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestHTTPCondition_HeaderContains_Fires(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{}`, map[string]string{"x-oauth-scopes": "repo, admin:org, read:user"})
	cond.firesWhen = &headerContainsLeaf{Name: "x-oauth-scopes", Value: "admin:org"}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestHTTPCondition_HeaderContains_CaseInsensitiveHeaderName(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{}`, map[string]string{"x-oauth-scopes": "admin:org"})
	cond.firesWhen = &headerContainsLeaf{Name: "X-OAuth-Scopes", Value: "admin:org"}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.True(t, fired)
}
