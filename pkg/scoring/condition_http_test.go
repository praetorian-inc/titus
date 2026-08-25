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

	// evaluateWithCache takes the cache as an explicit parameter so that the
	// shared *httpCondition state is never mutated (race fix). The deduplication
	// guarantee now lives at the call site — callers (Engine) pass the same cache
	// instance for all findings in a scan.
	cache := newHTTPResponseCache()
	cond := &httpCondition{method: "GET", url: srv.URL, auth: scorerAuth{}, firesWhen: &statusCodeLeaf{Code: 200}}
	m := matchWithGroups(nil)

	_, err := cond.evaluateWithCache(context.Background(), m, cache)
	require.NoError(t, err)
	_, err = cond.evaluateWithCache(context.Background(), m, cache) // second call — should use cache
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

func TestHTTPCondition_StatusCodeIn_DoesNotFire(t *testing.T) {
	cond, _ := httpConditionFixture(t, 404, `{}`, nil)
	cond.firesWhen = &statusCodeInLeaf{Codes: []int{200, 201, 204}}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestHTTPCondition_HeaderContains_HeaderAbsent_DoesNotFire(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{}`, nil)
	cond.firesWhen = &headerContainsLeaf{Name: "x-oauth-scopes", Value: "admin:org"}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestHTTPCondition_JSONPathEquals_DoesNotFire(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{"plan":{"name":"free"}}`, nil)
	cond.firesWhen = &jsonPathEqualsLeaf{Path: ".plan.name", Value: "enterprise"}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestHTTPCondition_JSONPathMatches_DoesNotFire(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{"login":"github-bot"}`, nil)
	cond.firesWhen = &jsonPathMatchesLeaf{Path: ".login", Regex: `^octo`}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestHTTPCondition_JSONPathEquals_Fires(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{"plan":{"name":"enterprise"}}`, nil)
	cond.firesWhen = &jsonPathEqualsLeaf{Path: ".plan.name", Value: "enterprise"}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestHTTPCondition_JSONPathMatches_Fires(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{"login":"octocat"}`, nil)
	cond.firesWhen = &jsonPathMatchesLeaf{Path: ".login", Regex: `^octo`}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestHTTPCondition_JSONArrayLengthGte_Fires(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `[{"id":1},{"id":2},{"id":3}]`, nil)
	cond.firesWhen = &jsonArrayLengthGteLeaf{Path: ".", Value: 3}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestHTTPCondition_JSONArrayLengthGte_DoesNotFire(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `[{"id":1}]`, nil)
	cond.firesWhen = &jsonArrayLengthGteLeaf{Path: ".", Value: 3}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.False(t, fired)
}

// ----------------------------------------------------------------
// negatedLeaf — `negative: true` on a fires_when block (LAB-3371)
// ----------------------------------------------------------------

func TestNegatedLeaf_InvertsFalseToTrue(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{}`, nil)
	cond.firesWhen = &negatedLeaf{inner: &statusCodeLeaf{Code: 403}}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.True(t, fired, "inner leaf did not fire, so the negation should")
}

func TestNegatedLeaf_InvertsTrueToFalse(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{}`, nil)
	cond.firesWhen = &negatedLeaf{inner: &statusCodeLeaf{Code: 200}}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.False(t, fired, "inner leaf fired, so the negation should not")
}

// A negated leaf must NOT turn an inner error into a "fires" result. jsonGet
// errors on a missing path rather than returning false, so inverting errors
// would make a negated json_path_* fire on any response lacking the field —
// including error bodies from a revoked key.
func TestNegatedLeaf_PropagatesErrorWithoutInverting(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{}`, nil)
	cond.firesWhen = &negatedLeaf{inner: &jsonPathEqualsLeaf{Path: ".missing", Value: true}}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.Error(t, err, "inner error must propagate, not be inverted into a match")
	assert.False(t, fired)
}

// negative + json_array_length_gte is the "fewer than N" test the DSL otherwise
// lacks; it is how a restricted-scope key is detected.
func TestNegatedLeaf_ArrayLengthGte_GivesLessThan(t *testing.T) {
	cond, _ := httpConditionFixture(t, 200, `{"scopes":["mail.send","stats.read"]}`, nil)
	cond.firesWhen = &negatedLeaf{inner: &jsonArrayLengthGteLeaf{Path: ".scopes", Value: 25}}
	fired, err := cond.Evaluate(context.Background(), matchWithGroups(nil))
	require.NoError(t, err)
	assert.True(t, fired, "2 scopes is fewer than 25, so the negated gte should fire")
}

// ----------------------------------------------------------------
// cache key must reflect the RENDERED request, not the template (LAB-6051)
// ----------------------------------------------------------------

// countingServer records the request paths it receives.
type countingServer struct {
	calls int
	paths []string
}

// Two findings sharing a secret but rendering a different non-secret template
// variable are different requests. Keying on the un-rendered template made them
// collide, so the second silently received the first one's response.
func TestHTTPCondition_DifferentTemplateValues_IssueSeparateRequests(t *testing.T) {
	var rec countingServer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.calls++
		rec.paths = append(rec.paths, r.URL.Path)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"region":"` + r.URL.Path + `"}`))
	}))
	defer srv.Close()

	cache := newHTTPResponseCache()
	cond := func() *httpCondition {
		return &httpCondition{
			method:    "GET",
			url:       srv.URL + "/{{region}}/account",
			auth:      scorerAuth{Type: "bearer", SecretGroup: "token"},
			firesWhen: &statusCodeLeaf{Code: 200},
		}
	}
	us := matchWithGroups(map[string][]byte{"token": []byte("same-secret"), "region": []byte("us")})
	eu := matchWithGroups(map[string][]byte{"token": []byte("same-secret"), "region": []byte("eu")})

	_, err := cond().evaluateWithCache(context.Background(), us, cache)
	require.NoError(t, err)
	_, err = cond().evaluateWithCache(context.Background(), eu, cache)
	require.NoError(t, err)

	assert.Equal(t, 2, rec.calls, "different rendered URLs must not share a cache entry")
	assert.Equal(t, []string{"/us/account", "/eu/account"}, rec.paths)
}

// The flip side, and the property the SendGrid scorer depends on: modifiers
// issuing an identical request must still share one network call.
func TestHTTPCondition_IdenticalRequests_ShareOneCacheEntry(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"scopes":["mail.send"]}`))
	}))
	defer srv.Close()

	cache := newHTTPResponseCache()
	cond := func() *httpCondition {
		return &httpCondition{
			method:    "GET",
			url:       srv.URL + "/v3/scopes",
			auth:      scorerAuth{Type: "bearer", SecretGroup: "token"},
			firesWhen: &statusCodeLeaf{Code: 200},
		}
	}
	m := matchWithGroups(map[string][]byte{"token": []byte("secret")})

	for i := 0; i < 3; i++ {
		_, err := cond().evaluateWithCache(context.Background(), m, cache)
		require.NoError(t, err)
	}
	assert.Equal(t, 1, calls, "identical requests must share one cache entry")
}

// Headers are part of request identity too.
func TestHTTPCondition_DifferentHeaders_IssueSeparateRequests(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	cache := newHTTPResponseCache()
	m := matchWithGroups(map[string][]byte{"token": []byte("secret")})
	for _, v := range []string{"v1", "v2"} {
		c := &httpCondition{
			method:    "GET",
			url:       srv.URL + "/x",
			headers:   []scorerHeader{{Name: "X-Api-Version", Value: v}},
			auth:      scorerAuth{Type: "bearer", SecretGroup: "token"},
			firesWhen: &statusCodeLeaf{Code: 200},
		}
		_, err := c.evaluateWithCache(context.Background(), m, cache)
		require.NoError(t, err)
	}
	assert.Equal(t, 2, calls, "different headers must not share a cache entry")
}

// So is the request body.
func TestHTTPCondition_DifferentBodies_IssueSeparateRequests(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	cache := newHTTPResponseCache()
	m := matchWithGroups(map[string][]byte{"token": []byte("secret")})
	for _, b := range []string{`{"q":"a"}`, `{"q":"b"}`} {
		c := &httpCondition{
			method:    "POST",
			url:       srv.URL + "/search",
			body:      b,
			auth:      scorerAuth{Type: "bearer", SecretGroup: "token"},
			firesWhen: &statusCodeLeaf{Code: 200},
		}
		_, err := c.evaluateWithCache(context.Background(), m, cache)
		require.NoError(t, err)
	}
	assert.Equal(t, 2, calls, "different bodies must not share a cache entry")
}

// Auth is part of what makes a request distinct: the same URL and secret sent
// as a bearer header, a custom header, or a query parameter are three different
// requests. Omitting auth from the key let the second reuse the first's response.
func TestHTTPCondition_DifferentAuthTypes_IssueSeparateRequests(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	cache := newHTTPResponseCache()
	m := matchWithGroups(map[string][]byte{"token": []byte("secret")})
	auths := []scorerAuth{
		{Type: "bearer", SecretGroup: "token"},
		{Type: "header", SecretGroup: "token", HeaderName: "X-Token"},
		{Type: "query", SecretGroup: "token", QueryParam: "token"},
	}
	for _, a := range auths {
		c := &httpCondition{
			method:    "GET",
			url:       srv.URL + "/x",
			auth:      a,
			firesWhen: &statusCodeLeaf{Code: 200},
		}
		_, err := c.evaluateWithCache(context.Background(), m, cache)
		require.NoError(t, err)
	}
	assert.Equal(t, len(auths), calls, "each auth scheme is a distinct request")
}

// The key encoding must be unambiguous. Delimiting fields with a NUL byte
// collides for values that themselves contain NUL: no headers with a body of
// "a\x00b\x00" produced the same bytes as one header {a: b} with an empty body.
func TestHTTPCondition_AmbiguousFieldBoundaries_DoNotCollide(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	cache := newHTTPResponseCache()
	m := matchWithGroups(map[string][]byte{"token": []byte("secret")})
	auth := scorerAuth{Type: "bearer", SecretGroup: "token"}

	withBody := &httpCondition{
		method: "POST", url: srv.URL + "/x", auth: auth,
		body:      "a\x00b\x00",
		firesWhen: &statusCodeLeaf{Code: 200},
	}
	withHeader := &httpCondition{
		method: "POST", url: srv.URL + "/x", auth: auth,
		headers:   []scorerHeader{{Name: "a", Value: "b"}},
		firesWhen: &statusCodeLeaf{Code: 200},
	}
	_, err := withBody.evaluateWithCache(context.Background(), m, cache)
	require.NoError(t, err)
	_, err = withHeader.evaluateWithCache(context.Background(), m, cache)
	require.NoError(t, err)

	assert.Equal(t, 2, calls, "distinct requests must not hash to the same key")
}
