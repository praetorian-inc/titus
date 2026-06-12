package enum

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinearEnumerator_Construction(t *testing.T) {
	e, err := NewLinearEnumerator(LinearConfig{Token: "lin_api_test"})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestLinearEnumerator_RequiresToken(t *testing.T) {
	_, err := NewLinearEnumerator(LinearConfig{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestLinearEnumerator_Defaults(t *testing.T) {
	e, err := NewLinearEnumerator(LinearConfig{Token: "lin_api_test"})
	require.NoError(t, err)
	assert.Equal(t, 3, e.config.Concurrency)
	assert.Equal(t, 2.0, e.config.RateLimit)
}

func TestLinearEnumerator_Interface(t *testing.T) {
	e, err := NewLinearEnumerator(LinearConfig{Token: "lin_api_test"})
	require.NoError(t, err)
	var _ Enumerator = e
}

func TestLinearProvenance(t *testing.T) {
	prov := linearProvenance("issue", "ISS-123", "Bug title", "https://linear.app/team/ISS-123", "MyTeam", "MyProject")
	assert.Equal(t, "extended", prov.Kind())
	assert.Equal(t, "linear", prov.Payload["source"])
	assert.Equal(t, "issue", prov.Payload["entityType"])
	assert.Equal(t, "ISS-123", prov.Payload["identifier"])
	assert.Equal(t, "Bug title", prov.Payload["title"])
	assert.Equal(t, "https://linear.app/team/ISS-123", prov.Payload["url"])
	assert.Equal(t, "MyTeam", prov.Payload["team"])
	assert.Equal(t, "MyProject", prov.Payload["project"])
}

// Compile-time assertion that *LinearEnumerator satisfies Enumerator.
var _ Enumerator = (*LinearEnumerator)(nil)

// Ensure types package is referenced so imports stay tidy.
var _ types.Provenance = types.ExtendedProvenance{}

func TestLinearGraphQL_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "lin_api_test", r.Header.Get("Authorization"))

		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, "{ viewer { id } }", body["query"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"viewer": map[string]interface{}{"id": "user-1"},
			},
		})
	}))
	defer server.Close()

	e := testLinearEnumerator(t, server.URL)

	var result struct {
		Viewer struct{ ID string } `json:"viewer"`
	}
	err := e.graphql(context.Background(), "{ viewer { id } }", nil, &result)
	require.NoError(t, err)
	assert.Equal(t, "user-1", result.Viewer.ID)
}

func TestLinearGraphQL_RateLimitRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []map[string]interface{}{
					{
						"message":    "rate limited",
						"extensions": map[string]interface{}{"code": "RATELIMITED"},
					},
				},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"viewer": map[string]interface{}{"id": "ok"}},
		})
	}))
	defer server.Close()

	e := testLinearEnumerator(t, server.URL)

	var result struct {
		Viewer struct{ ID string } `json:"viewer"`
	}
	err := e.graphql(context.Background(), "{ viewer { id } }", nil, &result)
	require.NoError(t, err)
	assert.Equal(t, 2, attempts)
	assert.Equal(t, "ok", result.Viewer.ID)
}

func TestLinearGraphQL_GraphQLErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []map[string]interface{}{
				{"message": "Authentication required"},
			},
		})
	}))
	defer server.Close()

	e := testLinearEnumerator(t, server.URL)

	var result struct{}
	err := e.graphql(context.Background(), "{ viewer { id } }", nil, &result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Authentication required")
}

// testLinearEnumerator creates a LinearEnumerator pointing at a test server.
func testLinearEnumerator(t *testing.T, url string) *LinearEnumerator {
	t.Helper()
	e, err := NewLinearEnumerator(LinearConfig{
		Token:     "lin_api_test",
		RateLimit: 1000, // no throttling in tests
	})
	require.NoError(t, err)
	e.endpoint = url
	return e
}
