package scoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeHTTPRequest_BearerAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer ghp_secret", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"login":"octocat"}`))
	}))
	defer srv.Close()

	auth := scorerAuth{Type: "bearer", SecretGroup: "token"}
	groups := map[string][]byte{"token": []byte("ghp_secret")}

	resp, err := makeHTTPRequest(context.Background(), "GET", srv.URL, nil, "", auth, groups)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, string(resp.Body), "octocat")
}

func TestSubstituteTemplateVars_ReplacesNamedGroups(t *testing.T) {
	groups := map[string][]byte{"org": []byte("praetorian-inc")}
	result := substituteVarsInURL("https://api.github.com/orgs/{{org}}/members", groups)
	assert.Equal(t, "https://api.github.com/orgs/praetorian-inc/members", result)
}

func TestMakeHTTPRequest_CancelsOnContextDone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow server — client should cancel
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled
	_, err := makeHTTPRequest(ctx, "GET", srv.URL, nil, "", scorerAuth{}, nil)
	assert.Error(t, err, "expected error from cancelled context")
}
