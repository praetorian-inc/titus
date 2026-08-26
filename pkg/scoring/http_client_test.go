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

// ----------------------------------------------------------------
// auth type "none" (LAB-6049)
// ----------------------------------------------------------------

// Some APIs take the credential in the URL rather than a header -- Google's
// Generative Language API uses ?key=<secret>. Those scorers declare
// auth.type: none, which was not a supported case: the guard in
// makeHTTPRequest only skips auth when the type is EMPTY, so "none" fell
// through to applyScorerAuth's default branch and failed the whole request.
func TestMakeHTTPRequest_AuthTypeNone_SendsRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"models":[{"name":"gemini-1.5-pro"}]}`))
	}))
	defer srv.Close()

	auth := scorerAuth{Type: "none", SecretGroup: "key"}
	groups := map[string][]byte{"key": []byte("AIzaSyEXAMPLE")}

	resp, err := makeHTTPRequest(context.Background(), "GET", srv.URL+"/v1/models?key={{key}}", nil, "", auth, groups)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, string(resp.Body), "gemini-1.5-pro")
}

// The whole point of type: none is that no Authorization header is set.
func TestMakeHTTPRequest_AuthTypeNone_SetsNoAuthorizationHeader(t *testing.T) {
	var gotAuth string
	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotURL = r.URL.String()
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	auth := scorerAuth{Type: "none", SecretGroup: "key"}
	groups := map[string][]byte{"key": []byte("AIzaSyEXAMPLE")}

	_, err := makeHTTPRequest(context.Background(), "GET", srv.URL+"/v1/models?key={{key}}", nil, "", auth, groups)
	require.NoError(t, err)
	assert.Empty(t, gotAuth, "type: none must not set an Authorization header")
	assert.Contains(t, gotURL, "key=AIzaSyEXAMPLE", "the secret still reaches the API via the URL template")
}
