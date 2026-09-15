package validator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLookerValidator(srv *httptest.Server) *LookerValidator {
	return &LookerValidator{
		client:  srv.Client(),
		baseURL: srv.URL,
	}
}

func TestLookerValidator_Name(t *testing.T) {
	v := NewLookerValidator()
	assert.Equal(t, "looker", v.Name())
}

func TestLookerValidator_CanValidate(t *testing.T) {
	v := NewLookerValidator()
	assert.True(t, v.CanValidate("kingfisher.looker.1"))
	assert.True(t, v.CanValidate("kingfisher.looker.2"))
	assert.True(t, v.CanValidate("kingfisher.looker.3"))
	assert.False(t, v.CanValidate("kingfisher.gcp.1"))
	assert.False(t, v.CanValidate("np.jenkins.1"))
}

func TestLookerValidator_BaseURLUndetermined(t *testing.T) {
	v := NewLookerValidator()
	match := &types.Match{RuleID: "kingfisher.looker.1"}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "base URL alone")
}

func TestLookerValidator_ClientIDUndetermined(t *testing.T) {
	v := NewLookerValidator()
	match := &types.Match{RuleID: "kingfisher.looker.2"}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "client ID alone")
}

func TestLookerValidator_ValidCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/4.0/login", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		require.NoError(t, r.ParseForm())
		assert.Equal(t, "abcdefghij1234567890", r.FormValue("client_id"))
		assert.Equal(t, "abcdefghijklmnop12345678", r.FormValue("client_secret"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "some-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	v := newTestLookerValidator(srv)

	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		Groups: [][]byte{[]byte("abcdefghijklmnop12345678")},
		Snippet: types.Snippet{
			Before:   []byte("client_id=abcdefghij1234567890\n"),
			Matching: []byte("abcdefghijklmnop12345678"),
			After:    []byte("\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Contains(t, result.Message, "Looker credentials valid")
}

func TestLookerValidator_InvalidCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	v := newTestLookerValidator(srv)

	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		Groups: [][]byte{[]byte("abcdefghijklmnop12345678")},
		Snippet: types.Snippet{
			Before:   []byte("client_id=abcdefghij1234567890\n"),
			Matching: []byte("abcdefghijklmnop12345678"),
			After:    []byte("\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Contains(t, result.Message, "rejected")
}

func TestLookerValidator_ForbiddenCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	v := newTestLookerValidator(srv)

	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		Groups: [][]byte{[]byte("abcdefghijklmnop12345678")},
		Snippet: types.Snippet{
			Before:   []byte("client_id=abcdefghij1234567890\n"),
			Matching: []byte("abcdefghijklmnop12345678"),
			After:    []byte("\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestLookerValidator_NotFoundIsInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	v := newTestLookerValidator(srv)

	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		Groups: [][]byte{[]byte("abcdefghijklmnop12345678")},
		Snippet: types.Snippet{
			Before:   []byte("client_id=abcdefghij1234567890\n"),
			Matching: []byte("abcdefghijklmnop12345678"),
			After:    []byte("\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Contains(t, result.Message, "404")
}

func TestLookerValidator_MissingBaseURL(t *testing.T) {
	v := NewLookerValidator()
	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		Groups: [][]byte{[]byte("abcdefghijklmnop12345678")},
		Snippet: types.Snippet{
			Before:   []byte("client_id=abcdefghij1234567890\n"),
			Matching: []byte("abcdefghijklmnop12345678"),
			After:    []byte("\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "no Looker base URL")
}

func TestLookerValidator_MissingClientID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	v := newTestLookerValidator(srv)

	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		Groups: [][]byte{[]byte("abcdefghijklmnop12345678")},
		Snippet: types.Snippet{
			Before:   []byte("some unrelated context\n"),
			Matching: []byte("abcdefghijklmnop12345678"),
			After:    []byte("\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "no client ID")
}

func TestLookerValidator_ResponseNotJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	v := newTestLookerValidator(srv)

	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		Groups: [][]byte{[]byte("abcdefghijklmnop12345678")},
		Snippet: types.Snippet{
			Before:   []byte("client_id=abcdefghij1234567890\n"),
			Matching: []byte("abcdefghijklmnop12345678"),
			After:    []byte("\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "not valid JSON")
}

func TestLookerValidator_MissingAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "something unexpected",
		})
	}))
	defer srv.Close()

	v := newTestLookerValidator(srv)

	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		Groups: [][]byte{[]byte("abcdefghijklmnop12345678")},
		Snippet: types.Snippet{
			Before:   []byte("client_id=abcdefghij1234567890\n"),
			Matching: []byte("abcdefghijklmnop12345678"),
			After:    []byte("\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "missing access_token")
}

func TestLookerValidator_NullAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":null}`))
	}))
	defer srv.Close()

	v := newTestLookerValidator(srv)

	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		Groups: [][]byte{[]byte("abcdefghijklmnop12345678")},
		Snippet: types.Snippet{
			Before:   []byte("client_id=abcdefghij1234567890\n"),
			Matching: []byte("abcdefghijklmnop12345678"),
			After:    []byte("\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "empty or non-string")
}

func TestLookerValidator_EmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":""}`))
	}))
	defer srv.Close()

	v := newTestLookerValidator(srv)

	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		Groups: [][]byte{[]byte("abcdefghijklmnop12345678")},
		Snippet: types.Snippet{
			Before:   []byte("client_id=abcdefghij1234567890\n"),
			Matching: []byte("abcdefghijklmnop12345678"),
			After:    []byte("\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "empty or non-string")
}

func TestLookerValidator_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	v := newTestLookerValidator(srv)

	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		Groups: [][]byte{[]byte("abcdefghijklmnop12345678")},
		Snippet: types.Snippet{
			Before:   []byte("client_id=abcdefghij1234567890\n"),
			Matching: []byte("abcdefghijklmnop12345678"),
			After:    []byte("\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "unexpected status")
}

func TestIsLookerDomain(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://example.cloud.looker.com", true},
		{"https://mycompany.looker.com:19999", true},
		{"https://sub.domain.looker.com/api/4.0", true},
		{"http://example.cloud.looker.com", false},
		{"https://evil.com", false},
		{"https://fakelooker.com", false},
		{"https://looker.com.evil.com", false},
		{"https://localhost:9999", false},
		{"not-a-url", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.want, isLookerDomain(tt.url))
		})
	}
}

type failingTransport struct{}

func (t *failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport: no real network access in tests")
}

func TestLookerValidator_ContextExtraction(t *testing.T) {
	v := &LookerValidator{
		client: &http.Client{Transport: &failingTransport{}},
	}

	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		Groups: [][]byte{[]byte("abcdefghijklmnop12345678")},
		Snippet: types.Snippet{
			Before:   []byte("LOOKER_BASE_URL=https://myco.cloud.looker.com\nLOOKER_CLIENT_ID=abcdefghij1234567890\n"),
			Matching: []byte("abcdefghijklmnop12345678"),
			After:    []byte("\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "request failed")
}

func TestLookerValidator_NoSecret(t *testing.T) {
	v := NewLookerValidator()
	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		Groups: [][]byte{},
		Snippet: types.Snippet{
			Before: []byte("LOOKER_BASE_URL=https://example.cloud.looker.com\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot extract client secret")
}

func TestLookerValidator_SecretFromNamedGroups(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "abcdefghijklmnop12345678", r.FormValue("client_secret"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
		})
	}))
	defer srv.Close()

	v := newTestLookerValidator(srv)

	match := &types.Match{
		RuleID: "kingfisher.looker.3",
		NamedGroups: map[string][]byte{
			"secret": []byte("abcdefghijklmnop12345678"),
		},
		Snippet: types.Snippet{
			Before:   []byte("client_id=abcdefghij1234567890\n"),
			Matching: []byte("abcdefghijklmnop12345678"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}
