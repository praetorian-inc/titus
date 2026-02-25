// pkg/validator/keenio_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestKeenIOValidator_Name(t *testing.T) {
	v := NewKeenIOValidator()
	assert.Equal(t, "keenio", v.Name())
}

func TestKeenIOValidator_CanValidate(t *testing.T) {
	v := NewKeenIOValidator()
	assert.True(t, v.CanValidate("np.keenio.1"))
	assert.False(t, v.CanValidate("np.keenio.2"))
	assert.False(t, v.CanValidate("np.github.1"))
}

func TestKeenIOValidator_ExtractCredentials_ProjectIDInBefore(t *testing.T) {
	v := NewKeenIOValidator()

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
		},
		Snippet: types.Snippet{
			Before:   []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
			Matching: []byte("KEEN_READ_KEY=a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
			After:    []byte(""),
		},
	}

	apiKey, projectID, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0", apiKey)
	assert.Equal(t, "5f3c8d2b1a4e7c9d0b2a3f4e", projectID)
}

func TestKeenIOValidator_ExtractCredentials_ProjectIDInAfter(t *testing.T) {
	v := NewKeenIOValidator()

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("KEEN_READ_KEY=a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
			After:    []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
		},
	}

	apiKey, projectID, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0", apiKey)
	assert.Equal(t, "5f3c8d2b1a4e7c9d0b2a3f4e", projectID)
}

func TestKeenIOValidator_ExtractCredentials_ProjectIDInMatching(t *testing.T) {
	v := NewKeenIOValidator()

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e KEEN_READ_KEY=a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
			After:    []byte(""),
		},
	}

	apiKey, projectID, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0", apiKey)
	assert.Equal(t, "5f3c8d2b1a4e7c9d0b2a3f4e", projectID)
}

func TestKeenIOValidator_ExtractCredentials_GenericProjectIDPattern(t *testing.T) {
	v := NewKeenIOValidator()

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
		},
		Snippet: types.Snippet{
			Before:   []byte("project_id: '5f3c8d2b1a4e7c9d0b2a3f4e'"),
			Matching: []byte("KEEN_READ_KEY=a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
			After:    []byte(""),
		},
	}

	apiKey, projectID, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0", apiKey)
	assert.Equal(t, "5f3c8d2b1a4e7c9d0b2a3f4e", projectID)
}

func TestKeenIOValidator_ExtractCredentials_MissingKey(t *testing.T) {
	v := NewKeenIOValidator()

	match := &types.Match{
		RuleID:      "np.keenio.1",
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before: []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
		},
	}

	apiKey, projectID, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key")
	assert.Empty(t, apiKey)
	assert.Empty(t, projectID)
}

func TestKeenIOValidator_ExtractCredentials_MissingProjectID(t *testing.T) {
	v := NewKeenIOValidator()

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
		},
		Snippet: types.Snippet{
			Before:   []byte("some other content"),
			Matching: []byte("KEEN_READ_KEY=a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
			After:    []byte("more content"),
		},
	}

	apiKey, projectID, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial")
	assert.Contains(t, err.Error(), "project ID")
	assert.Empty(t, apiKey)
	assert.Empty(t, projectID)
}

func TestKeenIOValidator_ExtractCredentials_NoNamedGroups(t *testing.T) {
	v := NewKeenIOValidator()

	match := &types.Match{
		RuleID:      "np.keenio.1",
		NamedGroups: nil,
	}

	apiKey, projectID, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no named capture groups")
	assert.Empty(t, apiKey)
	assert.Empty(t, projectID)
}

func TestKeenIOValidator_Validate_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify api_key query parameter is present
		assert.NotEmpty(t, r.URL.Query().Get("api_key"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewKeenIOValidatorWithClient(&http.Client{
		Transport: &keenIOMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
		},
		Snippet: types.Snippet{
			Before: []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "5f3c8d2b1a4e7c9d0b2a3f4e")
}

func TestKeenIOValidator_Validate_Invalid_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewKeenIOValidatorWithClient(&http.Client{
		Transport: &keenIOMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("invalid0000000000000000000000000000000000000000000000000000000000"),
		},
		Snippet: types.Snippet{
			Before: []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "401")
}

func TestKeenIOValidator_Validate_Invalid_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := NewKeenIOValidatorWithClient(&http.Client{
		Transport: &keenIOMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
		},
		Snippet: types.Snippet{
			Before: []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "403")
}

func TestKeenIOValidator_Validate_Undetermined_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewKeenIOValidatorWithClient(&http.Client{
		Transport: &keenIOMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
		},
		Snippet: types.Snippet{
			Before: []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Equal(t, 0.5, result.Confidence)
	assert.Contains(t, result.Message, "500")
}

func TestKeenIOValidator_Validate_PartialCredentials(t *testing.T) {
	v := NewKeenIOValidator()

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
		},
		Snippet: types.Snippet{
			Before:   []byte("no project id here"),
			Matching: []byte("KEEN_READ_KEY=a3b8f29e4d1c6a0578e23d9f41b6c8e2f7d2a1b849c3b05d6e81f2a794c3d5b0"),
			After:    []byte("or here"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

// keenIOMockTransport redirects requests to the mock server
type keenIOMockTransport struct {
	server *httptest.Server
}

func (t *keenIOMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}
