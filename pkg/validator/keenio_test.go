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
			"key": []byte("A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
		},
		Snippet: types.Snippet{
			Before:   []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
			Matching: []byte("KEEN_READ_KEY=A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
			After:    []byte(""),
		},
	}

	apiKey, projectID, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0", apiKey)
	assert.Equal(t, "5f3c8d2b1a4e7c9d0b2a3f4e", projectID)
}

func TestKeenIOValidator_ExtractCredentials_ProjectIDInAfter(t *testing.T) {
	v := NewKeenIOValidator()

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("KEEN_READ_KEY=A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
			After:    []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
		},
	}

	apiKey, projectID, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0", apiKey)
	assert.Equal(t, "5f3c8d2b1a4e7c9d0b2a3f4e", projectID)
}

func TestKeenIOValidator_ExtractCredentials_ProjectIDInMatching(t *testing.T) {
	v := NewKeenIOValidator()

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e KEEN_READ_KEY=A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
			After:    []byte(""),
		},
	}

	apiKey, projectID, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0", apiKey)
	assert.Equal(t, "5f3c8d2b1a4e7c9d0b2a3f4e", projectID)
}

func TestKeenIOValidator_ExtractCredentials_GenericProjectIDPattern(t *testing.T) {
	v := NewKeenIOValidator()

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
		},
		Snippet: types.Snippet{
			Before:   []byte("project_id: '5f3c8d2b1a4e7c9d0b2a3f4e'"),
			Matching: []byte("KEEN_READ_KEY=A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
			After:    []byte(""),
		},
	}

	apiKey, projectID, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0", apiKey)
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
			"key": []byte("A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
		},
		Snippet: types.Snippet{
			Before:   []byte("some other content"),
			Matching: []byte("KEEN_READ_KEY=A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
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

// --- Validation tests ---

func TestKeenIOValidator_Validate_ValidReadKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0", r.Header.Get("Authorization"))
		assert.Contains(t, r.URL.Path, "/events")
		assert.Equal(t, "GET", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewKeenIOValidatorWithClient(&http.Client{
		Transport: &keenIOMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
		},
		Snippet: types.Snippet{
			Before: []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "read key")
	assert.Contains(t, result.Message, "5f3c8d2b1a4e7c9d0b2a3f4e")
}

func TestKeenIOValidator_Validate_ValidWriteKey(t *testing.T) {
	// Write key: 403 on read endpoint, 201 on write endpoint
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == "GET" && callCount == 1 {
			// Read endpoint returns 403 for write key
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Method == "POST" {
			// Write endpoint accepts
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := NewKeenIOValidatorWithClient(&http.Client{
		Transport: &keenIOMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("B4C9E38F5D2A7B1068F34E0A52C7D9F3G8E3B2C950D4A16E7F92B3A805D4C6E1"),
		},
		Snippet: types.Snippet{
			Before: []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "write key")
}

func TestKeenIOValidator_Validate_ValidMasterKey(t *testing.T) {
	// Master key: 403 on read and write endpoints, 200 on project endpoint
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 2 {
			// Read and write endpoints return 403 for master key
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// Master/project endpoint returns 200
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewKeenIOValidatorWithClient(&http.Client{
		Transport: &keenIOMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("C5D0F49G6E3B8C2179G45F1B63D8E0A4H9F4C3D061E5B27F8A3C4B916E5D7F2"),
		},
		Snippet: types.Snippet{
			Before: []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "master key")
}

func TestKeenIOValidator_Validate_AllForbidden_StillValid(t *testing.T) {
	// Key that gets 403 on ALL endpoints — valid but restricted (e.g., custom access key)
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
			"key": []byte("D6E1G50H7F4C9D3280H56G2C74E9F1B5I0G5D4E172F6C38G9B4D5C027F6E8G3"),
		},
		Snippet: types.Snippet{
			Before: []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 0.8, result.Confidence)
	assert.Contains(t, result.Message, "restricted permissions")
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
			"key": []byte("0000000000000000000000000000000000000000000000000000000000000001"),
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
			"key": []byte("A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
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
			"key": []byte("A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
		},
		Snippet: types.Snippet{
			Before:   []byte("no project id here"),
			Matching: []byte("KEEN_READ_KEY=A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
			After:    []byte("or here"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

func TestKeenIOValidator_Validate_AuthorizationHeaderUsed(t *testing.T) {
	// Verify the Authorization header is set (not query parameter)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Must use Authorization header, not query param
		assert.NotEmpty(t, r.Header.Get("Authorization"))
		assert.Empty(t, r.URL.Query().Get("api_key"), "should not use query param auth")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewKeenIOValidatorWithClient(&http.Client{
		Transport: &keenIOMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.keenio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("A3B8F29E4D1C6A0578E23D9F41B6C8E2F7D2A1B849C3B05D6E81F2A794C3D5B0"),
		},
		Snippet: types.Snippet{
			Before: []byte("KEEN_PROJECT_ID=5f3c8d2b1a4e7c9d0b2a3f4e"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
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
