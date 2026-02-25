// pkg/validator/cypress_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestCypressValidator_Name(t *testing.T) {
	v := NewCypressValidator()
	assert.Equal(t, "cypress", v.Name())
}

func TestCypressValidator_CanValidate(t *testing.T) {
	v := NewCypressValidator()
	assert.True(t, v.CanValidate("np.cypress.1"))
	assert.False(t, v.CanValidate("np.github.1"))
	assert.False(t, v.CanValidate("np.cypress.2"))
}

func TestCypressValidator_ExtractCredentials_ProjectIDInBefore(t *testing.T) {
	v := NewCypressValidator()

	match := &types.Match{
		RuleID: "np.cypress.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
		},
		Snippet: types.Snippet{
			Before:   []byte("CYPRESS_PROJECT_ID=abc123"),
			Matching: []byte("CYPRESS_RECORD_KEY=a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
			After:    []byte(""),
		},
	}

	projectID, recordKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "abc123", projectID)
	assert.Equal(t, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", recordKey)
}

func TestCypressValidator_ExtractCredentials_ProjectIDInAfter(t *testing.T) {
	v := NewCypressValidator()

	match := &types.Match{
		RuleID: "np.cypress.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("CYPRESS_RECORD_KEY=a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
			After:    []byte("projectId: 'xyz789'"),
		},
	}

	projectID, recordKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "xyz789", projectID)
	assert.Equal(t, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", recordKey)
}

func TestCypressValidator_ExtractCredentials_ProjectIDInMatching(t *testing.T) {
	v := NewCypressValidator()

	match := &types.Match{
		RuleID: "np.cypress.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("project_id=abc123 CYPRESS_RECORD_KEY=a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
			After:    []byte(""),
		},
	}

	projectID, recordKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "abc123", projectID)
	assert.Equal(t, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", recordKey)
}

func TestCypressValidator_ExtractCredentials_MissingKey(t *testing.T) {
	v := NewCypressValidator()

	match := &types.Match{
		RuleID:      "np.cypress.1",
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before: []byte("CYPRESS_PROJECT_ID=abc123"),
		},
	}

	projectID, recordKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key")
	assert.Empty(t, projectID)
	assert.Empty(t, recordKey)
}

func TestCypressValidator_ExtractCredentials_MissingProjectID(t *testing.T) {
	v := NewCypressValidator()

	match := &types.Match{
		RuleID: "np.cypress.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
		},
		Snippet: types.Snippet{
			Before:   []byte("no project id here"),
			Matching: []byte("CYPRESS_RECORD_KEY=a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
			After:    []byte("nothing here either"),
		},
	}

	projectID, recordKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial credentials")
	assert.Empty(t, projectID)
	assert.Empty(t, recordKey)
}

func TestCypressValidator_ExtractCredentials_NoNamedGroups(t *testing.T) {
	v := NewCypressValidator()

	match := &types.Match{
		RuleID:      "np.cypress.1",
		NamedGroups: nil,
	}

	projectID, recordKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no named capture groups")
	assert.Empty(t, projectID)
	assert.Empty(t, recordKey)
}

func TestCypressValidator_Validate_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "4", r.Header.Get("x-route-version"))
		assert.Equal(t, "darwin", r.Header.Get("x-os-name"))
		assert.Equal(t, "5.5.0", r.Header.Get("x-cypress-version"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewCypressValidatorWithClient(&http.Client{
		Transport: &cypressMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.cypress.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
		},
		Snippet: types.Snippet{
			Before: []byte("CYPRESS_PROJECT_ID=abc123"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "abc123")
}

func TestCypressValidator_Validate_InvalidKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewCypressValidatorWithClient(&http.Client{
		Transport: &cypressMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.cypress.1",
		NamedGroups: map[string][]byte{
			"key": []byte("invalid0-0000-0000-0000-000000000000"),
		},
		Snippet: types.Snippet{
			Before: []byte("CYPRESS_PROJECT_ID=abc123"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "401")
}

func TestCypressValidator_Validate_InvalidProjectID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	v := NewCypressValidatorWithClient(&http.Client{
		Transport: &cypressMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.cypress.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
		},
		Snippet: types.Snippet{
			Before: []byte("CYPRESS_PROJECT_ID=abc123"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "404")
}

func TestCypressValidator_Validate_Undetermined_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewCypressValidatorWithClient(&http.Client{
		Transport: &cypressMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.cypress.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
		},
		Snippet: types.Snippet{
			Before: []byte("CYPRESS_PROJECT_ID=abc123"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Equal(t, 0.5, result.Confidence)
	assert.Contains(t, result.Message, "500")
}

func TestCypressValidator_Validate_PartialCredentials(t *testing.T) {
	v := NewCypressValidator()

	match := &types.Match{
		RuleID: "np.cypress.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
		},
		Snippet: types.Snippet{
			Before:   []byte("no project id here"),
			Matching: []byte("CYPRESS_RECORD_KEY=a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
			After:    []byte("or here"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

// cypressMockTransport redirects requests to the mock server
type cypressMockTransport struct {
	server *httptest.Server
}

func (t *cypressMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}
