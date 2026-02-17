// pkg/validator/saucelabs_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestSauceLabsValidator_Name(t *testing.T) {
	v := NewSauceLabsValidator()
	assert.Equal(t, "saucelabs", v.Name())
}

func TestSauceLabsValidator_CanValidate(t *testing.T) {
	v := NewSauceLabsValidator()

	// SauceLabs rule
	assert.True(t, v.CanValidate("np.sauce.1"))

	// Non-SauceLabs rules
	assert.False(t, v.CanValidate("np.github.1"))
	assert.False(t, v.CanValidate("np.aws.1"))
	assert.False(t, v.CanValidate("np.slack.1"))
}

func TestSauceLabsValidator_ExtractCredentials_Complete(t *testing.T) {
	v := NewSauceLabsValidator()

	// Match with access_key in named groups and username in snippet
	match := &types.Match{
		RuleID: "np.sauce.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("2397f603-c2c4-4897-a8ca-587ace5dc8dd"),
		},
		Snippet: types.Snippet{
			Before:   []byte("SAUCE_USERNAME=testuser"),
			Matching: []byte("SAUCE_ACCESS_KEY=2397f603-c2c4-4897-a8ca-587ace5dc8dd"),
			After:    []byte(""),
		},
	}

	username, accessKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", username)
	assert.Equal(t, "2397f603-c2c4-4897-a8ca-587ace5dc8dd", accessKey)
}

func TestSauceLabsValidator_ExtractCredentials_UsernameInAfter(t *testing.T) {
	v := NewSauceLabsValidator()

	// Match with username in after context
	match := &types.Match{
		RuleID: "np.sauce.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("2397f603-c2c4-4897-a8ca-587ace5dc8dd"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("SAUCE_ACCESS_KEY=2397f603-c2c4-4897-a8ca-587ace5dc8dd"),
			After:    []byte("SAUCE_USERNAME=afteruser"),
		},
	}

	username, accessKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "afteruser", username)
	assert.Equal(t, "2397f603-c2c4-4897-a8ca-587ace5dc8dd", accessKey)
}

func TestSauceLabsValidator_ExtractCredentials_UsernameInMatching(t *testing.T) {
	v := NewSauceLabsValidator()

	// Match with both on same line
	match := &types.Match{
		RuleID: "np.sauce.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("2397f603-c2c4-4897-a8ca-587ace5dc8dd"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("SAUCE_USERNAME=samelineuser SAUCE_ACCESS_KEY=2397f603-c2c4-4897-a8ca-587ace5dc8dd"),
			After:    []byte(""),
		},
	}

	username, accessKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "samelineuser", username)
	assert.Equal(t, "2397f603-c2c4-4897-a8ca-587ace5dc8dd", accessKey)
}

func TestSauceLabsValidator_ExtractCredentials_MissingAccessKey(t *testing.T) {
	v := NewSauceLabsValidator()

	// Missing access_key named group
	match := &types.Match{
		RuleID:      "np.sauce.1",
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before: []byte("SAUCE_USERNAME=testuser"),
		},
	}

	username, accessKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access_key")
	assert.Empty(t, username)
	assert.Empty(t, accessKey)
}

func TestSauceLabsValidator_ExtractCredentials_MissingUsername(t *testing.T) {
	v := NewSauceLabsValidator()

	// Has access_key but no username in context
	match := &types.Match{
		RuleID: "np.sauce.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("2397f603-c2c4-4897-a8ca-587ace5dc8dd"),
		},
		Snippet: types.Snippet{
			Before:   []byte("some other content"),
			Matching: []byte("SAUCE_ACCESS_KEY=2397f603-c2c4-4897-a8ca-587ace5dc8dd"),
			After:    []byte("more content"),
		},
	}

	username, accessKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial")
	assert.Contains(t, err.Error(), "SAUCE_USERNAME")
	assert.Empty(t, username)
	assert.Empty(t, accessKey)
}

func TestSauceLabsValidator_ExtractCredentials_NoNamedGroups(t *testing.T) {
	v := NewSauceLabsValidator()

	// No named groups at all
	match := &types.Match{
		RuleID:      "np.sauce.1",
		NamedGroups: nil,
	}

	username, accessKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no named capture groups")
	assert.Empty(t, username)
	assert.Empty(t, accessKey)
}

func TestSauceLabsValidator_Validate_Valid(t *testing.T) {
	// Create mock server that returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Basic auth header is present
		auth := r.Header.Get("Authorization")
		assert.Contains(t, auth, "Basic ")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create validator with custom client that redirects to test server
	v := NewSauceLabsValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.sauce.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("2397f603-c2c4-4897-a8ca-587ace5dc8dd"),
		},
		Snippet: types.Snippet{
			Before: []byte("SAUCE_USERNAME=testuser"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "testuser")
}

func TestSauceLabsValidator_Validate_Invalid_Unauthorized(t *testing.T) {
	// Create mock server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewSauceLabsValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.sauce.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("invalid-key-12345678901234567890"),
		},
		Snippet: types.Snippet{
			Before: []byte("SAUCE_USERNAME=testuser"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "401")
}

func TestSauceLabsValidator_Validate_Invalid_Forbidden(t *testing.T) {
	// Create mock server that returns 403 Forbidden
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := NewSauceLabsValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.sauce.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("2397f603-c2c4-4897-a8ca-587ace5dc8dd"),
		},
		Snippet: types.Snippet{
			Before: []byte("SAUCE_USERNAME=testuser"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "403")
}

func TestSauceLabsValidator_Validate_Undetermined_ServerError(t *testing.T) {
	// Create mock server that returns 500 Internal Server Error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewSauceLabsValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.sauce.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("2397f603-c2c4-4897-a8ca-587ace5dc8dd"),
		},
		Snippet: types.Snippet{
			Before: []byte("SAUCE_USERNAME=testuser"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Equal(t, 0.5, result.Confidence)
	assert.Contains(t, result.Message, "500")
}

func TestSauceLabsValidator_Validate_PartialCredentials(t *testing.T) {
	v := NewSauceLabsValidator()

	// Missing username in context
	match := &types.Match{
		RuleID: "np.sauce.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("2397f603-c2c4-4897-a8ca-587ace5dc8dd"),
		},
		Snippet: types.Snippet{
			Before:   []byte("no username here"),
			Matching: []byte("SAUCE_ACCESS_KEY=2397f603-c2c4-4897-a8ca-587ace5dc8dd"),
			After:    []byte("or here"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

// testTransport redirects all requests to a test server URL
type testTransport struct {
	url string
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirect to test server
	req.URL.Scheme = "http"
	req.URL.Host = t.url[7:] // Strip "http://"
	return http.DefaultTransport.RoundTrip(req)
}
