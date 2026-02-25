// pkg/validator/browserstack_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestBrowserStackValidator_Name(t *testing.T) {
	v := NewBrowserStackValidator()
	assert.Equal(t, "browserstack", v.Name())
}

func TestBrowserStackValidator_CanValidate(t *testing.T) {
	v := NewBrowserStackValidator()

	// BrowserStack rule
	assert.True(t, v.CanValidate("np.browserstack.1"))

	// Non-BrowserStack rules
	assert.False(t, v.CanValidate("np.github.1"))
	assert.False(t, v.CanValidate("np.aws.1"))
	assert.False(t, v.CanValidate("np.sauce.1"))
}

func TestBrowserStackValidator_ExtractCredentials_Complete(t *testing.T) {
	v := NewBrowserStackValidator()

	// Match with access_key in named groups and username in snippet
	match := &types.Match{
		RuleID: "np.browserstack.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("qA1bC2dE3fG4hI5jK6lM"),
		},
		Snippet: types.Snippet{
			Before:   []byte("BROWSERSTACK_USERNAME=testuser"),
			Matching: []byte("BROWSERSTACK_ACCESS_KEY=qA1bC2dE3fG4hI5jK6lM"),
			After:    []byte(""),
		},
	}

	username, accessKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", username)
	assert.Equal(t, "qA1bC2dE3fG4hI5jK6lM", accessKey)
}

func TestBrowserStackValidator_ExtractCredentials_UsernameInAfter(t *testing.T) {
	v := NewBrowserStackValidator()

	// Match with username in after context
	match := &types.Match{
		RuleID: "np.browserstack.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("qA1bC2dE3fG4hI5jK6lM"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("BROWSERSTACK_ACCESS_KEY=qA1bC2dE3fG4hI5jK6lM"),
			After:    []byte("BROWSERSTACK_USERNAME=afteruser"),
		},
	}

	username, accessKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "afteruser", username)
	assert.Equal(t, "qA1bC2dE3fG4hI5jK6lM", accessKey)
}

func TestBrowserStackValidator_ExtractCredentials_UsernameInMatching(t *testing.T) {
	v := NewBrowserStackValidator()

	// Match with both on same line
	match := &types.Match{
		RuleID: "np.browserstack.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("qA1bC2dE3fG4hI5jK6lM"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("BROWSERSTACK_USERNAME=samelineuser BROWSERSTACK_ACCESS_KEY=qA1bC2dE3fG4hI5jK6lM"),
			After:    []byte(""),
		},
	}

	username, accessKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "samelineuser", username)
	assert.Equal(t, "qA1bC2dE3fG4hI5jK6lM", accessKey)
}

func TestBrowserStackValidator_ExtractCredentials_UserVariant(t *testing.T) {
	v := NewBrowserStackValidator()

	// Match with BROWSERSTACK_USER variant
	match := &types.Match{
		RuleID: "np.browserstack.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("qA1bC2dE3fG4hI5jK6lM"),
		},
		Snippet: types.Snippet{
			Before:   []byte("BROWSERSTACK_USER=variantuser"),
			Matching: []byte("BROWSERSTACK_ACCESS_KEY=qA1bC2dE3fG4hI5jK6lM"),
			After:    []byte(""),
		},
	}

	username, accessKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "variantuser", username)
	assert.Equal(t, "qA1bC2dE3fG4hI5jK6lM", accessKey)
}

func TestBrowserStackValidator_ExtractCredentials_MissingAccessKey(t *testing.T) {
	v := NewBrowserStackValidator()

	// Missing access_key named group
	match := &types.Match{
		RuleID:      "np.browserstack.1",
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before: []byte("BROWSERSTACK_USERNAME=testuser"),
		},
	}

	username, accessKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access_key")
	assert.Empty(t, username)
	assert.Empty(t, accessKey)
}

func TestBrowserStackValidator_ExtractCredentials_MissingUsername(t *testing.T) {
	v := NewBrowserStackValidator()

	// Has access_key but no username in context
	match := &types.Match{
		RuleID: "np.browserstack.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("qA1bC2dE3fG4hI5jK6lM"),
		},
		Snippet: types.Snippet{
			Before:   []byte("some other content"),
			Matching: []byte("BROWSERSTACK_ACCESS_KEY=qA1bC2dE3fG4hI5jK6lM"),
			After:    []byte("more content"),
		},
	}

	username, accessKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial")
	assert.Contains(t, err.Error(), "BROWSERSTACK_USERNAME")
	assert.Empty(t, username)
	assert.Empty(t, accessKey)
}

func TestBrowserStackValidator_ExtractCredentials_NoNamedGroups(t *testing.T) {
	v := NewBrowserStackValidator()

	// No named groups at all
	match := &types.Match{
		RuleID:      "np.browserstack.1",
		NamedGroups: nil,
	}

	username, accessKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no named capture groups")
	assert.Empty(t, username)
	assert.Empty(t, accessKey)
}

func TestBrowserStackValidator_Validate_Valid(t *testing.T) {
	// Create mock server that returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Basic auth header is present
		auth := r.Header.Get("Authorization")
		assert.Contains(t, auth, "Basic ")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create validator with custom client that redirects to test server
	v := NewBrowserStackValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.browserstack.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("qA1bC2dE3fG4hI5jK6lM"),
		},
		Snippet: types.Snippet{
			Before: []byte("BROWSERSTACK_USERNAME=testuser"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "testuser")
}

func TestBrowserStackValidator_Validate_Invalid_Unauthorized(t *testing.T) {
	// Create mock server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewBrowserStackValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.browserstack.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("invalid-key-1234567890"),
		},
		Snippet: types.Snippet{
			Before: []byte("BROWSERSTACK_USERNAME=testuser"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "401")
}

func TestBrowserStackValidator_Validate_Invalid_Forbidden(t *testing.T) {
	// Create mock server that returns 403 Forbidden
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := NewBrowserStackValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.browserstack.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("qA1bC2dE3fG4hI5jK6lM"),
		},
		Snippet: types.Snippet{
			Before: []byte("BROWSERSTACK_USERNAME=testuser"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "403")
}

func TestBrowserStackValidator_Validate_Undetermined_ServerError(t *testing.T) {
	// Create mock server that returns 500 Internal Server Error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewBrowserStackValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.browserstack.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("qA1bC2dE3fG4hI5jK6lM"),
		},
		Snippet: types.Snippet{
			Before: []byte("BROWSERSTACK_USERNAME=testuser"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Equal(t, 0.5, result.Confidence)
	assert.Contains(t, result.Message, "500")
}

func TestBrowserStackValidator_Validate_PartialCredentials(t *testing.T) {
	v := NewBrowserStackValidator()

	// Missing username in context
	match := &types.Match{
		RuleID: "np.browserstack.1",
		NamedGroups: map[string][]byte{
			"access_key": []byte("qA1bC2dE3fG4hI5jK6lM"),
		},
		Snippet: types.Snippet{
			Before:   []byte("no username here"),
			Matching: []byte("BROWSERSTACK_ACCESS_KEY=qA1bC2dE3fG4hI5jK6lM"),
			After:    []byte("or here"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}
