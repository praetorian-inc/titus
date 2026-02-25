// pkg/validator/wpengine_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestWPEngineValidator_Name(t *testing.T) {
	v := NewWPEngineValidator()
	assert.Equal(t, "wpengine", v.Name())
}

func TestWPEngineValidator_CanValidate(t *testing.T) {
	v := NewWPEngineValidator()

	// WPEngine rule
	assert.True(t, v.CanValidate("np.wpengine.1"))

	// Non-WPEngine rules
	assert.False(t, v.CanValidate("np.github.1"))
	assert.False(t, v.CanValidate("np.aws.1"))
	assert.False(t, v.CanValidate("np.slack.1"))
}

func TestWPEngineValidator_ExtractCredentials_Complete(t *testing.T) {
	v := NewWPEngineValidator()

	// Match with key in named groups and account name in Before snippet
	match := &types.Match{
		RuleID: "np.wpengine.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6"),
		},
		Snippet: types.Snippet{
			Before:   []byte("WPE_ACCOUNT_NAME=mysite"),
			Matching: []byte("WPE_APIKEY=a3b8f29e4d1c6a0578e23d9f41b6"),
			After:    []byte(""),
		},
	}

	accountName, apiKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "mysite", accountName)
	assert.Equal(t, "a3b8f29e4d1c6a0578e23d9f41b6", apiKey)
}

func TestWPEngineValidator_ExtractCredentials_AccountNameInAfter(t *testing.T) {
	v := NewWPEngineValidator()

	// Match with account name in after context
	match := &types.Match{
		RuleID: "np.wpengine.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("WPE_APIKEY=a3b8f29e4d1c6a0578e23d9f41b6"),
			After:    []byte("WPENGINE_ACCOUNT=aftersite"),
		},
	}

	accountName, apiKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "aftersite", accountName)
	assert.Equal(t, "a3b8f29e4d1c6a0578e23d9f41b6", apiKey)
}

func TestWPEngineValidator_ExtractCredentials_AccountNameGeneric(t *testing.T) {
	v := NewWPEngineValidator()

	// Match with generic account_name pattern
	match := &types.Match{
		RuleID: "np.wpengine.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6"),
		},
		Snippet: types.Snippet{
			Before:   []byte("account_name=mysite"),
			Matching: []byte("WPE_APIKEY=a3b8f29e4d1c6a0578e23d9f41b6"),
			After:    []byte(""),
		},
	}

	accountName, apiKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "mysite", accountName)
	assert.Equal(t, "a3b8f29e4d1c6a0578e23d9f41b6", apiKey)
}

func TestWPEngineValidator_ExtractCredentials_MissingKey(t *testing.T) {
	v := NewWPEngineValidator()

	// Missing key named group
	match := &types.Match{
		RuleID:      "np.wpengine.1",
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before: []byte("WPE_ACCOUNT_NAME=mysite"),
		},
	}

	accountName, apiKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key")
	assert.Empty(t, accountName)
	assert.Empty(t, apiKey)
}

func TestWPEngineValidator_ExtractCredentials_MissingAccountName(t *testing.T) {
	v := NewWPEngineValidator()

	// Has key but no account name in context
	match := &types.Match{
		RuleID: "np.wpengine.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6"),
		},
		Snippet: types.Snippet{
			Before:   []byte("some other content"),
			Matching: []byte("WPE_APIKEY=a3b8f29e4d1c6a0578e23d9f41b6"),
			After:    []byte("more content"),
		},
	}

	accountName, apiKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial")
	assert.Contains(t, err.Error(), "account name")
	assert.Empty(t, accountName)
	assert.Empty(t, apiKey)
}

func TestWPEngineValidator_ExtractCredentials_NoNamedGroups(t *testing.T) {
	v := NewWPEngineValidator()

	// No named groups at all
	match := &types.Match{
		RuleID:      "np.wpengine.1",
		NamedGroups: nil,
	}

	accountName, apiKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no named capture groups")
	assert.Empty(t, accountName)
	assert.Empty(t, apiKey)
}

func TestWPEngineValidator_Validate_Valid(t *testing.T) {
	// Create mock server that returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify URL contains account_name and wpe_apikey params
		assert.Contains(t, r.URL.RawQuery, "account_name=mysite")
		assert.Contains(t, r.URL.RawQuery, "wpe_apikey=a3b8f29e4d1c6a0578e23d9f41b6")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create validator with custom client that redirects to test server
	v := NewWPEngineValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.wpengine.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6"),
		},
		Snippet: types.Snippet{
			Before: []byte("WPE_ACCOUNT_NAME=mysite"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "mysite")
}

func TestWPEngineValidator_Validate_Invalid_Unauthorized(t *testing.T) {
	// Create mock server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewWPEngineValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.wpengine.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6"),
		},
		Snippet: types.Snippet{
			Before: []byte("WPE_ACCOUNT_NAME=mysite"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "401")
}

func TestWPEngineValidator_Validate_Invalid_Forbidden(t *testing.T) {
	// Create mock server that returns 403 Forbidden
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := NewWPEngineValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.wpengine.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6"),
		},
		Snippet: types.Snippet{
			Before: []byte("WPE_ACCOUNT_NAME=mysite"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "403")
}

func TestWPEngineValidator_Validate_Undetermined_ServerError(t *testing.T) {
	// Create mock server that returns 500 Internal Server Error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewWPEngineValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.wpengine.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6"),
		},
		Snippet: types.Snippet{
			Before: []byte("WPE_ACCOUNT_NAME=mysite"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Equal(t, 0.5, result.Confidence)
	assert.Contains(t, result.Message, "500")
}

func TestWPEngineValidator_Validate_PartialCredentials(t *testing.T) {
	v := NewWPEngineValidator()

	// Missing account name in context
	match := &types.Match{
		RuleID: "np.wpengine.1",
		NamedGroups: map[string][]byte{
			"key": []byte("a3b8f29e4d1c6a0578e23d9f41b6"),
		},
		Snippet: types.Snippet{
			Before:   []byte("no account name here"),
			Matching: []byte("WPE_APIKEY=a3b8f29e4d1c6a0578e23d9f41b6"),
			After:    []byte("or here"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}
