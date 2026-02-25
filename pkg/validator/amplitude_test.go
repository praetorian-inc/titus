// pkg/validator/amplitude_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestAmplitudeValidator_Name(t *testing.T) {
	v := NewAmplitudeValidator()
	assert.Equal(t, "amplitude", v.Name())
}

func TestAmplitudeValidator_CanValidate(t *testing.T) {
	v := NewAmplitudeValidator()
	assert.True(t, v.CanValidate("np.amplitude.1"))
	assert.False(t, v.CanValidate("np.github.1"))
	assert.False(t, v.CanValidate("np.twilio.1"))
}

func TestAmplitudeValidator_ExtractCredentials_SecretInBefore(t *testing.T) {
	v := NewAmplitudeValidator()

	// Match with api_key in named groups and secret in snippet
	match := &types.Match{
		RuleID: "np.amplitude.1",
		NamedGroups: map[string][]byte{
			"api_key": []byte("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
		},
		Snippet: types.Snippet{
			Before:   []byte("AMPLITUDE_SECRET_KEY=f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3"),
			Matching: []byte("AMPLITUDE_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
			After:    []byte(""),
		},
	}

	apiKey, secretKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", apiKey)
	assert.Equal(t, "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3", secretKey)
}

func TestAmplitudeValidator_ExtractCredentials_SecretInAfter(t *testing.T) {
	v := NewAmplitudeValidator()

	// Match with secret in after context
	match := &types.Match{
		RuleID: "np.amplitude.1",
		NamedGroups: map[string][]byte{
			"api_key": []byte("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
		},
		Snippet: types.Snippet{
			Before:   []byte("# Amplitude config"),
			Matching: []byte("AMPLITUDE_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
			After:    []byte("AMPLITUDE_SECRET_KEY=f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3"),
		},
	}

	apiKey, secretKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", apiKey)
	assert.Equal(t, "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3", secretKey)
}

func TestAmplitudeValidator_ExtractCredentials_SecretInMatching(t *testing.T) {
	v := NewAmplitudeValidator()

	// Both credentials on same line
	match := &types.Match{
		RuleID: "np.amplitude.1",
		NamedGroups: map[string][]byte{
			"api_key": []byte("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("AMPLITUDE_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 AMPLITUDE_SECRET_KEY=f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3"),
			After:    []byte(""),
		},
	}

	apiKey, secretKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", apiKey)
	assert.Equal(t, "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3", secretKey)
}

func TestAmplitudeValidator_ExtractCredentials_SecretVariant(t *testing.T) {
	v := NewAmplitudeValidator()

	// AMPLITUDE_SECRET variant
	match := &types.Match{
		RuleID: "np.amplitude.1",
		NamedGroups: map[string][]byte{
			"api_key": []byte("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
		},
		Snippet: types.Snippet{
			Before:   []byte("AMPLITUDE_SECRET=f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3"),
			Matching: []byte("AMPLITUDE_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
			After:    []byte(""),
		},
	}

	apiKey, secretKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", apiKey)
	assert.Equal(t, "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3", secretKey)
}

func TestAmplitudeValidator_ExtractCredentials_GenericSecretKey(t *testing.T) {
	v := NewAmplitudeValidator()

	// Generic secret_key pattern
	match := &types.Match{
		RuleID: "np.amplitude.1",
		NamedGroups: map[string][]byte{
			"api_key": []byte("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
		},
		Snippet: types.Snippet{
			Before:   []byte("secret_key = 'f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3'"),
			Matching: []byte("AMPLITUDE_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
			After:    []byte(""),
		},
	}

	apiKey, secretKey, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", apiKey)
	assert.Equal(t, "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3", secretKey)
}

func TestAmplitudeValidator_ExtractCredentials_MissingAPIKey(t *testing.T) {
	v := NewAmplitudeValidator()

	match := &types.Match{
		RuleID:      "np.amplitude.1",
		NamedGroups: map[string][]byte{}, // No api_key
		Snippet: types.Snippet{
			Before: []byte("AMPLITUDE_SECRET_KEY=f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3"),
		},
	}

	apiKey, secretKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
	assert.Empty(t, apiKey)
	assert.Empty(t, secretKey)
}

func TestAmplitudeValidator_ExtractCredentials_MissingSecret(t *testing.T) {
	v := NewAmplitudeValidator()

	// Has api_key but no secret in context
	match := &types.Match{
		RuleID: "np.amplitude.1",
		NamedGroups: map[string][]byte{
			"api_key": []byte("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
		},
		Snippet: types.Snippet{
			Before:   []byte("# no secret here"),
			Matching: []byte("AMPLITUDE_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
			After:    []byte("# nothing here either"),
		},
	}

	apiKey, secretKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial credentials")
	assert.Empty(t, apiKey)
	assert.Empty(t, secretKey)
}

func TestAmplitudeValidator_ExtractCredentials_NoNamedGroups(t *testing.T) {
	v := NewAmplitudeValidator()

	// No named groups at all
	match := &types.Match{
		RuleID:      "np.amplitude.1",
		NamedGroups: nil,
	}

	apiKey, secretKey, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no named capture groups")
	assert.Empty(t, apiKey)
	assert.Empty(t, secretKey)
}

func TestAmplitudeValidator_Validate_ValidCredentials(t *testing.T) {
	// Mock server returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Basic auth header is present
		auth := r.Header.Get("Authorization")
		assert.Contains(t, auth, "Basic ")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create validator with custom client that redirects to mock server
	v := NewAmplitudeValidatorWithClient(&http.Client{
		Transport: &amplitudeMockTransport{
			server: server,
		},
	})

	match := &types.Match{
		RuleID: "np.amplitude.1",
		NamedGroups: map[string][]byte{
			"api_key": []byte("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
		},
		Snippet: types.Snippet{
			Before: []byte("AMPLITUDE_SECRET_KEY=f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestAmplitudeValidator_Validate_InvalidCredentials(t *testing.T) {
	// Mock server returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewAmplitudeValidatorWithClient(&http.Client{
		Transport: &amplitudeMockTransport{
			server: server,
		},
	})

	match := &types.Match{
		RuleID: "np.amplitude.1",
		NamedGroups: map[string][]byte{
			"api_key": []byte("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
		},
		Snippet: types.Snippet{
			Before: []byte("AMPLITUDE_SECRET_KEY=f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestAmplitudeValidator_Validate_PartialCredentials(t *testing.T) {
	v := NewAmplitudeValidator()

	// Missing secret in context
	match := &types.Match{
		RuleID: "np.amplitude.1",
		NamedGroups: map[string][]byte{
			"api_key": []byte("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
		},
		Snippet: types.Snippet{
			Before:   []byte("no secret here"),
			Matching: []byte("AMPLITUDE_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
			After:    []byte("no secret here either"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

// amplitudeMockTransport redirects requests to the mock server
type amplitudeMockTransport struct {
	server *httptest.Server
}

func (t *amplitudeMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite URL to mock server
	req.URL.Scheme = "http"
	req.URL.Host = t.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}
