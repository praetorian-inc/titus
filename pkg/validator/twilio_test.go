// pkg/validator/twilio_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestTwilioValidator_Name(t *testing.T) {
	v := NewTwilioValidator()
	assert.Equal(t, "twilio", v.Name())
}

func TestTwilioValidator_CanValidate(t *testing.T) {
	v := NewTwilioValidator()
	assert.True(t, v.CanValidate("np.twilio.1"))
	assert.False(t, v.CanValidate("np.github.1"))
	assert.False(t, v.CanValidate("np.sendgrid.1"))
}

func TestTwilioValidator_ExtractCredentials_SecretInBefore(t *testing.T) {
	v := NewTwilioValidator()

	// Match with key_sid in named groups and secret in snippet
	match := &types.Match{
		RuleID: "np.twilio.1",
		NamedGroups: map[string][]byte{
			"key_sid": []byte("SK9b4cc552783500ace5414a1ed3e9fd1a"),
		},
		Snippet: types.Snippet{
			Before:   []byte("TWILIO_API_SECRET=l6LUelKF2BUtMLace5oShZSmRppadYqI"),
			Matching: []byte("TWILIO_API_KEY=SK9b4cc552783500ace5414a1ed3e9fd1a"),
			After:    []byte(""),
		},
	}

	keySID, keySecret, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "SK9b4cc552783500ace5414a1ed3e9fd1a", keySID)
	assert.Equal(t, "l6LUelKF2BUtMLace5oShZSmRppadYqI", keySecret)
}

func TestTwilioValidator_ExtractCredentials_SecretInAfter(t *testing.T) {
	v := NewTwilioValidator()

	// Match with secret in after context
	match := &types.Match{
		RuleID: "np.twilio.1",
		NamedGroups: map[string][]byte{
			"key_sid": []byte("SK9b4cc552783500ace5414a1ed3e9fd1a"),
		},
		Snippet: types.Snippet{
			Before:   []byte("# Twilio config"),
			Matching: []byte("TWILIO_API_KEY=SK9b4cc552783500ace5414a1ed3e9fd1a"),
			After:    []byte("TWILIO_AUTH_TOKEN=wbTs1SUt6Aace5eKeNCxuYvJa6PhaRd0"),
		},
	}

	keySID, keySecret, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "SK9b4cc552783500ace5414a1ed3e9fd1a", keySID)
	assert.Equal(t, "wbTs1SUt6Aace5eKeNCxuYvJa6PhaRd0", keySecret)
}

func TestTwilioValidator_ExtractCredentials_SecretInMatching(t *testing.T) {
	v := NewTwilioValidator()

	// Both credentials on same line
	match := &types.Match{
		RuleID: "np.twilio.1",
		NamedGroups: map[string][]byte{
			"key_sid": []byte("SK9b4cc552783500ace5414a1ed3e9fd1a"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("TWILIO_API_KEY=SK9b4cc552783500ace5414a1ed3e9fd1a TWILIO_API_SECRET=l6LUelKF2BUtMLace5oShZSmRppadYqI"),
			After:    []byte(""),
		},
	}

	keySID, keySecret, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "SK9b4cc552783500ace5414a1ed3e9fd1a", keySID)
	assert.Equal(t, "l6LUelKF2BUtMLace5oShZSmRppadYqI", keySecret)
}

func TestTwilioValidator_ExtractCredentials_CamelCasePattern(t *testing.T) {
	v := NewTwilioValidator()

	// JavaScript/TypeScript style
	match := &types.Match{
		RuleID: "np.twilio.1",
		NamedGroups: map[string][]byte{
			"key_sid": []byte("SK9b4cc552783500ace5414a1ed3e9fd1a"),
		},
		Snippet: types.Snippet{
			Before:   []byte("const twilioApiKeySecret = 'l6LUelKF2BUtMLace5oShZSmRppadYqI'"),
			Matching: []byte("const twilioApiKeySID = 'SK9b4cc552783500ace5414a1ed3e9fd1a'"),
			After:    []byte(""),
		},
	}

	keySID, keySecret, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "SK9b4cc552783500ace5414a1ed3e9fd1a", keySID)
	assert.Equal(t, "l6LUelKF2BUtMLace5oShZSmRppadYqI", keySecret)
}

func TestTwilioValidator_ExtractCredentials_MissingKeySID(t *testing.T) {
	v := NewTwilioValidator()

	match := &types.Match{
		RuleID:      "np.twilio.1",
		NamedGroups: map[string][]byte{}, // No key_sid
		Snippet: types.Snippet{
			Before: []byte("TWILIO_API_SECRET=l6LUelKF2BUtMLace5oShZSmRppadYqI"),
		},
	}

	keySID, keySecret, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key_sid")
	assert.Empty(t, keySID)
	assert.Empty(t, keySecret)
}

func TestTwilioValidator_ExtractCredentials_MissingSecret(t *testing.T) {
	v := NewTwilioValidator()

	// Has key_sid but no secret in context
	match := &types.Match{
		RuleID: "np.twilio.1",
		NamedGroups: map[string][]byte{
			"key_sid": []byte("SK9b4cc552783500ace5414a1ed3e9fd1a"),
		},
		Snippet: types.Snippet{
			Before:   []byte("# no secret here"),
			Matching: []byte("TWILIO_API_KEY=SK9b4cc552783500ace5414a1ed3e9fd1a"),
			After:    []byte("# nothing here either"),
		},
	}

	keySID, keySecret, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial credentials")
	assert.Empty(t, keySID)
	assert.Empty(t, keySecret)
}

func TestTwilioValidator_Validate_ValidCredentials(t *testing.T) {
	// Mock server returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Basic auth header is present
		auth := r.Header.Get("Authorization")
		assert.Contains(t, auth, "Basic ")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create validator with custom client that redirects to mock server
	v := NewTwilioValidatorWithClient(&http.Client{
		Transport: &twilioMockTransport{
			server: server,
		},
	})

	match := &types.Match{
		RuleID: "np.twilio.1",
		NamedGroups: map[string][]byte{
			"key_sid": []byte("SK9b4cc552783500ace5414a1ed3e9fd1a"),
		},
		Snippet: types.Snippet{
			Before: []byte("TWILIO_API_SECRET=l6LUelKF2BUtMLace5oShZSmRppadYqI"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestTwilioValidator_Validate_InvalidCredentials(t *testing.T) {
	// Mock server returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewTwilioValidatorWithClient(&http.Client{
		Transport: &twilioMockTransport{
			server: server,
		},
	})

	match := &types.Match{
		RuleID: "np.twilio.1",
		NamedGroups: map[string][]byte{
			"key_sid": []byte("SK9b4cc552783500ace5414a1ed3e9fd1a"),
		},
		Snippet: types.Snippet{
			Before: []byte("TWILIO_API_SECRET=l6LUelKF2BUtMLace5oShZSmRppadYqI"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestTwilioValidator_Validate_PartialCredentials(t *testing.T) {
	v := NewTwilioValidator()

	// Missing secret in context
	match := &types.Match{
		RuleID: "np.twilio.1",
		NamedGroups: map[string][]byte{
			"key_sid": []byte("SK9b4cc552783500ace5414a1ed3e9fd1a"),
		},
		Snippet: types.Snippet{
			Before:   []byte("no secret here"),
			Matching: []byte("TWILIO_API_KEY=SK9b4cc552783500ace5414a1ed3e9fd1a"),
			After:    []byte("no secret here either"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

// twilioMockTransport redirects requests to the mock server
type twilioMockTransport struct {
	server *httptest.Server
}

func (t *twilioMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite URL to mock server
	req.URL.Scheme = "http"
	req.URL.Host = t.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}
