// pkg/validator/helpscout_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestHelpScoutValidator_Name(t *testing.T) {
	v := NewHelpScoutValidator()
	assert.Equal(t, "helpscout", v.Name())
}

func TestHelpScoutValidator_CanValidate(t *testing.T) {
	v := NewHelpScoutValidator()
	assert.True(t, v.CanValidate("np.helpscout.1"))
	assert.False(t, v.CanValidate("np.github.1"))
	assert.False(t, v.CanValidate("np.helpscout.2"))
}

func TestHelpScoutValidator_ExtractCredentials_ClientIDInBefore(t *testing.T) {
	v := NewHelpScoutValidator()

	match := &types.Match{
		RuleID: "np.helpscout.1",
		NamedGroups: map[string][]byte{
			"secret": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
		},
		Snippet: types.Snippet{
			Before:   []byte("HELPSCOUT_CLIENT_ID=a1b2c3d4e5f6a7b8c9d0"),
			Matching: []byte("HELPSCOUT_CLIENT_SECRET=a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
			After:    []byte(""),
		},
	}

	clientID, clientSecret, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "a1b2c3d4e5f6a7b8c9d0", clientID)
	assert.Equal(t, "a3B8f29E4d1C6a0578e23D9f41b6C8e2", clientSecret)
}

func TestHelpScoutValidator_ExtractCredentials_ClientIDInAfter(t *testing.T) {
	v := NewHelpScoutValidator()

	match := &types.Match{
		RuleID: "np.helpscout.1",
		NamedGroups: map[string][]byte{
			"secret": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("HELPSCOUT_CLIENT_SECRET=a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
			After:    []byte("HELPSCOUT_APP_ID=x9y8z7w6v5u4t3s2r1q0"),
		},
	}

	clientID, clientSecret, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "x9y8z7w6v5u4t3s2r1q0", clientID)
	assert.Equal(t, "a3B8f29E4d1C6a0578e23D9f41b6C8e2", clientSecret)
}

func TestHelpScoutValidator_ExtractCredentials_ClientIDInMatching(t *testing.T) {
	v := NewHelpScoutValidator()

	match := &types.Match{
		RuleID: "np.helpscout.1",
		NamedGroups: map[string][]byte{
			"secret": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("client_id=a1b2c3d4e5f6a7b8c9d0 HELPSCOUT_CLIENT_SECRET=a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
			After:    []byte(""),
		},
	}

	clientID, clientSecret, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "a1b2c3d4e5f6a7b8c9d0", clientID)
	assert.Equal(t, "a3B8f29E4d1C6a0578e23D9f41b6C8e2", clientSecret)
}

func TestHelpScoutValidator_ExtractCredentials_ApplicationIDPattern(t *testing.T) {
	v := NewHelpScoutValidator()

	match := &types.Match{
		RuleID: "np.helpscout.1",
		NamedGroups: map[string][]byte{
			"secret": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
		},
		Snippet: types.Snippet{
			Before:   []byte("application_id = 'a1b2c3d4e5f6a7b8c9d0'"),
			Matching: []byte("HELPSCOUT_CLIENT_SECRET=a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
			After:    []byte(""),
		},
	}

	clientID, clientSecret, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "a1b2c3d4e5f6a7b8c9d0", clientID)
	assert.Equal(t, "a3B8f29E4d1C6a0578e23D9f41b6C8e2", clientSecret)
}

func TestHelpScoutValidator_ExtractCredentials_MissingSecret(t *testing.T) {
	v := NewHelpScoutValidator()

	match := &types.Match{
		RuleID:      "np.helpscout.1",
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before: []byte("HELPSCOUT_CLIENT_ID=a1b2c3d4e5f6a7b8c9d0"),
		},
	}

	clientID, clientSecret, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secret")
	assert.Empty(t, clientID)
	assert.Empty(t, clientSecret)
}

func TestHelpScoutValidator_ExtractCredentials_MissingClientID(t *testing.T) {
	v := NewHelpScoutValidator()

	match := &types.Match{
		RuleID: "np.helpscout.1",
		NamedGroups: map[string][]byte{
			"secret": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
		},
		Snippet: types.Snippet{
			Before:   []byte("no client id here"),
			Matching: []byte("HELPSCOUT_CLIENT_SECRET=a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
			After:    []byte("nothing here either"),
		},
	}

	clientID, clientSecret, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial credentials")
	assert.Empty(t, clientID)
	assert.Empty(t, clientSecret)
}

func TestHelpScoutValidator_ExtractCredentials_NoNamedGroups(t *testing.T) {
	v := NewHelpScoutValidator()

	match := &types.Match{
		RuleID:      "np.helpscout.1",
		NamedGroups: nil,
	}

	clientID, clientSecret, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no named capture groups")
	assert.Empty(t, clientID)
	assert.Empty(t, clientSecret)
}

func TestHelpScoutValidator_Validate_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewHelpScoutValidatorWithClient(&http.Client{
		Transport: &helpScoutMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.helpscout.1",
		NamedGroups: map[string][]byte{
			"secret": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
		},
		Snippet: types.Snippet{
			Before: []byte("HELPSCOUT_CLIENT_ID=a1b2c3d4e5f6a7b8c9d0"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "a1b2c3d4e5f6a7b8c9d0")
}

func TestHelpScoutValidator_Validate_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewHelpScoutValidatorWithClient(&http.Client{
		Transport: &helpScoutMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.helpscout.1",
		NamedGroups: map[string][]byte{
			"secret": []byte("invalid-secret-1234567890abcdef"),
		},
		Snippet: types.Snippet{
			Before: []byte("HELPSCOUT_CLIENT_ID=a1b2c3d4e5f6a7b8c9d0"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "401")
}

func TestHelpScoutValidator_Validate_Undetermined_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewHelpScoutValidatorWithClient(&http.Client{
		Transport: &helpScoutMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.helpscout.1",
		NamedGroups: map[string][]byte{
			"secret": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
		},
		Snippet: types.Snippet{
			Before: []byte("HELPSCOUT_CLIENT_ID=a1b2c3d4e5f6a7b8c9d0"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Equal(t, 0.5, result.Confidence)
	assert.Contains(t, result.Message, "500")
}

func TestHelpScoutValidator_Validate_PartialCredentials(t *testing.T) {
	v := NewHelpScoutValidator()

	match := &types.Match{
		RuleID: "np.helpscout.1",
		NamedGroups: map[string][]byte{
			"secret": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
		},
		Snippet: types.Snippet{
			Before:   []byte("no client id here"),
			Matching: []byte("HELPSCOUT_CLIENT_SECRET=a3B8f29E4d1C6a0578e23D9f41b6C8e2"),
			After:    []byte("or here"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

// helpScoutMockTransport redirects requests to the mock server
type helpScoutMockTransport struct {
	server *httptest.Server
}

func (t *helpScoutMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}
