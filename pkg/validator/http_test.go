// pkg/validator/http_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestHTTPValidator_Name(t *testing.T) {
	def := ValidatorDef{
		Name:    "github-token",
		RuleIDs: []string{"np.github.1"},
	}

	v := NewHTTPValidator(def, nil)
	assert.Equal(t, "github-token", v.Name())
}

func TestHTTPValidator_CanValidate(t *testing.T) {
	def := ValidatorDef{
		Name:    "github-token",
		RuleIDs: []string{"np.github.1", "np.github.2"},
	}

	v := NewHTTPValidator(def, nil)

	assert.True(t, v.CanValidate("np.github.1"))
	assert.True(t, v.CanValidate("np.github.2"))
	assert.False(t, v.CanValidate("np.slack.1"))
}

func TestHTTPValidator_Validate_Bearer_Valid(t *testing.T) {
	// Mock server that expects Bearer token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer ghp_validtoken123456" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	def := ValidatorDef{
		Name:    "github-token",
		RuleIDs: []string{"np.github.1"},
		HTTP: HTTPDef{
			Method: "GET",
			URL:    server.URL,
			Auth: AuthDef{
				Type:        "bearer",
				SecretGroup: "token", // Named capture group
			},
			SuccessCodes: []int{200},
			FailureCodes: []int{401, 403},
		},
	}

	v := NewHTTPValidator(def, nil)

	match := &types.Match{
		RuleID: "np.github.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ghp_validtoken123456"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestHTTPValidator_Validate_Bearer_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	def := ValidatorDef{
		Name:    "github-token",
		RuleIDs: []string{"np.github.1"},
		HTTP: HTTPDef{
			Method: "GET",
			URL:    server.URL,
			Auth: AuthDef{
				Type:        "bearer",
				SecretGroup: "token",
			},
			SuccessCodes: []int{200},
			FailureCodes: []int{401, 403},
		},
	}

	v := NewHTTPValidator(def, nil)

	match := &types.Match{
		RuleID: "np.github.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ghp_invalidtoken"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestHTTPValidator_Validate_Basic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok && user == "api" && pass == "sk_live_test123" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	def := ValidatorDef{
		Name:    "stripe",
		RuleIDs: []string{"np.stripe.1"},
		HTTP: HTTPDef{
			Method: "GET",
			URL:    server.URL,
			Auth: AuthDef{
				Type:        "basic",
				SecretGroup: "secret",
				Username:    "api", // Static username, secret as password
			},
			SuccessCodes: []int{200},
			FailureCodes: []int{401},
		},
	}

	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID: "np.stripe.1",
		NamedGroups: map[string][]byte{
			"secret": []byte("sk_live_test123"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestHTTPValidator_Validate_Header(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("DD-API-KEY") == "valid_datadog_key" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	def := ValidatorDef{
		Name:    "datadog",
		RuleIDs: []string{"np.datadog.1"},
		HTTP: HTTPDef{
			Method: "GET",
			URL:    server.URL,
			Auth: AuthDef{
				Type:        "header",
				SecretGroup: "api_key",
				HeaderName:  "DD-API-KEY",
			},
			SuccessCodes: []int{200},
			FailureCodes: []int{403},
		},
	}

	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID: "np.datadog.1",
		NamedGroups: map[string][]byte{
			"api_key": []byte("valid_datadog_key"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestHTTPValidator_Validate_Query(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") == "AIzaSyValidGoogleKey" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	def := ValidatorDef{
		Name:    "google-maps",
		RuleIDs: []string{"np.google.1"},
		HTTP: HTTPDef{
			Method: "GET",
			URL:    server.URL,
			Auth: AuthDef{
				Type:        "query",
				SecretGroup: "api_key",
				QueryParam:  "key",
			},
			SuccessCodes: []int{200},
			FailureCodes: []int{403},
		},
	}

	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID: "np.google.1",
		NamedGroups: map[string][]byte{
			"api_key": []byte("AIzaSyValidGoogleKey"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestHTTPValidator_Validate_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Slow response
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	def := ValidatorDef{
		Name:    "slow-service",
		RuleIDs: []string{"np.test.1"},
		HTTP: HTTPDef{
			Method: "GET",
			URL:    server.URL,
			Auth: AuthDef{
				Type:        "bearer",
				SecretGroup: "token",
			},
			SuccessCodes: []int{200},
			FailureCodes: []int{401},
		},
	}

	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID: "np.test.1",
		NamedGroups: map[string][]byte{
			"token": []byte("test-token"),
		},
	}

	// Context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	result, err := v.Validate(ctx, match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "request failed")
}
