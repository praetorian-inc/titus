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

func TestHTTPValidator_Validate_ApiKey(t *testing.T) {
	// Mock server that expects "Authorization: key=SECRET" format (Firebase FCM style)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "key=AAAATestKey:APA91bValidFCMServerKey" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	def := ValidatorDef{
		Name:    "firebase-fcm",
		RuleIDs: []string{"np.firebase.1"},
		HTTP: HTTPDef{
			Method: "POST",
			URL:    server.URL,
			Auth: AuthDef{
				Type:        "api_key",
				SecretGroup: "server_key",
				// KeyPrefix defaults to "key="
			},
			SuccessCodes: []int{200},
			FailureCodes: []int{401, 403},
		},
	}

	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID: "np.firebase.1",
		NamedGroups: map[string][]byte{
			"server_key": []byte("AAAATestKey:APA91bValidFCMServerKey"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestHTTPValidator_Validate_ApiKey_CustomPrefix(t *testing.T) {
	// Test custom prefix like "Bearer " or "token "
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "token my_custom_token" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	def := ValidatorDef{
		Name:    "custom-api",
		RuleIDs: []string{"np.custom.1"},
		HTTP: HTTPDef{
			Method: "GET",
			URL:    server.URL,
			Auth: AuthDef{
				Type:        "api_key",
				SecretGroup: "token",
				KeyPrefix:   "token ", // Custom prefix with space
			},
			SuccessCodes: []int{200},
			FailureCodes: []int{401},
		},
	}

	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID: "np.custom.1",
		NamedGroups: map[string][]byte{
			"token": []byte("my_custom_token"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestHTTPValidator_Validate_POST_WithBody(t *testing.T) {
	// Test POST request with JSON body (Firebase FCM style)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Verify Content-Type
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify auth
		auth := r.Header.Get("Authorization")
		if auth != "key=AAAATestKey:APA91bValidFCMServerKey" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Verify body exists
		buf := make([]byte, 100)
		n, _ := r.Body.Read(buf)
		if n == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	def := ValidatorDef{
		Name:    "firebase-fcm",
		RuleIDs: []string{"np.firebase.1"},
		HTTP: HTTPDef{
			Method: "POST",
			URL:    server.URL,
			Auth: AuthDef{
				Type:        "api_key",
				SecretGroup: "server_key",
			},
			Headers: []Header{
				{Name: "Content-Type", Value: "application/json"},
			},
			Body:         `{"registration_ids":["test"]}`,
			SuccessCodes: []int{200},
			FailureCodes: []int{401, 403},
		},
	}

	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID: "np.firebase.1",
		NamedGroups: map[string][]byte{
			"server_key": []byte("AAAATestKey:APA91bValidFCMServerKey"),
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

func TestHTTPValidator_Validate_None_URLTemplateSubstitution(t *testing.T) {
	// Test "none" auth type with URL template substitution (Slack webhook use case)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slack webhook behavior: empty POST returns 400 if webhook exists
		if r.Method == "POST" && r.URL.Path == "/services/T123/B456/secrettoken" {
			w.WriteHeader(http.StatusBadRequest) // 400 = valid webhook (missing text)
			return
		}
		w.WriteHeader(http.StatusNotFound) // 404 = webhook doesn't exist
	}))
	defer server.Close()

	def := ValidatorDef{
		Name:    "slack-webhook",
		RuleIDs: []string{"np.slack.3"},
		HTTP: HTTPDef{
			Method: "POST",
			URL:    "{{webhook}}", // Template - should be replaced with captured value
			Auth: AuthDef{
				Type:        "none", // No auth header - URL contains the secret
				SecretGroup: "webhook",
			},
			SuccessCodes: []int{400}, // 400 with no_text means webhook exists
			FailureCodes: []int{403, 404},
		},
	}

	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID: "np.slack.3",
		NamedGroups: map[string][]byte{
			"webhook": []byte(server.URL + "/services/T123/B456/secrettoken"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Contains(t, result.Message, "HTTP 400")
}

func TestHTTPValidator_Validate_None_MultipleTemplates(t *testing.T) {
	// Test URL with multiple template substitutions
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/workspace123/channel/C456" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	def := ValidatorDef{
		Name:    "multi-template",
		RuleIDs: []string{"np.test.1"},
		HTTP: HTTPDef{
			Method: "GET",
			URL:    server.URL + "/api/{{workspace}}/channel/{{channel}}",
			Auth: AuthDef{
				Type:        "none",
				SecretGroup: "workspace", // Still need to specify for extractSecret
			},
			SuccessCodes: []int{200},
			FailureCodes: []int{404},
		},
	}

	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID: "np.test.1",
		NamedGroups: map[string][]byte{
			"workspace": []byte("workspace123"),
			"channel":   []byte("C456"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestHTTPValidator_Validate_None_EmptyAuthType(t *testing.T) {
	// Test that empty auth type (not specified) is treated same as "none"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify no Authorization header was set
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	def := ValidatorDef{
		Name:    "no-auth",
		RuleIDs: []string{"np.test.1"},
		HTTP: HTTPDef{
			Method: "GET",
			URL:    server.URL,
			Auth: AuthDef{
				Type:        "", // Empty string should behave like "none"
				SecretGroup: "token",
			},
			SuccessCodes: []int{200},
			FailureCodes: []int{400},
		},
	}

	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID: "np.test.1",
		NamedGroups: map[string][]byte{
			"token": []byte("unused"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}
