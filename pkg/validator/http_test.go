// pkg/validator/http_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
				SecretGroup: 0,
			},
			SuccessCodes: []int{200},
			FailureCodes: []int{401, 403},
		},
	}

	v := NewHTTPValidator(def, nil)

	match := &types.Match{
		RuleID: "np.github.1",
		Groups: [][]byte{[]byte("ghp_validtoken123456")},
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
				SecretGroup: 0,
			},
			SuccessCodes: []int{200},
			FailureCodes: []int{401, 403},
		},
	}

	v := NewHTTPValidator(def, nil)

	match := &types.Match{
		RuleID: "np.github.1",
		Groups: [][]byte{[]byte("ghp_invalidtoken")},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}
