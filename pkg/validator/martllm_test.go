package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A clearly synthetic key. Never a real credential.
const martllmValidatorTestKey = "ull_EXAMPLEkeyDoNotUse4mZ9vT2kL8nR3pW6xY1bC5dQ7"

// martllmValidatorDef returns the shipped MartLLM validator definition from the
// embedded catalog, so a drift in the shipped YAML fails here.
func martllmValidatorDef(t *testing.T) ValidatorDef {
	t.Helper()
	validators, err := LoadEmbeddedValidators()
	require.NoError(t, err)

	for _, v := range validators {
		if v.Name() == "martllm-api-key" {
			httpValidator, ok := v.(*HTTPValidator)
			require.True(t, ok, "martllm-api-key should be an HTTP validator")
			return httpValidator.def
		}
	}
	t.Fatal("martllm-api-key validator is missing from the embedded catalog")
	return ValidatorDef{}
}

func martllmValidatorMatch(key string) *types.Match {
	return &types.Match{
		RuleID:      "kingfisher.martllm.1",
		Groups:      [][]byte{[]byte(key)},
		NamedGroups: map[string][]byte{"key": []byte(key)},
	}
}

func TestMartLLMValidator_IsRegisteredForRule(t *testing.T) {
	def := martllmValidatorDef(t)

	assert.Equal(t, []string{"kingfisher.martllm.1"}, def.RuleIDs)
	assert.Equal(t, http.MethodGet, def.HTTP.Method)
	assert.Equal(t, "https://api.martllm.com/v1/balance", def.HTTP.URL)
	assert.Equal(t, "bearer", def.HTTP.Auth.Type)
	assert.Equal(t, "key", def.HTTP.Auth.SecretGroup)
	assert.Equal(t, []int{200}, def.HTTP.SuccessCodes)
	assert.Equal(t, []int{401, 403}, def.HTTP.FailureCodes)

	v := NewHTTPValidator(def, nil)
	assert.True(t, v.CanValidate("kingfisher.martllm.1"))
	assert.False(t, v.CanValidate("kingfisher.openrouter.1"))
}

func TestMartLLMValidator_LiveKeyIsValid(t *testing.T) {
	def := martllmValidatorDef(t)

	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"balance","balance_usd":4.2,"held_usd":0,"available_usd":4.2}`))
	}))
	defer srv.Close()

	def.HTTP.URL = srv.URL + "/v1/balance"
	result, err := NewHTTPValidator(def, srv.Client()).Validate(context.Background(), martllmValidatorMatch(martllmValidatorTestKey))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, "/v1/balance", gotPath)
	assert.Equal(t, "Bearer "+martllmValidatorTestKey, gotAuth)
}

func TestMartLLMValidator_RevokedKeyIsInvalid(t *testing.T) {
	def := martllmValidatorDef(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Invalid, revoked, or expired API key.","type":"authentication_error","code":"invalid_api_key"}}`))
	}))
	defer srv.Close()

	def.HTTP.URL = srv.URL + "/v1/balance"
	result, err := NewHTTPValidator(def, srv.Client()).Validate(context.Background(), martllmValidatorMatch(martllmValidatorTestKey))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.NotContains(t, result.Message, martllmValidatorTestKey)
}
