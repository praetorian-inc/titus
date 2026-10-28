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
const orcaValidatorTestKey = "sk-orca-TEST-ONLY-000011112222333344445555"

// orcaValidatorDef returns the shipped OrcaRouter validator definition from the
// embedded catalog. The test reads the real YAML rather than constructing a
// definition inline, so a drift in the shipped file fails here.
func orcaValidatorDef(t *testing.T) ValidatorDef {
	t.Helper()
	validators, err := LoadEmbeddedValidators()
	require.NoError(t, err)

	for _, v := range validators {
		if v.Name() == "orcarouter-api-key" {
			httpValidator, ok := v.(*HTTPValidator)
			require.True(t, ok, "orcarouter-api-key should be an HTTP validator")
			return httpValidator.def
		}
	}
	t.Fatal("orcarouter-api-key validator is missing from the embedded catalog")
	return ValidatorDef{}
}

func orcaValidatorMatch(key string) *types.Match {
	return &types.Match{
		RuleID:      "kingfisher.orcarouter.1",
		Groups:      [][]byte{[]byte(key)},
		NamedGroups: map[string][]byte{"key": []byte(key)},
	}
}

func TestOrcaRouterValidator_IsRegisteredForRule(t *testing.T) {
	def := orcaValidatorDef(t)

	assert.Equal(t, "orcarouter-api-key", def.Name)
	assert.Equal(t, []string{"kingfisher.orcarouter.1"}, def.RuleIDs)

	v := NewHTTPValidator(def, nil)
	assert.True(t, v.CanValidate("kingfisher.orcarouter.1"))
	assert.False(t, v.CanValidate("kingfisher.openrouter.1"))
}

func TestOrcaRouterValidator_UsesBearerAuthAgainstInferenceOrigin(t *testing.T) {
	def := orcaValidatorDef(t)

	assert.Equal(t, http.MethodGet, def.HTTP.Method)
	assert.Equal(t, "https://api.orcarouter.ai/v1/models", def.HTTP.URL)
	assert.Equal(t, "bearer", def.HTTP.Auth.Type)
	assert.Equal(t, "key", def.HTTP.Auth.SecretGroup)
	assert.Equal(t, []int{200}, def.HTTP.SuccessCodes)
	assert.Equal(t, []int{401, 403}, def.HTTP.FailureCodes)
}

func TestOrcaRouterValidator_SendsKeyAsBearer(t *testing.T) {
	def := orcaValidatorDef(t)

	var gotAuth, gotPath, gotVerb string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotVerb = r.Method
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[{"id":"orcarouter/auto"}]}`))
	}))
	defer srv.Close()

	def.HTTP.URL = srv.URL + "/v1/models"
	v := NewHTTPValidator(def, srv.Client())

	result, err := v.Validate(context.Background(), orcaValidatorMatch(orcaValidatorTestKey))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, "GET", gotVerb)
	assert.Equal(t, "/v1/models", gotPath)
	assert.Equal(t, "Bearer "+orcaValidatorTestKey, gotAuth)
}

func TestOrcaRouterValidator_RevokedKeyIsInvalid(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			def := orcaValidatorDef(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":{"message":"invalid api key"}}`))
			}))
			defer srv.Close()

			def.HTTP.URL = srv.URL + "/v1/models"
			v := NewHTTPValidator(def, srv.Client())

			result, err := v.Validate(context.Background(), orcaValidatorMatch(orcaValidatorTestKey))
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, types.StatusInvalid, result.Status)
		})
	}
}

func TestOrcaRouterValidator_KeyNeverAppearsInResultMessage(t *testing.T) {
	def := orcaValidatorDef(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"nope"}}`))
	}))
	defer srv.Close()

	def.HTTP.URL = srv.URL + "/v1/models"
	v := NewHTTPValidator(def, srv.Client())

	result, err := v.Validate(context.Background(), orcaValidatorMatch(orcaValidatorTestKey))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotContains(t, result.Message, orcaValidatorTestKey)
}
