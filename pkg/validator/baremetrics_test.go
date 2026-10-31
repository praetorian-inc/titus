package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func loadBaremetricsValidator(t *testing.T) ValidatorDef {
	t.Helper()
	data, err := validatorsFS.ReadFile("validators/baremetrics.yaml")
	require.NoError(t, err)

	var cfg ValidatorsConfig
	require.NoError(t, yaml.Unmarshal(data, &cfg))
	require.NotEmpty(t, cfg.Validators)
	return cfg.Validators[0]
}

func TestBaremetrics_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "Bearer test-api-key-12345abcdef67", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"sources":[]}`))
	}))
	defer server.Close()

	def := loadBaremetricsValidator(t)
	def.HTTP.URL = server.URL + "/v1/sources"
	v := NewHTTPValidator(def, nil)

	match := &types.Match{
		RuleID:      "kingfisher.baremetrics.1",
		NamedGroups: map[string][]byte{"secret": []byte("test-api-key-12345abcdef67")},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestBaremetrics_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	def := loadBaremetricsValidator(t)
	def.HTTP.URL = server.URL + "/v1/sources"
	v := NewHTTPValidator(def, nil)

	match := &types.Match{
		RuleID:      "kingfisher.baremetrics.1",
		NamedGroups: map[string][]byte{"secret": []byte("invalid-key-abcdefghijklmno")},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestBaremetrics_CanValidate(t *testing.T) {
	def := loadBaremetricsValidator(t)
	v := NewHTTPValidator(def, nil)
	assert.True(t, v.CanValidate("kingfisher.baremetrics.1"))
	assert.False(t, v.CanValidate("kingfisher.other.1"))
}
