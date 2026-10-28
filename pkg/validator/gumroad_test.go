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

func loadGumroadValidator(t *testing.T) ValidatorDef {
	t.Helper()
	data, err := validatorsFS.ReadFile("validators/gumroad.yaml")
	require.NoError(t, err)

	var cfg ValidatorsConfig
	require.NoError(t, yaml.Unmarshal(data, &cfg))
	require.NotEmpty(t, cfg.Validators)
	return cfg.Validators[0]
}

func TestGumroad_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.NotEmpty(t, r.URL.Query().Get("access_token"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"user":{"name":"test"}}`))
	}))
	defer server.Close()

	def := loadGumroadValidator(t)
	def.HTTP.URL = server.URL + "/v2/user"
	v := NewHTTPValidator(def, nil)

	match := &types.Match{
		RuleID: "kingfisher.gumroad.1",
		Groups: [][]byte{[]byte("abf11e4ab2850ffd50ef690257f7a1c998a443059513d1a4826f2b3159620505")},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestGumroad_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	def := loadGumroadValidator(t)
	def.HTTP.URL = server.URL + "/v2/user"
	v := NewHTTPValidator(def, nil)

	match := &types.Match{
		RuleID: "kingfisher.gumroad.1",
		Groups: [][]byte{[]byte("0000000000000000000000000000000000000000000000000000000000000000")},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestGumroad_CanValidate(t *testing.T) {
	def := loadGumroadValidator(t)
	v := NewHTTPValidator(def, nil)
	assert.True(t, v.CanValidate("kingfisher.gumroad.1"))
	assert.False(t, v.CanValidate("kingfisher.other.1"))
}
