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

func loadKickboxValidator(t *testing.T) ValidatorDef {
	t.Helper()
	data, err := validatorsFS.ReadFile("validators/kickbox.yaml")
	require.NoError(t, err)

	var cfg ValidatorsConfig
	require.NoError(t, yaml.Unmarshal(data, &cfg))
	require.NotEmpty(t, cfg.Validators)
	return cfg.Validators[0]
}

func TestKickbox_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.NotEmpty(t, r.URL.Query().Get("apikey"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	def := loadKickboxValidator(t)
	def.HTTP.URL = server.URL + "/v2/balance"
	v := NewHTTPValidator(def, nil)

	match := &types.Match{
		RuleID: "kingfisher.kickbox.1",
		Groups: [][]byte{[]byte("test_abcdefghijklmnopqrstuvwxyzbu9JFVJtII3FINL1rOKcNpveXD4hSMtSDx7opOWd")},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestKickbox_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	def := loadKickboxValidator(t)
	def.HTTP.URL = server.URL + "/v2/balance"
	v := NewHTTPValidator(def, nil)

	match := &types.Match{
		RuleID: "kingfisher.kickbox.1",
		Groups: [][]byte{[]byte("invalid_key_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestKickbox_CanValidate(t *testing.T) {
	def := loadKickboxValidator(t)
	v := NewHTTPValidator(def, nil)
	assert.True(t, v.CanValidate("kingfisher.kickbox.1"))
	assert.False(t, v.CanValidate("kingfisher.other.1"))
}
