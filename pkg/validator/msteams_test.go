package validator

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func loadMSTeamsValidator(t *testing.T, ruleID string) ValidatorDef {
	t.Helper()
	data, err := validatorsFS.ReadFile("validators/msteams.yaml")
	require.NoError(t, err)

	var cfg ValidatorsConfig
	require.NoError(t, yaml.Unmarshal(data, &cfg))

	for _, def := range cfg.Validators {
		v := NewHTTPValidator(def, nil)
		if v.CanValidate(ruleID) {
			return def
		}
	}
	t.Fatalf("no validator for rule %s in msteams.yaml", ruleID)
	return ValidatorDef{}
}

func TestMSTeamsWebhook_Legacy_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Equal(t, `{"text":""}`, string(body))
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Text is required"))
	}))
	defer server.Close()

	def := loadMSTeamsValidator(t, "np.msteams.1")
	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID:      "np.msteams.1",
		NamedGroups: map[string][]byte{"webhook": []byte(server.URL)},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestMSTeamsWebhook_Legacy_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	def := loadMSTeamsValidator(t, "np.msteams.1")
	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID:      "np.msteams.1",
		NamedGroups: map[string][]byte{"webhook": []byte(server.URL)},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestMSTeamsWebhook_Kingfisher_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Equal(t, `{"text":""}`, string(body))
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Text is required"))
	}))
	defer server.Close()

	def := loadMSTeamsValidator(t, "kingfisher.microsoftteamswebhook.1")
	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID:      "kingfisher.microsoftteamswebhook.1",
		NamedGroups: map[string][]byte{"webhook": []byte(server.URL)},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestMSTeamsWebhook_Kingfisher_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	def := loadMSTeamsValidator(t, "kingfisher.microsoftteamswebhook.1")
	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID:      "kingfisher.microsoftteamswebhook.1",
		NamedGroups: map[string][]byte{"webhook": []byte(server.URL)},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestMSTeamsWebhook_CanValidate(t *testing.T) {
	data, err := validatorsFS.ReadFile("validators/msteams.yaml")
	require.NoError(t, err)

	var cfg ValidatorsConfig
	require.NoError(t, yaml.Unmarshal(data, &cfg))

	ruleIDs := make(map[string]bool)
	for _, def := range cfg.Validators {
		v := NewHTTPValidator(def, nil)
		for _, id := range def.RuleIDs {
			ruleIDs[id] = v.CanValidate(id)
		}
	}

	assert.True(t, ruleIDs["np.msteams.1"])
	assert.True(t, ruleIDs["kingfisher.microsoftteamswebhook.1"])
}

func TestMSTeamsWebhook_BodyContainsCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Something else entirely"))
	}))
	defer server.Close()

	def := loadMSTeamsValidator(t, "np.msteams.1")
	v := NewHTTPValidator(def, nil)
	match := &types.Match{
		RuleID:      "np.msteams.1",
		NamedGroups: map[string][]byte{"webhook": []byte(server.URL)},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status, "400 without 'Text is required' body should be invalid")
}
