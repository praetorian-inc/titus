package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// TestLoadEmbeddedValidators_DropboxExists verifies that the dropbox validator
// is included in the embedded validators
func TestLoadEmbeddedValidators_DropboxExists(t *testing.T) {
	validators, err := LoadEmbeddedValidators()
	assert.NoError(t, err)
	assert.NotEmpty(t, validators)

	// Find the dropbox-access-token validator
	found := false
	for _, v := range validators {
		if v.Name() == "dropbox-access-token" {
			found = true
			break
		}
	}
	assert.True(t, found, "dropbox-access-token validator should be embedded")
}

// TestDropboxValidator_Structure verifies the dropbox validator has correct configuration
func TestDropboxValidator_Structure(t *testing.T) {
	// Read the dropbox validator file directly
	data, err := validatorsFS.ReadFile("validators/dropbox.yaml")
	assert.NoError(t, err, "dropbox.yaml should exist in embedded validators")

	// Parse the YAML
	var cfg ValidatorsConfig
	err = yaml.Unmarshal(data, &cfg)
	assert.NoError(t, err)
	assert.Len(t, cfg.Validators, 1, "dropbox.yaml should contain exactly one validator")

	v := cfg.Validators[0]

	// Verify name
	assert.Equal(t, "dropbox-access-token", v.Name)

	// Verify rule ID mapping
	assert.Contains(t, v.RuleIDs, "np.dropbox.1", "validator should reference np.dropbox.1 rule")

	// Verify HTTP configuration
	assert.Equal(t, "POST", v.HTTP.Method, "Dropbox API uses POST")
	assert.Equal(t, "https://api.dropboxapi.com/2/users/get_current_account", v.HTTP.URL)

	// Verify auth configuration
	assert.Equal(t, "bearer", v.HTTP.Auth.Type, "Dropbox uses Bearer token auth")
	assert.Equal(t, "token", v.HTTP.Auth.SecretGroup, "must match (?P<token>...) in rule regex")

	// Verify success/failure codes
	assert.Contains(t, v.HTTP.SuccessCodes, 200)
	assert.Contains(t, v.HTTP.FailureCodes, 401)
	assert.Contains(t, v.HTTP.FailureCodes, 403)
}
