package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// TestLoadEmbeddedValidators_ContentfulDeliveryExists verifies that the contentful-delivery-token validator
// is included in the embedded validators
func TestLoadEmbeddedValidators_ContentfulDeliveryExists(t *testing.T) {
	validators, err := LoadEmbeddedValidators()
	assert.NoError(t, err)
	assert.NotEmpty(t, validators)

	// Find the contentful-delivery-token validator
	found := false
	for _, v := range validators {
		if v.Name() == "contentful-delivery-token" {
			found = true
			break
		}
	}
	assert.True(t, found, "contentful-delivery-token validator should be embedded")
}

// TestLoadEmbeddedValidators_ContentfulPATExists verifies that the contentful-personal-access-token validator
// is included in the embedded validators
func TestLoadEmbeddedValidators_ContentfulPATExists(t *testing.T) {
	validators, err := LoadEmbeddedValidators()
	assert.NoError(t, err)
	assert.NotEmpty(t, validators)

	// Find the contentful-personal-access-token validator
	found := false
	for _, v := range validators {
		if v.Name() == "contentful-personal-access-token" {
			found = true
			break
		}
	}
	assert.True(t, found, "contentful-personal-access-token validator should be embedded")
}

// TestContentfulDeliveryValidator_Structure verifies the contentful delivery validator has correct configuration
func TestContentfulDeliveryValidator_Structure(t *testing.T) {
	// Read the contentful validator file directly
	data, err := validatorsFS.ReadFile("validators/contentful.yaml")
	assert.NoError(t, err, "contentful.yaml should exist in embedded validators")

	// Parse the YAML
	var cfg ValidatorsConfig
	err = yaml.Unmarshal(data, &cfg)
	assert.NoError(t, err)
	assert.Len(t, cfg.Validators, 2, "contentful.yaml should contain exactly two validators")

	// Find the delivery token validator
	var v *ValidatorDef
	for i := range cfg.Validators {
		if cfg.Validators[i].Name == "contentful-delivery-token" {
			v = &cfg.Validators[i]
			break
		}
	}
	assert.NotNil(t, v, "contentful-delivery-token validator should exist")

	// Verify rule ID mapping
	assert.Contains(t, v.RuleIDs, "kingfisher.contentful.1", "validator should reference kingfisher.contentful.1 rule")

	// Verify HTTP configuration
	assert.Equal(t, "GET", v.HTTP.Method, "Contentful Delivery API uses GET")
	assert.Equal(t, "https://cdn.contentful.com/spaces", v.HTTP.URL)

	// Verify auth configuration
	assert.Equal(t, "bearer", v.HTTP.Auth.Type, "Contentful uses Bearer token auth")
	assert.Equal(t, "token", v.HTTP.Auth.SecretGroup, "must match (?P<token>...) in rule regex")

	// Verify success/failure codes
	assert.Contains(t, v.HTTP.SuccessCodes, 200)
	assert.Contains(t, v.HTTP.FailureCodes, 401)
	assert.Contains(t, v.HTTP.FailureCodes, 403)
}

// TestContentfulPATValidator_Structure verifies the contentful PAT validator has correct configuration
func TestContentfulPATValidator_Structure(t *testing.T) {
	// Read the contentful validator file directly
	data, err := validatorsFS.ReadFile("validators/contentful.yaml")
	assert.NoError(t, err, "contentful.yaml should exist in embedded validators")

	// Parse the YAML
	var cfg ValidatorsConfig
	err = yaml.Unmarshal(data, &cfg)
	assert.NoError(t, err)

	// Find the PAT validator
	var v *ValidatorDef
	for i := range cfg.Validators {
		if cfg.Validators[i].Name == "contentful-personal-access-token" {
			v = &cfg.Validators[i]
			break
		}
	}
	assert.NotNil(t, v, "contentful-personal-access-token validator should exist")

	// Verify rule ID mapping
	assert.Contains(t, v.RuleIDs, "kingfisher.contentful.2", "validator should reference kingfisher.contentful.2 rule")

	// Verify HTTP configuration
	assert.Equal(t, "GET", v.HTTP.Method, "Contentful CMA uses GET for user info")
	assert.Equal(t, "https://api.contentful.com/users/me", v.HTTP.URL)

	// Verify auth configuration
	assert.Equal(t, "bearer", v.HTTP.Auth.Type, "Contentful uses Bearer token auth")
	assert.Equal(t, "token", v.HTTP.Auth.SecretGroup, "must match (?P<token>...) in rule regex")

	// Verify success/failure codes
	assert.Contains(t, v.HTTP.SuccessCodes, 200)
	assert.Contains(t, v.HTTP.FailureCodes, 401)
	assert.Contains(t, v.HTTP.FailureCodes, 403)
}

// TestContentfulValidators_CanValidate verifies the validators can validate their respective rule IDs
func TestContentfulValidators_CanValidate(t *testing.T) {
	validators, err := LoadEmbeddedValidators()
	assert.NoError(t, err)

	// Find contentful validators
	var deliveryValidator, patValidator Validator
	for _, v := range validators {
		switch v.Name() {
		case "contentful-delivery-token":
			deliveryValidator = v
		case "contentful-personal-access-token":
			patValidator = v
		}
	}

	assert.NotNil(t, deliveryValidator, "delivery validator should exist")
	assert.NotNil(t, patValidator, "PAT validator should exist")

	// Test delivery validator
	assert.True(t, deliveryValidator.CanValidate("kingfisher.contentful.1"),
		"delivery validator should handle kingfisher.contentful.1")
	assert.False(t, deliveryValidator.CanValidate("kingfisher.contentful.2"),
		"delivery validator should not handle kingfisher.contentful.2")
	assert.False(t, deliveryValidator.CanValidate("np.github.1"),
		"delivery validator should not handle github rules")

	// Test PAT validator
	assert.True(t, patValidator.CanValidate("kingfisher.contentful.2"),
		"PAT validator should handle kingfisher.contentful.2")
	assert.False(t, patValidator.CanValidate("kingfisher.contentful.1"),
		"PAT validator should not handle kingfisher.contentful.1")
	assert.False(t, patValidator.CanValidate("np.slack.1"),
		"PAT validator should not handle slack rules")
}
