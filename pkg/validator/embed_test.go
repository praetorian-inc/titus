// pkg/validator/embed_test.go
package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadEmbeddedValidators(t *testing.T) {
	validators, err := LoadEmbeddedValidators()
	assert.NoError(t, err)
	assert.NotEmpty(t, validators)

	// At least the GitHub validator should exist
	found := false
	for _, v := range validators {
		if v.Name() == "github-token" {
			found = true
			break
		}
	}
	assert.True(t, found, "github-token validator should be embedded")

	// Verify np.github.3 and np.github.7 are registered
	var githubValidator Validator
	for _, v := range validators {
		if v.Name() == "github-token" {
			githubValidator = v
			break
		}
	}
	require.NotNil(t, githubValidator, "github-token validator should exist")
	assert.True(t, githubValidator.CanValidate("np.github.1"))
	assert.True(t, githubValidator.CanValidate("np.github.2"))
	// np.github.3 is handled by the Go GitHubAppTokenValidator (ghu_ vs ghs_ need different endpoints)
	assert.False(t, githubValidator.CanValidate("np.github.3"))
	assert.True(t, githubValidator.CanValidate("np.github.7"))
}
