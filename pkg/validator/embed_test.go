// pkg/validator/embed_test.go
package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
}
