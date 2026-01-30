// pkg/validator/http_test.go
package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPValidator_Name(t *testing.T) {
	def := ValidatorDef{
		Name:    "github-token",
		RuleIDs: []string{"np.github.1"},
	}

	v := NewHTTPValidator(def, nil)
	assert.Equal(t, "github-token", v.Name())
}

func TestHTTPValidator_CanValidate(t *testing.T) {
	def := ValidatorDef{
		Name:    "github-token",
		RuleIDs: []string{"np.github.1", "np.github.2"},
	}

	v := NewHTTPValidator(def, nil)

	assert.True(t, v.CanValidate("np.github.1"))
	assert.True(t, v.CanValidate("np.github.2"))
	assert.False(t, v.CanValidate("np.slack.1"))
}
