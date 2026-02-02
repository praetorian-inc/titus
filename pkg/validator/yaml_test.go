// pkg/validator/yaml_test.go
package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestValidatorConfig_Parse(t *testing.T) {
	yamlData := `
validators:
  - name: github-token
    rule_ids:
      - np.github.1
    http:
      method: GET
      url: https://api.github.com/user
      auth:
        type: bearer
        secret_group: token
      success_codes: [200]
      failure_codes: [401, 403]
`
	var cfg ValidatorsConfig
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	assert.NoError(t, err)
	assert.Len(t, cfg.Validators, 1)

	v := cfg.Validators[0]
	assert.Equal(t, "github-token", v.Name)
	assert.Contains(t, v.RuleIDs, "np.github.1")
	assert.Equal(t, "GET", v.HTTP.Method)
	assert.Equal(t, "https://api.github.com/user", v.HTTP.URL)
	assert.Equal(t, "bearer", v.HTTP.Auth.Type)
	assert.Equal(t, "token", v.HTTP.Auth.SecretGroup) // Named capture group
	assert.Contains(t, v.HTTP.SuccessCodes, 200)
	assert.Contains(t, v.HTTP.FailureCodes, 401)
}

func TestLoadValidatorsFromYAML(t *testing.T) {
	yamlData := []byte(`
validators:
  - name: github-token
    rule_ids: [np.github.1]
    http:
      method: GET
      url: https://api.github.com/user
      auth:
        type: bearer
        secret_group: token
      success_codes: [200]
      failure_codes: [401]
  - name: slack-token
    rule_ids: [np.slack.1]
    http:
      method: GET
      url: https://slack.com/api/auth.test
      auth:
        type: bearer
        secret_group: token
      success_codes: [200]
      failure_codes: [401]
`)

	validators, err := LoadValidatorsFromYAML(yamlData)
	assert.NoError(t, err)
	assert.Len(t, validators, 2)

	// Verify they implement Validator interface
	for _, v := range validators {
		assert.NotEmpty(t, v.Name())
	}

	// Check specific validators
	assert.True(t, validators[0].CanValidate("np.github.1"))
	assert.True(t, validators[1].CanValidate("np.slack.1"))
}
