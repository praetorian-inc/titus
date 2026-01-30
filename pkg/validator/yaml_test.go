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
        secret_group: 0
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
	assert.Equal(t, 0, v.HTTP.Auth.SecretGroup)
	assert.Contains(t, v.HTTP.SuccessCodes, 200)
	assert.Contains(t, v.HTTP.FailureCodes, 401)
}
