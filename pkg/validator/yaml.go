// pkg/validator/yaml.go
package validator

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ValidatorsConfig is the root YAML structure for validator definitions.
type ValidatorsConfig struct {
	Validators []ValidatorDef `yaml:"validators"`
}

// ValidatorDef defines a single HTTP-based validator.
type ValidatorDef struct {
	Name    string   `yaml:"name"`
	RuleIDs []string `yaml:"rule_ids"`
	HTTP    HTTPDef  `yaml:"http"`
}

// HTTPDef defines HTTP request configuration.
type HTTPDef struct {
	Method       string   `yaml:"method"`
	URL          string   `yaml:"url"`
	Auth         AuthDef  `yaml:"auth"`
	Headers      []Header `yaml:"headers,omitempty"`
	Body         string   `yaml:"body,omitempty"` // Static request body for POST/PUT
	SuccessCodes []int    `yaml:"success_codes"`
	FailureCodes []int    `yaml:"failure_codes"`
}

// AuthDef defines authentication configuration.
type AuthDef struct {
	Type        string `yaml:"type"` // bearer, basic, header, query, api_key
	SecretGroup string `yaml:"secret_group"`           // named capture group containing the secret (e.g., "secret", "token")
	HeaderName  string `yaml:"header_name,omitempty"`  // for type=header
	QueryParam  string `yaml:"query_param,omitempty"`  // for type=query
	Username    string `yaml:"username,omitempty"`     // for type=basic (if static)
	KeyPrefix   string `yaml:"key_prefix,omitempty"`   // for type=api_key, default "key=" (e.g., "Authorization: key=SECRET")
}

// Header is a custom header key-value pair.
type Header struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// LoadValidatorsFromYAML parses YAML and creates HTTPValidator instances.
func LoadValidatorsFromYAML(data []byte) ([]Validator, error) {
	var cfg ValidatorsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	validators := make([]Validator, 0, len(cfg.Validators))
	for _, def := range cfg.Validators {
		validators = append(validators, NewHTTPValidator(def, nil))
	}

	return validators, nil
}
