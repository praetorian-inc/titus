// pkg/validator/yaml.go
package validator

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
	SuccessCodes []int    `yaml:"success_codes"`
	FailureCodes []int    `yaml:"failure_codes"`
}

// AuthDef defines authentication configuration.
type AuthDef struct {
	Type        string `yaml:"type"` // bearer, basic, header, query
	SecretGroup int    `yaml:"secret_group"`
	HeaderName  string `yaml:"header_name,omitempty"`  // for type=header
	QueryParam  string `yaml:"query_param,omitempty"`  // for type=query
	Username    string `yaml:"username,omitempty"`     // for type=basic (if static)
}

// Header is a custom header key-value pair.
type Header struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}
