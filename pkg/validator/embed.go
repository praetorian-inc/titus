// pkg/validator/embed.go
package validator

import (
	"embed"
	"fmt"
	"path/filepath"
)

// NOTE: The following files are embedded but produce no active validators at
// runtime. They are skipped by the schema contract test (yaml_contract_test.go).
// Two distinct classes:
//
// Empty-RuleID legacy (load but validators have empty rule_ids, never match):
//
//   - blynk.yaml       — rule_id/valid_status schema (old format)
//   - clay.yaml        — request/response/classification schema (old format)
//   - clojars.yaml     — no rule_ids field (old format)
//   - codeclimate.yaml — root-level entry, no validators: wrapper (old format)
//   - curl.yaml        — placeholder/template with empty URLs
//
// Zero-validator / non-HTTP (register nothing at runtime):
//
//   - adobe.yaml       — all validators commented out; needs client_id+secret pair not yet supported
//   - bitbucket.yaml   — all validators commented out; needs username+app_password not yet supported
//   - cratesio.yaml    — old kingfisher http.request schema, not current validators: format
//   - credentials.yaml — entropy/length validator schema, not HTTP-based
//   - firebase.yaml    — all validators commented out; FCM legacy API deprecated June 2024
//
//go:embed validators/*.yaml
var validatorsFS embed.FS

// LoadEmbeddedValidators loads all embedded YAML validator definitions.
func LoadEmbeddedValidators() ([]Validator, error) {
	entries, err := validatorsFS.ReadDir("validators")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded validators: %w", err)
	}

	var validators []Validator
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		data, err := validatorsFS.ReadFile("validators/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", entry.Name(), err)
		}

		loaded, err := LoadValidatorsFromYAML(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", entry.Name(), err)
		}

		validators = append(validators, loaded...)
	}

	return validators, nil
}
