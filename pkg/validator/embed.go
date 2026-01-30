// pkg/validator/embed.go
package validator

import (
	"embed"
	"fmt"
	"path/filepath"
)

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
