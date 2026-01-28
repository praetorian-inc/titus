package rule

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/titus/pkg/types"
	"gopkg.in/yaml.v3"
)

// Loader handles loading rules from YAML files.
type Loader struct {
	fs fs.FS // embedded filesystem for built-in rules
}

// NewLoader creates a loader with built-in rules from embedded filesystem.
func NewLoader() *Loader {
	return &Loader{
		fs: builtinRulesFS,
	}
}

// NewLoaderWithFS creates a loader with a custom filesystem.
func NewLoaderWithFS(fsys fs.FS) *Loader {
	return &Loader{
		fs: fsys,
	}
}

// LoadRule loads a single rule from YAML bytes.
// Returns error if YAML is invalid or multiple rules are present.
func (l *Loader) LoadRule(data []byte) (*types.Rule, error) {
	var yamlFile yamlRulesFile
	if err := yaml.Unmarshal(data, &yamlFile); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if len(yamlFile.Rules) == 0 {
		return nil, fmt.Errorf("no rules found in YAML")
	}
	if len(yamlFile.Rules) > 1 {
		return nil, fmt.Errorf("expected single rule, found %d", len(yamlFile.Rules))
	}

	return convertYAMLRule(yamlFile.Rules[0]), nil
}

// LoadRuleFile loads a rule from a YAML file path.
func (l *Loader) LoadRuleFile(path string) (*types.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return l.LoadRule(data)
}

// LoadRuleset loads a ruleset from YAML bytes.
// Returns error if YAML is invalid or multiple rulesets are present.
func (l *Loader) LoadRuleset(data []byte) (*types.Ruleset, error) {
	var yamlFile yamlRulesetsFile
	if err := yaml.Unmarshal(data, &yamlFile); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if len(yamlFile.Rulesets) == 0 {
		return nil, fmt.Errorf("no rulesets found in YAML")
	}
	if len(yamlFile.Rulesets) > 1 {
		return nil, fmt.Errorf("expected single ruleset, found %d", len(yamlFile.Rulesets))
	}

	return convertYAMLRuleset(yamlFile.Rulesets[0]), nil
}

// LoadRulesetFile loads a ruleset from a YAML file path.
func (l *Loader) LoadRulesetFile(path string) (*types.Ruleset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return l.LoadRuleset(data)
}

// LoadBuiltinRules loads all built-in rules from embedded filesystem.
func (l *Loader) LoadBuiltinRules() ([]*types.Rule, error) {
	var rules []*types.Rule

	err := fs.WalkDir(l.fs, "rules", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yml" {
			return nil
		}

		data, err := fs.ReadFile(l.fs, path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		// Parse all rules from the file
		var yamlFile yamlRulesFile
		if err := yaml.Unmarshal(data, &yamlFile); err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		for _, yr := range yamlFile.Rules {
			rules = append(rules, convertYAMLRule(yr))
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return rules, nil
}

// LoadBuiltinRulesets loads all built-in rulesets from embedded filesystem.
func (l *Loader) LoadBuiltinRulesets() ([]*types.Ruleset, error) {
	var rulesets []*types.Ruleset

	err := fs.WalkDir(l.fs, "rulesets", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yml" {
			return nil
		}

		data, err := fs.ReadFile(l.fs, path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		// Parse all rulesets from the file
		var yamlFile yamlRulesetsFile
		if err := yaml.Unmarshal(data, &yamlFile); err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		for _, yrs := range yamlFile.Rulesets {
			rulesets = append(rulesets, convertYAMLRuleset(yrs))
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return rulesets, nil
}

// convertYAMLRule converts yamlRule to types.Rule and computes StructuralID.
func convertYAMLRule(yr yamlRule) *types.Rule {
	r := &types.Rule{
		ID:               yr.ID,
		Name:             yr.Name,
		Pattern:          yr.Pattern,
		Description:      yr.Description,
		Examples:         yr.Examples,
		NegativeExamples: yr.NegativeExamples,
		References:       yr.References,
		Categories:       yr.Categories,
	}
	r.StructuralID = r.ComputeStructuralID()
	return r
}

// convertYAMLRuleset converts yamlRuleset to types.Ruleset.
func convertYAMLRuleset(yrs yamlRuleset) *types.Ruleset {
	return &types.Ruleset{
		ID:          yrs.ID,
		Name:        yrs.Name,
		Description: yrs.Description,
		RuleIDs:     yrs.RuleIDs,
	}
}
