package rule

import (
	"testing"
	"testing/fstest"
)

func TestLoadRule_Valid(t *testing.T) {
	loader := NewLoader()

	validYAML := `rules:
  - name: AWS API Key
    id: np.aws.1
    pattern: |
      (?x)
      AKIA[A-Z0-9]{16}
    description: AWS access key ID
    references:
      - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
    examples:
      - "AKIAIOSFODNN7EXAMPLE"
    negative_examples:
      - "not a key"
    categories:
      - secret
      - api
`

	rule, err := loader.LoadRule([]byte(validYAML))
	if err != nil {
		t.Fatalf("LoadRule failed: %v", err)
	}

	if rule.ID != "np.aws.1" {
		t.Errorf("expected ID np.aws.1, got %s", rule.ID)
	}
	if rule.Name != "AWS API Key" {
		t.Errorf("expected name 'AWS API Key', got %s", rule.Name)
	}
	if rule.Pattern == "" {
		t.Error("expected non-empty pattern")
	}
	if rule.Description != "AWS access key ID" {
		t.Errorf("expected description 'AWS access key ID', got %s", rule.Description)
	}
	if len(rule.Examples) != 1 {
		t.Errorf("expected 1 example, got %d", len(rule.Examples))
	}
	if len(rule.NegativeExamples) != 1 {
		t.Errorf("expected 1 negative example, got %d", len(rule.NegativeExamples))
	}
	if len(rule.References) != 1 {
		t.Errorf("expected 1 reference, got %d", len(rule.References))
	}
	if len(rule.Categories) != 2 {
		t.Errorf("expected 2 categories, got %d", len(rule.Categories))
	}
	if rule.StructuralID == "" {
		t.Error("expected StructuralID to be computed")
	}
}

func TestLoadRule_InvalidYAML(t *testing.T) {
	loader := NewLoader()

	invalidYAML := `this is not valid yaml: [[[`

	_, err := loader.LoadRule([]byte(invalidYAML))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadRule_NoRules(t *testing.T) {
	loader := NewLoader()

	emptyYAML := `rules: []`

	_, err := loader.LoadRule([]byte(emptyYAML))
	if err == nil {
		t.Error("expected error for empty rules array")
	}
}

func TestLoadRule_MultipleRules(t *testing.T) {
	loader := NewLoader()

	multipleYAML := `rules:
  - name: Rule 1
    id: np.test.1
    pattern: test1
  - name: Rule 2
    id: np.test.2
    pattern: test2
`

	_, err := loader.LoadRule([]byte(multipleYAML))
	if err == nil {
		t.Error("expected error for multiple rules")
	}
}

func TestLoadRuleset_Valid(t *testing.T) {
	loader := NewLoader()

	validYAML := `rulesets:
  - id: rs.aws
    name: AWS Rules
    description: Rules for AWS credential detection
    rule_ids:
      - np.aws.1
      - np.aws.2
`

	ruleset, err := loader.LoadRuleset([]byte(validYAML))
	if err != nil {
		t.Fatalf("LoadRuleset failed: %v", err)
	}

	if ruleset.ID != "rs.aws" {
		t.Errorf("expected ID rs.aws, got %s", ruleset.ID)
	}
	if ruleset.Name != "AWS Rules" {
		t.Errorf("expected name 'AWS Rules', got %s", ruleset.Name)
	}
	if ruleset.Description != "Rules for AWS credential detection" {
		t.Errorf("expected description, got %s", ruleset.Description)
	}
	if len(ruleset.RuleIDs) != 2 {
		t.Errorf("expected 2 rule IDs, got %d", len(ruleset.RuleIDs))
	}
}

func TestLoadRuleset_InvalidYAML(t *testing.T) {
	loader := NewLoader()

	invalidYAML := `invalid yaml content`

	_, err := loader.LoadRuleset([]byte(invalidYAML))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadRuleset_NoRulesets(t *testing.T) {
	loader := NewLoader()

	emptyYAML := `rulesets: []`

	_, err := loader.LoadRuleset([]byte(emptyYAML))
	if err == nil {
		t.Error("expected error for empty rulesets array")
	}
}

func TestLoadBuiltinRules_EmptyFS(t *testing.T) {
	// Create a mock filesystem with empty rules directory
	mockFS := fstest.MapFS{
		"rules/.gitkeep": &fstest.MapFile{Data: []byte("")},
	}

	loader := NewLoaderWithFS(mockFS)
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		t.Fatalf("LoadBuiltinRules failed: %v", err)
	}

	if len(rules) != 0 {
		t.Errorf("expected 0 rules from empty directory, got %d", len(rules))
	}
}

func TestLoadBuiltinRules_WithRules(t *testing.T) {
	ruleYAML := `rules:
  - name: Test Rule
    id: np.test.1
    pattern: test.*pattern
    categories:
      - test
`

	mockFS := fstest.MapFS{
		"rules/test.yaml": &fstest.MapFile{Data: []byte(ruleYAML)},
	}

	loader := NewLoaderWithFS(mockFS)
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		t.Fatalf("LoadBuiltinRules failed: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	if rules[0].ID != "np.test.1" {
		t.Errorf("expected ID np.test.1, got %s", rules[0].ID)
	}
}

func TestLoadBuiltinRulesets_EmptyFS(t *testing.T) {
	mockFS := fstest.MapFS{
		"rulesets/.gitkeep": &fstest.MapFile{Data: []byte("")},
	}

	loader := NewLoaderWithFS(mockFS)
	rulesets, err := loader.LoadBuiltinRulesets()
	if err != nil {
		t.Fatalf("LoadBuiltinRulesets failed: %v", err)
	}

	if len(rulesets) != 0 {
		t.Errorf("expected 0 rulesets from empty directory, got %d", len(rulesets))
	}
}

func TestLoadBuiltinRulesets_WithRulesets(t *testing.T) {
	rulesetYAML := `rulesets:
  - id: rs.test
    name: Test Ruleset
    description: Test ruleset
    rule_ids:
      - np.test.1
      - np.test.2
`

	mockFS := fstest.MapFS{
		"rulesets/test.yaml": &fstest.MapFile{Data: []byte(rulesetYAML)},
	}

	loader := NewLoaderWithFS(mockFS)
	rulesets, err := loader.LoadBuiltinRulesets()
	if err != nil {
		t.Fatalf("LoadBuiltinRulesets failed: %v", err)
	}

	if len(rulesets) != 1 {
		t.Fatalf("expected 1 ruleset, got %d", len(rulesets))
	}

	if rulesets[0].ID != "rs.test" {
		t.Errorf("expected ID rs.test, got %s", rulesets[0].ID)
	}
}

func TestConvertYAMLRule(t *testing.T) {
	yr := yamlRule{
		ID:          "np.test.1",
		Name:        "Test Rule",
		Pattern:     "test.*pattern",
		Description: "Test description",
		Examples:    []string{"test example"},
		Categories:  []string{"test"},
	}

	rule := convertYAMLRule(yr)

	if rule.ID != yr.ID {
		t.Errorf("expected ID %s, got %s", yr.ID, rule.ID)
	}
	if rule.Name != yr.Name {
		t.Errorf("expected Name %s, got %s", yr.Name, rule.Name)
	}
	if rule.Pattern != yr.Pattern {
		t.Errorf("expected Pattern %s, got %s", yr.Pattern, rule.Pattern)
	}
	if rule.StructuralID == "" {
		t.Error("expected StructuralID to be computed")
	}

	// Verify StructuralID is correct
	expected := rule.ComputeStructuralID()
	if rule.StructuralID != expected {
		t.Errorf("expected StructuralID %s, got %s", expected, rule.StructuralID)
	}
}

func TestConvertYAMLRuleset(t *testing.T) {
	yrs := yamlRuleset{
		ID:          "rs.test",
		Name:        "Test Ruleset",
		Description: "Test description",
		RuleIDs:     []string{"np.test.1", "np.test.2"},
	}

	ruleset := convertYAMLRuleset(yrs)

	if ruleset.ID != yrs.ID {
		t.Errorf("expected ID %s, got %s", yrs.ID, ruleset.ID)
	}
	if ruleset.Name != yrs.Name {
		t.Errorf("expected Name %s, got %s", yrs.Name, ruleset.Name)
	}
	if len(ruleset.RuleIDs) != len(yrs.RuleIDs) {
		t.Errorf("expected %d RuleIDs, got %d", len(yrs.RuleIDs), len(ruleset.RuleIDs))
	}
}

func TestRoundTrip(t *testing.T) {
	// Test that we can load a rule, validate it, and use it
	loader := NewLoader()

	ruleYAML := `rules:
  - name: GitHub Token
    id: np.github.1
    pattern: ghp_[a-zA-Z0-9]{36}
    description: GitHub personal access token
    examples:
      - "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"
    categories:
      - secret
`

	rule, err := loader.LoadRule([]byte(ruleYAML))
	if err != nil {
		t.Fatalf("LoadRule failed: %v", err)
	}

	// Validate the loaded rule
	if err := ValidateRule(rule); err != nil {
		t.Errorf("ValidateRule failed: %v", err)
	}

	// Verify the rule has expected properties
	if rule.ID != "np.github.1" {
		t.Errorf("expected ID np.github.1, got %s", rule.ID)
	}
	if rule.Pattern == "" {
		t.Error("expected non-empty pattern")
	}
	if rule.StructuralID == "" {
		t.Error("expected StructuralID to be computed")
	}
}
