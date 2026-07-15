package rule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/praetorian-inc/titus/pkg/types"
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
    base_score: 60
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
    include_rule_ids:
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
    base_score: 50
    categories:
      - test
`

	mockFS := fstest.MapFS{
		"rules/test.yml": &fstest.MapFile{Data: []byte(ruleYAML)},
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
		"rulesets/test.yml": &fstest.MapFile{Data: []byte(rulesetYAML)},
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
	score := 50
	yr := yamlRule{
		ID:          "np.test.1",
		Name:        "Test Rule",
		Pattern:     "test.*pattern",
		Description: "Test description",
		Examples:    []string{"test example"},
		Categories:  []string{"test"},
		BaseScore:   &score,
	}

	rule, err := convertYAMLRule(yr)
	if err != nil {
		t.Fatalf("convertYAMLRule: %v", err)
	}

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
    base_score: 75
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

func TestLoadRule_WithMinEntropy(t *testing.T) {
	loader := NewLoader()

	yaml := `rules:
  - name: Test Rule With Entropy
    id: np.test.entropy.1
    pattern: 'test[A-Z0-9]{16}'
    base_score: 50
    min_entropy: 3.5
`
	rule, err := loader.LoadRule([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadRule failed: %v", err)
	}
	if rule.MinEntropy != 3.5 {
		t.Errorf("expected MinEntropy 3.5, got %f", rule.MinEntropy)
	}
}

func TestLoadRule_WithPatternRequirements(t *testing.T) {
	loader := NewLoader()

	yaml := `rules:
  - name: Test Rule With Requirements
    id: np.test.req.1
    pattern: 'sk_live_[A-Za-z0-9]{24}'
    base_score: 50
    pattern_requirements:
      min_digits: 2
      min_uppercase: 1
      min_lowercase: 3
      min_special_chars: 0
      ignore_if_contains:
        - EXAMPLE
        - test
`
	rule, err := loader.LoadRule([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadRule failed: %v", err)
	}
	if rule.PatternRequirements == nil {
		t.Fatal("expected PatternRequirements to be non-nil")
	}
	if rule.PatternRequirements.MinDigits != 2 {
		t.Errorf("expected MinDigits 2, got %d", rule.PatternRequirements.MinDigits)
	}
	if rule.PatternRequirements.MinUppercase != 1 {
		t.Errorf("expected MinUppercase 1, got %d", rule.PatternRequirements.MinUppercase)
	}
	if rule.PatternRequirements.MinLowercase != 3 {
		t.Errorf("expected MinLowercase 3, got %d", rule.PatternRequirements.MinLowercase)
	}
	if len(rule.PatternRequirements.IgnoreIfContains) != 2 {
		t.Errorf("expected 2 IgnoreIfContains entries, got %d", len(rule.PatternRequirements.IgnoreIfContains))
	}
}

func TestLoadRule_NoPatternRequirements(t *testing.T) {
	loader := NewLoader()

	yaml := `rules:
  - name: Simple Rule
    id: np.test.simple.1
    pattern: 'simple[A-Z0-9]+'
    base_score: 50
`
	rule, err := loader.LoadRule([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadRule failed: %v", err)
	}
	if rule.MinEntropy != 0 {
		t.Errorf("expected MinEntropy 0 (unset), got %f", rule.MinEntropy)
	}
	if rule.PatternRequirements != nil {
		t.Error("expected PatternRequirements to be nil for rule without requirements")
	}
}

func TestLoadRule_BaseScoreParsed(t *testing.T) {
	loader := NewLoader()
	yaml := `rules:
  - name: Test Rule
    id: np.test.1
    pattern: 'test'
    base_score: 75
`
	rule, err := loader.LoadRule([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadRule: %v", err)
	}
	if rule.BaseScore != 75 {
		t.Errorf("BaseScore = %d, want 75", rule.BaseScore)
	}
}

func TestLoadRule_BaseScoreMissing_Rejected(t *testing.T) {
	loader := NewLoader()
	yaml := `rules:
  - name: Test Rule
    id: np.test.1
    pattern: 'test'
`
	_, err := loader.LoadRule([]byte(yaml))
	if err == nil {
		t.Error("expected error for rule missing base_score, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "base_score") {
		t.Errorf("error message does not mention base_score: %v", err)
	}
}

func TestLoadRule_BaseScoreOutOfRange(t *testing.T) {
	loader := NewLoader()
	yaml := `rules:
  - name: Test Rule
    id: np.test.1
    pattern: 'test'
    base_score: 150
`
	_, err := loader.LoadRule([]byte(yaml))
	if err == nil {
		t.Error("expected error for base_score 150 (out of range), got nil")
	}
}

func TestLoadRule_BaseScoreNegative(t *testing.T) {
	loader := NewLoader()
	yaml := `rules:
  - name: Test Rule
    id: np.test.1
    pattern: 'test'
    base_score: -5
`
	_, err := loader.LoadRule([]byte(yaml))
	if err == nil {
		t.Error("expected error for negative base_score, got nil")
	}
}

func TestLoadRule_BaseScoreValid(t *testing.T) {
	loader := NewLoader()
	yaml := `rules:
  - name: Test Rule
    id: np.test.1
    pattern: 'test'
    base_score: 75
`
	rule, err := loader.LoadRule([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadRule: %v", err)
	}
	if rule.BaseScore != 75 {
		t.Errorf("BaseScore = %d, want 75", rule.BaseScore)
	}
}

func TestFindRuleset(t *testing.T) {
	rulesets := []*types.Ruleset{
		{ID: "default", Name: "Default"},
		{ID: "np.assets", Name: "Assets"},
		{ID: "np.hashes", Name: "Hashes"},
	}

	rs := FindRuleset(rulesets, "np.assets")
	if rs == nil {
		t.Fatal("expected to find np.assets ruleset")
	}
	if rs.ID != "np.assets" {
		t.Errorf("expected np.assets, got %s", rs.ID)
	}

	rs = FindRuleset(rulesets, "nonexistent")
	if rs != nil {
		t.Error("expected nil for nonexistent ruleset")
	}
}

func TestLoadRulesFromFileMulti_MultipleRules(t *testing.T) {
	loader := NewLoader()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yml")

	yamlData := `rules:
  - name: Test Rule One
    id: np.test.multi.1
    pattern: AKIA[A-Z0-9]{16}
    description: First synthetic test rule
    base_score: 50
  - name: Test Rule Two
    id: np.test.multi.2
    pattern: ghp_[A-Za-z0-9]{36}
    description: Second synthetic test rule
    base_score: 60
  - name: Test Rule Three
    id: np.test.multi.3
    pattern: xoxb-[A-Za-z0-9-]+
    description: Third synthetic test rule
    base_score: 70
`
	if err := os.WriteFile(path, []byte(yamlData), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	rules, err := loader.LoadRulesFromFileMulti(path)
	if err != nil {
		t.Fatalf("LoadRulesFromFileMulti failed: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	wantIDs := map[string]bool{
		"np.test.multi.1": false,
		"np.test.multi.2": false,
		"np.test.multi.3": false,
	}
	for _, r := range rules {
		if _, ok := wantIDs[r.ID]; !ok {
			t.Errorf("unexpected rule ID %q", r.ID)
			continue
		}
		wantIDs[r.ID] = true
		if r.StructuralID == "" {
			t.Errorf("rule %s: expected StructuralID to be computed", r.ID)
		}
	}
	for id, found := range wantIDs {
		if !found {
			t.Errorf("missing rule ID %q", id)
		}
	}
}

func TestLoadRulesFromFileMulti_SingleRule(t *testing.T) {
	loader := NewLoader()
	dir := t.TempDir()
	path := filepath.Join(dir, "single.yaml")

	yamlData := `rules:
  - name: Solo Rule
    id: np.test.solo
    pattern: solo[0-9]{8}
    description: Single rule in a file
    base_score: 42
`
	if err := os.WriteFile(path, []byte(yamlData), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	rules, err := loader.LoadRulesFromFileMulti(path)
	if err != nil {
		t.Fatalf("LoadRulesFromFileMulti failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID != "np.test.solo" {
		t.Errorf("expected np.test.solo, got %q", rules[0].ID)
	}
}

func TestLoadRulesFromFileMulti_EmptyRules(t *testing.T) {
	loader := NewLoader()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yml")
	if err := os.WriteFile(path, []byte("rules: []\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := loader.LoadRulesFromFileMulti(path)
	if err == nil {
		t.Fatal("expected error for empty rules array")
	}
	if !strings.Contains(err.Error(), "no rules found") {
		t.Errorf("expected error to mention 'no rules found', got: %v", err)
	}
}

func TestLoadRulesFromFileMulti_MalformedYAML(t *testing.T) {
	loader := NewLoader()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yml")
	if err := os.WriteFile(path, []byte("rules: [[[ not yaml"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := loader.LoadRulesFromFileMulti(path)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

func TestLoadRulesFromFileMulti_MissingFile(t *testing.T) {
	loader := NewLoader()
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.yml")

	_, err := loader.LoadRulesFromFileMulti(path)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "failed to read file") {
		t.Errorf("expected error to mention 'failed to read file', got: %v", err)
	}
}

func TestLoadRulesFromFileMulti_InvalidRule(t *testing.T) {
	loader := NewLoader()
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.yml")

	// Missing required base_score should bubble up from convertYAMLRule.
	yamlData := `rules:
  - name: No Score
    id: np.test.noscore
    pattern: foo
`
	if err := os.WriteFile(path, []byte(yamlData), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := loader.LoadRulesFromFileMulti(path)
	if err == nil {
		t.Fatal("expected error for rule missing base_score")
	}
}

// TestBuiltinRules_UniqueIDs guards against two builtin rules sharing an ID.
// LoadBuiltinRules appends every rule without deduping, so a collision makes
// ID-keyed lookups (scoring, ruleset selection, downstream mapping) resolve to
// only one of the colliding rules.
func TestBuiltinRules_UniqueIDs(t *testing.T) {
	rules, err := NewLoader().LoadBuiltinRules()
	if err != nil {
		t.Fatalf("LoadBuiltinRules failed: %v", err)
	}

	nameByID := make(map[string]string, len(rules))
	for _, r := range rules {
		if prev, dup := nameByID[r.ID]; dup {
			t.Errorf("duplicate rule ID %q: %q and %q", r.ID, prev, r.Name)
		}
		nameByID[r.ID] = r.Name
	}
}
