package rule

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func TestValidateRule_Valid(t *testing.T) {
	rule := &types.Rule{
		ID:      "np.test.1",
		Name:    "Test Rule",
		Pattern: "test.*pattern",
	}
	rule.StructuralID = rule.ComputeStructuralID()

	err := ValidateRule(rule)
	if err != nil {
		t.Errorf("ValidateRule failed for valid rule: %v", err)
	}
}

func TestValidateRule_NilRule(t *testing.T) {
	err := ValidateRule(nil)
	if err == nil {
		t.Error("expected error for nil rule")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("expected 'nil' in error message, got: %v", err)
	}
}

func TestValidateRule_MissingID(t *testing.T) {
	rule := &types.Rule{
		Name:    "Test Rule",
		Pattern: "test.*pattern",
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("expected error for missing ID")
	}
	if !strings.Contains(err.Error(), "ID") {
		t.Errorf("expected 'ID' in error message, got: %v", err)
	}
}

func TestValidateRule_MissingName(t *testing.T) {
	rule := &types.Rule{
		ID:      "np.test.1",
		Pattern: "test.*pattern",
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("expected error for missing name")
	}
	if !strings.Contains(err.Error(), "name") {
		t.Errorf("expected 'name' in error message, got: %v", err)
	}
}

func TestValidateRule_MissingPattern(t *testing.T) {
	rule := &types.Rule{
		ID:   "np.test.1",
		Name: "Test Rule",
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("expected error for missing pattern")
	}
	if !strings.Contains(err.Error(), "pattern") {
		t.Errorf("expected 'pattern' in error message, got: %v", err)
	}
}

func TestValidateRule_InvalidPattern(t *testing.T) {
	rule := &types.Rule{
		ID:      "np.test.1",
		Name:    "Test Rule",
		Pattern: "[invalid(regex",
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("expected error for invalid regex pattern")
	}
	if !strings.Contains(err.Error(), "pattern") {
		t.Errorf("expected 'pattern' in error message, got: %v", err)
	}
}

func TestValidateRule_InconsistentStructuralID(t *testing.T) {
	rule := &types.Rule{
		ID:           "np.test.1",
		Name:         "Test Rule",
		Pattern:      "test.*pattern",
		StructuralID: "wrong_id",
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("expected error for inconsistent StructuralID")
	}
	if !strings.Contains(err.Error(), "StructuralID") {
		t.Errorf("expected 'StructuralID' in error message, got: %v", err)
	}
}

func TestValidateRule_EmptyStructuralID(t *testing.T) {
	// Empty StructuralID is acceptable (will be computed later)
	rule := &types.Rule{
		ID:           "np.test.1",
		Name:         "Test Rule",
		Pattern:      "test.*pattern",
		StructuralID: "",
	}

	err := ValidateRule(rule)
	if err != nil {
		t.Errorf("ValidateRule failed for empty StructuralID: %v", err)
	}
}

func TestValidateRuleset_Valid(t *testing.T) {
	ruleset := &types.Ruleset{
		ID:      "rs.test",
		Name:    "Test Ruleset",
		RuleIDs: []string{"np.test.1", "np.test.2"},
	}

	knownRules := map[string]bool{
		"np.test.1": true,
		"np.test.2": true,
	}

	err := ValidateRuleset(ruleset, knownRules)
	if err != nil {
		t.Errorf("ValidateRuleset failed for valid ruleset: %v", err)
	}
}

func TestValidateRuleset_NilRuleset(t *testing.T) {
	err := ValidateRuleset(nil, nil)
	if err == nil {
		t.Error("expected error for nil ruleset")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("expected 'nil' in error message, got: %v", err)
	}
}

func TestValidateRuleset_MissingID(t *testing.T) {
	ruleset := &types.Ruleset{
		Name:    "Test Ruleset",
		RuleIDs: []string{"np.test.1"},
	}

	err := ValidateRuleset(ruleset, nil)
	if err == nil {
		t.Error("expected error for missing ID")
	}
	if !strings.Contains(err.Error(), "ID") {
		t.Errorf("expected 'ID' in error message, got: %v", err)
	}
}

func TestValidateRuleset_MissingName(t *testing.T) {
	ruleset := &types.Ruleset{
		ID:      "rs.test",
		RuleIDs: []string{"np.test.1"},
	}

	err := ValidateRuleset(ruleset, nil)
	if err == nil {
		t.Error("expected error for missing name")
	}
	if !strings.Contains(err.Error(), "name") {
		t.Errorf("expected 'name' in error message, got: %v", err)
	}
}

func TestValidateRuleset_EmptyRuleIDs(t *testing.T) {
	ruleset := &types.Ruleset{
		ID:      "rs.test",
		Name:    "Test Ruleset",
		RuleIDs: []string{},
	}

	err := ValidateRuleset(ruleset, nil)
	if err == nil {
		t.Error("expected error for empty RuleIDs")
	}
	if !strings.Contains(err.Error(), "rule") {
		t.Errorf("expected 'rule' in error message, got: %v", err)
	}
}

func TestValidateRuleset_UnknownRuleID(t *testing.T) {
	ruleset := &types.Ruleset{
		ID:      "rs.test",
		Name:    "Test Ruleset",
		RuleIDs: []string{"np.test.1", "np.unknown"},
	}

	knownRules := map[string]bool{
		"np.test.1": true,
	}

	err := ValidateRuleset(ruleset, knownRules)
	if err == nil {
		t.Error("expected error for unknown rule ID")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("expected 'unknown' in error message, got: %v", err)
	}
}

func TestValidateRuleset_NilKnownRules(t *testing.T) {
	// Nil knownRuleIDs map should skip reference checking
	ruleset := &types.Ruleset{
		ID:      "rs.test",
		Name:    "Test Ruleset",
		RuleIDs: []string{"np.test.1", "np.unknown"},
	}

	err := ValidateRuleset(ruleset, nil)
	if err != nil {
		t.Errorf("ValidateRuleset should skip reference check with nil map: %v", err)
	}
}

func TestValidateRuleset_DuplicateRuleIDs(t *testing.T) {
	ruleset := &types.Ruleset{
		ID:      "rs.test",
		Name:    "Test Ruleset",
		RuleIDs: []string{"np.test.1", "np.test.2", "np.test.1"},
	}

	knownRules := map[string]bool{
		"np.test.1": true,
		"np.test.2": true,
	}

	err := ValidateRuleset(ruleset, knownRules)
	if err == nil {
		t.Error("expected error for duplicate rule IDs")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected 'duplicate' in error message, got: %v", err)
	}
}

func TestValidateRuleset_AllRulesValid(t *testing.T) {
	// Test that all referenced rule IDs are valid
	ruleset := &types.Ruleset{
		ID:      "rs.test",
		Name:    "Test Ruleset",
		RuleIDs: []string{"np.test.1", "np.test.2", "np.test.3"},
	}

	knownRules := map[string]bool{
		"np.test.1": true,
		"np.test.2": true,
		"np.test.3": true,
	}

	err := ValidateRuleset(ruleset, knownRules)
	if err != nil {
		t.Errorf("ValidateRuleset failed for valid ruleset: %v", err)
	}
}

func TestValidateRule_ComplexPattern(t *testing.T) {
	// Test with complex regex pattern
	// Note: NoseyParker uses Hyperscan which supports more features than Go's regexp
	// This test uses a Go-compatible pattern for validation
	rule := &types.Rule{
		ID:      "np.aws.1",
		Name:    "AWS API Key",
		Pattern: `AKIA[A-Z0-9]{16}`,
	}

	err := ValidateRule(rule)
	if err != nil {
		t.Errorf("ValidateRule failed for complex pattern: %v", err)
	}
}

func TestValidateRule_WithAllFields(t *testing.T) {
	// Test validation with all optional fields populated
	rule := &types.Rule{
		ID:               "np.test.1",
		Name:             "Test Rule",
		Pattern:          "test.*pattern",
		Description:      "Test description",
		Examples:         []string{"test1", "test2"},
		NegativeExamples: []string{"nottest1", "nottest2"},
		References:       []string{"https://example.com"},
		Categories:       []string{"test", "example"},
	}
	rule.StructuralID = rule.ComputeStructuralID()

	err := ValidateRule(rule)
	if err != nil {
		t.Errorf("ValidateRule failed with all fields: %v", err)
	}
}
