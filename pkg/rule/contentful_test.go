package rule

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestContentfulDeliveryToken_RuleExists verifies the kingfisher.contentful.1 rule exists
// and has the correct structure for detecting Contentful Delivery API tokens
func TestContentfulDeliveryToken_RuleExists(t *testing.T) {
	// Load the contentful.yml file
	data, err := builtinRulesFS.ReadFile("rules/contentful.yml")
	if err != nil {
		t.Fatalf("Failed to read contentful.yml: %v", err)
	}

	// Parse the YAML
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	if err != nil {
		t.Fatalf("Failed to parse contentful.yml: %v", err)
	}

	// Find the kingfisher.contentful.1 rule
	var deliveryRule *yamlRule
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "kingfisher.contentful.1" {
			deliveryRule = &yamlFile.Rules[i]
			break
		}
	}

	if deliveryRule == nil {
		t.Fatal("kingfisher.contentful.1 rule not found in contentful.yml")
	}

	// Verify the rule has expected properties
	if deliveryRule.Name != "Contentful Delivery API Token" {
		t.Errorf("Expected name 'Contentful Delivery API Token', got '%s'", deliveryRule.Name)
	}

	// Verify categories
	hasAPI := false
	hasSecret := false
	for _, cat := range deliveryRule.Categories {
		if cat == "api" {
			hasAPI = true
		}
		if cat == "secret" {
			hasSecret = true
		}
	}
	if !hasAPI {
		t.Error("Rule should have 'api' category")
	}
	if !hasSecret {
		t.Error("Rule should have 'secret' category")
	}

	// Verify examples exist
	if len(deliveryRule.Examples) == 0 {
		t.Error("Rule should have at least one example")
	}

	// Verify references
	if len(deliveryRule.References) == 0 {
		t.Error("Rule should have at least one reference")
	}
}

// TestContentfulPersonalAccessToken_RuleExists verifies the kingfisher.contentful.2 rule exists
func TestContentfulPersonalAccessToken_RuleExists(t *testing.T) {
	// Load the contentful.yml file
	data, err := builtinRulesFS.ReadFile("rules/contentful.yml")
	if err != nil {
		t.Fatalf("Failed to read contentful.yml: %v", err)
	}

	// Parse the YAML
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	if err != nil {
		t.Fatalf("Failed to parse contentful.yml: %v", err)
	}

	// Find the kingfisher.contentful.2 rule
	var patRule *yamlRule
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "kingfisher.contentful.2" {
			patRule = &yamlFile.Rules[i]
			break
		}
	}

	if patRule == nil {
		t.Fatal("kingfisher.contentful.2 rule not found in contentful.yml")
	}

	// Verify the rule has expected properties
	if patRule.Name != "Contentful Personal Access Token" {
		t.Errorf("Expected name 'Contentful Personal Access Token', got '%s'", patRule.Name)
	}

	// Verify categories
	hasAPI := false
	hasSecret := false
	for _, cat := range patRule.Categories {
		if cat == "api" {
			hasAPI = true
		}
		if cat == "secret" {
			hasSecret = true
		}
	}
	if !hasAPI {
		t.Error("Rule should have 'api' category")
	}
	if !hasSecret {
		t.Error("Rule should have 'secret' category")
	}

	// Verify examples exist
	if len(patRule.Examples) == 0 {
		t.Error("Rule should have at least one example")
	}
}

// TestContentfulDeliveryToken_HasNamedCaptureGroup verifies the pattern has named capture group
func TestContentfulDeliveryToken_HasNamedCaptureGroup(t *testing.T) {
	// Load the contentful.yml file
	data, err := builtinRulesFS.ReadFile("rules/contentful.yml")
	if err != nil {
		t.Fatalf("Failed to read contentful.yml: %v", err)
	}

	// Parse the YAML
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	if err != nil {
		t.Fatalf("Failed to parse contentful.yml: %v", err)
	}

	// Find the kingfisher.contentful.1 rule
	var pattern string
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "kingfisher.contentful.1" {
			pattern = yamlFile.Rules[i].Pattern
			break
		}
	}

	if pattern == "" {
		t.Fatal("kingfisher.contentful.1 rule not found")
	}

	// Test that the pattern has a named capture group called "token"
	// This is required for the validator to extract the secret
	if !strings.Contains(pattern, "(?P<token>") {
		t.Errorf("contentful delivery rule pattern must have named capture group '(?P<token>' for validator integration, got pattern:\n%s", pattern)
	}
}

// TestContentfulPersonalAccessToken_HasNamedCaptureGroup verifies the pattern has named capture group
func TestContentfulPersonalAccessToken_HasNamedCaptureGroup(t *testing.T) {
	// Load the contentful.yml file
	data, err := builtinRulesFS.ReadFile("rules/contentful.yml")
	if err != nil {
		t.Fatalf("Failed to read contentful.yml: %v", err)
	}

	// Parse the YAML
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	if err != nil {
		t.Fatalf("Failed to parse contentful.yml: %v", err)
	}

	// Find the kingfisher.contentful.2 rule
	var pattern string
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "kingfisher.contentful.2" {
			pattern = yamlFile.Rules[i].Pattern
			break
		}
	}

	if pattern == "" {
		t.Fatal("kingfisher.contentful.2 rule not found")
	}

	// Test that the pattern has a named capture group called "token"
	if !strings.Contains(pattern, "(?P<token>") {
		t.Errorf("contentful PAT rule pattern must have named capture group '(?P<token>' for validator integration, got pattern:\n%s", pattern)
	}
}

// TestContentfulDeliveryToken_PatternHasExamples verifies the delivery rule has examples
func TestContentfulDeliveryToken_PatternHasExamples(t *testing.T) {
	// Load the contentful.yml file
	data, err := builtinRulesFS.ReadFile("rules/contentful.yml")
	if err != nil {
		t.Fatalf("Failed to read contentful.yml: %v", err)
	}

	// Parse the YAML
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	if err != nil {
		t.Fatalf("Failed to parse contentful.yml: %v", err)
	}

	// Find the kingfisher.contentful.1 rule
	var rule *yamlRule
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "kingfisher.contentful.1" {
			rule = &yamlFile.Rules[i]
			break
		}
	}

	if rule == nil {
		t.Fatal("kingfisher.contentful.1 rule not found")
	}

	// Verify positive examples exist
	if len(rule.Examples) == 0 {
		t.Error("Rule should have at least one positive example")
	}

	// Verify negative examples exist
	if len(rule.NegativeExamples) == 0 {
		t.Error("Rule should have at least one negative example")
	}

	// Verify pattern is non-empty
	if rule.Pattern == "" {
		t.Error("Rule pattern should not be empty")
	}

	// Verify pattern contains the expected token structure
	if !strings.Contains(rule.Pattern, "[A-Z0-9_-]") {
		t.Error("Pattern should define token character class for delivery API tokens")
	}
}

// TestContentfulPersonalAccessToken_PatternHasExamples verifies the PAT rule has examples
func TestContentfulPersonalAccessToken_PatternHasExamples(t *testing.T) {
	// Load the contentful.yml file
	data, err := builtinRulesFS.ReadFile("rules/contentful.yml")
	if err != nil {
		t.Fatalf("Failed to read contentful.yml: %v", err)
	}

	// Parse the YAML
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	if err != nil {
		t.Fatalf("Failed to parse contentful.yml: %v", err)
	}

	// Find the kingfisher.contentful.2 rule
	var rule *yamlRule
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "kingfisher.contentful.2" {
			rule = &yamlFile.Rules[i]
			break
		}
	}

	if rule == nil {
		t.Fatal("kingfisher.contentful.2 rule not found")
	}

	// Verify positive examples exist
	if len(rule.Examples) == 0 {
		t.Error("Rule should have at least one positive example")
	}

	// Verify negative examples exist
	if len(rule.NegativeExamples) == 0 {
		t.Error("Rule should have at least one negative example")
	}

	// Verify pattern is non-empty
	if rule.Pattern == "" {
		t.Error("Rule pattern should not be empty")
	}

	// Verify pattern contains the CFPAT prefix
	if !strings.Contains(rule.Pattern, "CFPAT-") {
		t.Error("Pattern should match CFPAT- prefix for personal access tokens")
	}
}
