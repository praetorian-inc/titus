package rule

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestFacebookAppCredentials_RuleExists verifies the np.facebook.3 rule exists
// and has the correct structure for detecting paired Facebook app credentials
func TestFacebookAppCredentials_RuleExists(t *testing.T) {
	// Load the facebook.yml file containing all Facebook rules
	data, err := builtinRulesFS.ReadFile("rules/facebook.yml")
	if err != nil {
		t.Fatalf("Failed to read facebook.yml: %v", err)
	}

	// Parse the YAML to get all rules
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	if err != nil {
		t.Fatalf("Failed to parse facebook.yml: %v", err)
	}

	// Find the np.facebook.3 rule
	var facebookAppRule *yamlRule
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "np.facebook.3" {
			facebookAppRule = &yamlFile.Rules[i]
			break
		}
	}

	if facebookAppRule == nil {
		t.Fatal("np.facebook.3 rule not found in facebook.yml")
	}

	// Verify the rule has the expected properties
	if facebookAppRule.Name != "Facebook App Credentials" {
		t.Errorf("Expected name 'Facebook App Credentials', got '%s'", facebookAppRule.Name)
	}

	// Verify pattern contains key components for paired detection
	pattern := facebookAppRule.Pattern
	if !strings.Contains(pattern, "app_id") && !strings.Contains(pattern, "client_id") {
		t.Error("Pattern should contain 'app_id' or 'client_id'")
	}
	if !strings.Contains(pattern, "app_secret") && !strings.Contains(pattern, "client_secret") {
		t.Error("Pattern should contain 'app_secret' or 'client_secret'")
	}
	if !strings.Contains(pattern, "(?P<app_id>") {
		t.Error("Pattern should have named capture group 'app_id'")
	}
	if !strings.Contains(pattern, "(?P<secret>") {
		t.Error("Pattern should have named capture group 'secret'")
	}

	// Verify categories
	hasAPI := false
	hasSecret := false
	for _, cat := range facebookAppRule.Categories {
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
	if len(facebookAppRule.Examples) == 0 {
		t.Error("Rule should have at least one example")
	}

	// Verify references
	if len(facebookAppRule.References) == 0 {
		t.Error("Rule should have at least one reference")
	}
}

// TestFacebookAppCredentials_ExamplesIncluded tests that positive and negative examples are included
func TestFacebookAppCredentials_ExamplesIncluded(t *testing.T) {
	// Load the facebook.yml file
	data, err := builtinRulesFS.ReadFile("rules/facebook.yml")
	if err != nil {
		t.Fatalf("Failed to read facebook.yml: %v", err)
	}

	// Parse the YAML
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	if err != nil {
		t.Fatalf("Failed to parse facebook.yml: %v", err)
	}

	// Find the np.facebook.3 rule
	var facebookAppRule *yamlRule
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "np.facebook.3" {
			facebookAppRule = &yamlFile.Rules[i]
			break
		}
	}

	if facebookAppRule == nil {
		t.Fatal("np.facebook.3 rule not found")
	}

	// Check for expected example patterns
	expectedExamplePatterns := []string{
		"app_id",
		"app_secret",
		"1241440636013546",  // Example app_id
		"c0acf898d0cf77b57dfae30210d6acf9",  // Example app_secret
	}

	for _, pattern := range expectedExamplePatterns {
		found := false
		for _, example := range facebookAppRule.Examples {
			if strings.Contains(example, pattern) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected to find pattern '%s' in examples", pattern)
		}
	}

	// Verify negative examples exist
	if len(facebookAppRule.NegativeExamples) == 0 {
		t.Error("Rule should have at least one negative example")
	}
}
