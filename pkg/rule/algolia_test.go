package rule

import (
	"strings"
	"testing"
)

// TestAlgoliaRules_HasNamedCaptureGroups verifies the algolia rules
// have named capture groups required for validation
func TestAlgoliaRules_HasNamedCaptureGroups(t *testing.T) {
	// Load the algolia rules
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		t.Fatalf("failed to load builtin rules: %v", err)
	}

	// Test cases for each algolia rule
	testCases := []struct {
		ruleID        string
		expectedGroup string
	}{
		{
			ruleID:        "kingfisher.algolia.1",
			expectedGroup: "(?P<token>",
		},
		{
			ruleID:        "kingfisher.algolia.2",
			expectedGroup: "(?P<appid>",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.ruleID, func(t *testing.T) {
			// Find the rule
			var pattern string
			for _, rule := range rules {
				if rule.ID == tc.ruleID {
					pattern = rule.Pattern
					break
				}
			}

			if pattern == "" {
				t.Fatalf("algolia rule not found - %s rule ID not found in builtin rules", tc.ruleID)
			}

			// Test that the pattern has the required named capture group
			if !strings.Contains(pattern, tc.expectedGroup) {
				t.Errorf("%s rule pattern must have named capture group '%s' for validator integration, got pattern: %s",
					tc.ruleID, tc.expectedGroup, pattern)
			}
		})
	}
}
