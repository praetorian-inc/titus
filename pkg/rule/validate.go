package rule

import (
	"fmt"
	"regexp"

	"github.com/praetorian-inc/titus/pkg/types"
)

// ValidateRule checks rule consistency and required fields.
// Returns error if rule is invalid.
func ValidateRule(r *types.Rule) error {
	if r == nil {
		return fmt.Errorf("rule is nil")
	}

	// Check required fields
	if r.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if r.Pattern == "" {
		return fmt.Errorf("rule pattern is required")
	}

	// Validate pattern is a valid regex
	_, err := regexp.Compile(r.Pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern regex for rule %s: %w", r.ID, err)
	}

	// Validate StructuralID matches computed value
	expectedID := r.ComputeStructuralID()
	if r.StructuralID != "" && r.StructuralID != expectedID {
		return fmt.Errorf("rule %s has inconsistent StructuralID: got %s, expected %s",
			r.ID, r.StructuralID, expectedID)
	}

	return nil
}

// ValidateRuleset checks ruleset consistency and required fields.
// knownRuleIDs is a map of valid rule IDs for reference checking.
// Returns error if ruleset is invalid.
func ValidateRuleset(rs *types.Ruleset, knownRuleIDs map[string]bool) error {
	if rs == nil {
		return fmt.Errorf("ruleset is nil")
	}

	// Check required fields
	if rs.ID == "" {
		return fmt.Errorf("ruleset ID is required")
	}
	if rs.Name == "" {
		return fmt.Errorf("ruleset name is required")
	}
	if len(rs.RuleIDs) == 0 {
		return fmt.Errorf("ruleset %s must reference at least one rule", rs.ID)
	}

	// Validate all referenced rule IDs exist
	if knownRuleIDs != nil {
		for _, ruleID := range rs.RuleIDs {
			if !knownRuleIDs[ruleID] {
				return fmt.Errorf("ruleset %s references unknown rule ID: %s", rs.ID, ruleID)
			}
		}
	}

	// Check for duplicate rule IDs
	seen := make(map[string]bool)
	for _, ruleID := range rs.RuleIDs {
		if seen[ruleID] {
			return fmt.Errorf("ruleset %s contains duplicate rule ID: %s", rs.ID, ruleID)
		}
		seen[ruleID] = true
	}

	return nil
}
