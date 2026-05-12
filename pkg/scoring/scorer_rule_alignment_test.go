package scoring

import (
	"fmt"
	"testing"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/stretchr/testify/require"
)

// TestBuiltinScorers_AllRuleIDsReferenceExtantRules is a table-driven guard
// that loads the embedded rule YAML files and the embedded scorer YAML files
// and verifies that every rule_id listed in every scorer exists in the actual
// rule set.
//
// Purpose: catch renames or deletions of rule IDs without a corresponding
// update to the scorer YAMLs. For example, if np.aws.1 were renamed to
// np.aws.10, the aws-key-scope scorer would silently become a no-op; this
// test makes that failure loud.
//
// Implementation notes:
//   - Uses pkg/rule.NewLoader().LoadBuiltinRules() for the rule set (same
//     embedded FS the production binary uses).
//   - Uses pkg/scoring.NewLoader().LoadBuiltinScorers() for the scorer set.
//   - No external fixtures or test data files needed.
func TestBuiltinScorers_AllRuleIDsReferenceExtantRules(t *testing.T) {
	// Load the canonical set of built-in rules.
	ruleLoader := rule.NewLoader()
	rules, err := ruleLoader.LoadBuiltinRules()
	require.NoError(t, err, "failed to load builtin rules")
	require.NotEmpty(t, rules, "no builtin rules found — embedded FS may be broken")

	// Build a fast-lookup set of rule IDs.
	ruleIDSet := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		ruleIDSet[r.ID] = struct{}{}
	}

	// Load all builtin scorers.
	scorerLoader := NewLoader()
	scorers, err := scorerLoader.LoadBuiltinScorers()
	require.NoError(t, err, "failed to load builtin scorers")
	require.NotEmpty(t, scorers, "no builtin scorers found — embedded FS may be broken")

	// For each scorer, for each rule_id, assert it exists in the rule set.
	for _, s := range scorers {
		scorer := s // pin loop variable
		for _, ruleID := range scorer.RuleIDs {
			ruleID := ruleID // pin loop variable
			t.Run(fmt.Sprintf("scorer=%s/rule=%s", scorer.Name, ruleID), func(t *testing.T) {
				if _, ok := ruleIDSet[ruleID]; !ok {
					t.Errorf(
						"scorer %q references nonexistent rule ID %q — "+
							"either the rule was renamed/deleted or the scorer YAML needs updating",
						scorer.Name, ruleID,
					)
				}
			})
		}
	}
}

// TestBuiltinGoScorers_AllRuleIDsReferenceExtantRules is a drift guard that
// verifies every rule ID referenced by a built-in Go scorer actually exists
// in the embedded rule set.
//
// Purpose: catch renames or deletions of rule IDs without a corresponding
// update to the Go scorer builders (AWSGoScorer, GitHubGoScorer, etc.).
func TestBuiltinGoScorers_AllRuleIDsReferenceExtantRules(t *testing.T) {
	ruleLoader := rule.NewLoader()
	rules, err := ruleLoader.LoadBuiltinRules()
	require.NoError(t, err, "failed to load builtin rules")

	ruleIDSet := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		ruleIDSet[r.ID] = struct{}{}
	}

	for _, s := range BuiltinGoScorers() {
		scorer := s
		for _, ruleID := range scorer.RuleIDs {
			ruleID := ruleID
			t.Run(fmt.Sprintf("scorer=%s/rule=%s", scorer.Name, ruleID), func(t *testing.T) {
				if _, ok := ruleIDSet[ruleID]; !ok {
					t.Errorf(
						"Go scorer %q references nonexistent rule ID %q — "+
							"update the scorer or add the missing rule",
						scorer.Name, ruleID,
					)
				}
			})
		}
	}
}
