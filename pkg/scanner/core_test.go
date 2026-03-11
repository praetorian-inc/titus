//go:build !wasm

package scanner

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildRulesJSON encodes a slice of rules to JSON for use with NewCore.
func buildRulesJSON(rules []*types.Rule) string {
	b, err := json.Marshal(rules)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestCore_Scan_DeduplicatesCrossRuleMatches verifies that Scan applies
// cross-rule deduplication before returning results.
//
// Both rules capture the same AWS access key. The combo rule also captures
// the credential suffix, giving it two capture groups. Dedup clusters them
// by the shared key value and keeps only the more informative combo match.
func TestCore_Scan_DeduplicatesCrossRuleMatches(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "rule.key_only",
			Name:    "Key Only",
			Pattern: `(AKIA[A-Z0-9]{16})`,
		},
		{
			ID:      "rule.key_and_secret",
			Name:    "Key and Secret",
			Pattern: `(AKIA[A-Z0-9]{16}).*([A-Za-z0-9/+=]{10})`,
		},
	}

	core, err := NewCore(buildRulesJSON(rules), nil)
	require.NoError(t, err)
	defer core.Close()

	content := "aws_access_key=AKIAZ52KNG5GARBXTEST credential=wJalrXUtnFE"
	result, err := core.Scan(content, "test")
	require.NoError(t, err)

	// Dedup clusters by shared group value "AKIAZ52KNG5GARBXTEST"
	// rule.key_and_secret has more groups so it wins
	require.Len(t, result.Matches, 1)
	assert.Equal(t, "rule.key_and_secret", result.Matches[0].RuleID)
}

// TestCore_Scan_PreservesIndependentMatches verifies that Scan does not
// suppress matches for different secrets (no shared capture group values).
func TestCore_Scan_PreservesIndependentMatches(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "rule.aws",
			Name:    "AWS Key",
			Pattern: `(AKIA[A-Z0-9]{16})`,
		},
		{
			ID:      "rule.stripe",
			Name:    "Stripe Key",
			Pattern: `(sk_live_[a-z0-9]{10})`,
		},
	}

	core, err := NewCore(buildRulesJSON(rules), nil)
	require.NoError(t, err)
	defer core.Close()

	// Content with two different secrets — neither should be suppressed
	result, err := core.Scan("aws=AKIAZ52KNG5GARBXTEST stripe=sk_live_abcdef0123", "test")
	require.NoError(t, err)

	assert.Len(t, result.Matches, 2)
}

// TestCore_ScanBatch_DeduplicatesPerItem verifies that ScanBatch applies
// dedup independently to each scanned item.
func TestCore_ScanBatch_DeduplicatesPerItem(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "rule.key_only",
			Name:    "Key Only",
			Pattern: `(AKIA[A-Z0-9]{16})`,
		},
		{
			ID:      "rule.key_and_secret",
			Name:    "Key and Secret",
			Pattern: `(AKIA[A-Z0-9]{16}).*([A-Za-z0-9/+=]{10})`,
		},
	}

	core, err := NewCore(buildRulesJSON(rules), nil)
	require.NoError(t, err)
	defer core.Close()

	items := []ContentItem{
		{Source: "file1", Content: "aws_access_key=AKIAZ52KNG5GARBXTEST credential=wJalrXUtnFE"},
		{Source: "file2", Content: "aws_access_key=AKIAAAAAAAAAAAAATEST credential=BBBBBBBBBB"},
	}

	batchResult, err := core.ScanBatch(items)
	require.NoError(t, err)

	require.Len(t, batchResult.Results, 2)
	// Each item: two rules match same AWS key, dedup keeps only the combo rule
	assert.Len(t, batchResult.Results[0].Matches, 1)
	assert.Equal(t, "rule.key_and_secret", batchResult.Results[0].Matches[0].RuleID)
	assert.Len(t, batchResult.Results[1].Matches, 1)
	assert.Equal(t, "rule.key_and_secret", batchResult.Results[1].Matches[0].RuleID)
	// Total reflects deduplicated counts: 1 per item
	assert.Equal(t, 2, batchResult.Total)
}

// TestCore_SetCanValidate_PreferValidatedRule verifies that after calling
// SetCanValidate, the deduplicator uses validator awareness to break ties.
//
// rule.many_groups has two capture groups; rule.has_validator has one group
// but is declared as having a validator. Without SetCanValidate the
// many-groups rule wins on group count. After SetCanValidate the validated
// rule should win because validator presence outranks group count.
func TestCore_SetCanValidate_PreferValidatedRule(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "rule.many_groups",
			Name:    "Many Groups",
			Pattern: `(AKIA[A-Z0-9]{16}).*([A-Za-z0-9/+=]{10})`,
		},
		{
			ID:      "rule.has_validator",
			Name:    "Has Validator",
			Pattern: `(AKIA[A-Z0-9]{16})`,
		},
	}

	core, err := NewCore(buildRulesJSON(rules), nil)
	require.NoError(t, err)
	defer core.Close()

	content := "aws_access_key=AKIAZ52KNG5GARBXTEST credential=wJalrXUtnFE"

	// Without SetCanValidate: rule.many_groups wins due to more capture groups
	result, err := core.Scan(content, "test")
	require.NoError(t, err)
	require.Len(t, result.Matches, 1)
	assert.Equal(t, "rule.many_groups", result.Matches[0].RuleID)

	// After SetCanValidate: rule.has_validator should win (validator beats group count)
	core.SetCanValidate(func(ruleID string) bool {
		return ruleID == "rule.has_validator"
	})

	result, err = core.Scan(content, "test")
	require.NoError(t, err)
	require.Len(t, result.Matches, 1)
	assert.Equal(t, "rule.has_validator", result.Matches[0].RuleID)
}
