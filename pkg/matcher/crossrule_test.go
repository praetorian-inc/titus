package matcher

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeMatch(ruleID string, groups ...string) *types.Match {
	g := make([][]byte, len(groups))
	for i, s := range groups {
		g[i] = []byte(s)
	}
	return &types.Match{
		RuleID: ruleID,
		Groups: g,
	}
}

func makeRules(rules ...struct{ id, pattern string }) map[string]*types.Rule {
	m := make(map[string]*types.Rule)
	for _, r := range rules {
		m[r.id] = &types.Rule{ID: r.id, Pattern: r.pattern}
	}
	return m
}

func TestCrossRule_AWSCombo(t *testing.T) {
	// np.aws.1 captures key, np.aws.2 captures secret, np.aws.6 captures both.
	// aws.6 shares group[0] with aws.1 and group[1] with aws.2 → all clustered.
	// aws.6 wins: most groups (2 > 1).
	rules := makeRules(
		struct{ id, pattern string }{"np.aws.1", `AKIA[A-Z0-9]{16}`},
		struct{ id, pattern string }{"np.aws.2", `aws_secret.*[a-z0-9/+=]{40}`},
		struct{ id, pattern string }{"np.aws.6", `AKIA[A-Z0-9]{16}.*[A-Za-z0-9/+=]{40}`},
	)

	// All have validators
	canValidate := func(ruleID string) bool { return true }

	dedup := NewCrossRuleDeduplicator(rules, canValidate)

	matches := []*types.Match{
		makeMatch("np.aws.1", "AKIAZ52KNG5GARBXTEST"),
		makeMatch("np.aws.2", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		makeMatch("np.aws.6", "AKIAZ52KNG5GARBXTEST", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
	}

	result := dedup.Deduplicate(matches)

	require.Len(t, result, 1)
	assert.Equal(t, "np.aws.6", result[0].RuleID)
}

func TestCrossRule_ValidatorWins(t *testing.T) {
	// RuleA has 2 groups but no validator. RuleB has 1 group but has validator.
	// They share a group value. Validator priority wins.
	rules := makeRules(
		struct{ id, pattern string }{"rule.a", `pattern_a`},
		struct{ id, pattern string }{"rule.b", `pattern_b`},
	)

	canValidate := func(ruleID string) bool { return ruleID == "rule.b" }

	dedup := NewCrossRuleDeduplicator(rules, canValidate)

	matches := []*types.Match{
		makeMatch("rule.a", "SECRET123", "extra_group"),
		makeMatch("rule.b", "SECRET123"),
	}

	result := dedup.Deduplicate(matches)

	require.Len(t, result, 1)
	assert.Equal(t, "rule.b", result[0].RuleID)
}

func TestCrossRule_NoOverlap_DifferentSecrets(t *testing.T) {
	// AWS key and Stripe key in same file — no shared group values.
	rules := makeRules(
		struct{ id, pattern string }{"np.aws.1", `AKIA[A-Z0-9]{16}`},
		struct{ id, pattern string }{"np.stripe.1", `sk_live_[a-z0-9]{24}`},
	)

	dedup := NewCrossRuleDeduplicator(rules, nil)

	matches := []*types.Match{
		makeMatch("np.aws.1", "AKIAZ52KNG5GARBXTEST"),
		makeMatch("np.stripe.1", "sk_live_abc123def456ghi789jk"),
	}

	result := dedup.Deduplicate(matches)

	require.Len(t, result, 2)
}

func TestCrossRule_TwoDifferentAWSKeys(t *testing.T) {
	// Two different AWS keys in same file — different values, both survive.
	rules := makeRules(
		struct{ id, pattern string }{"np.aws.1", `AKIA[A-Z0-9]{16}`},
	)

	dedup := NewCrossRuleDeduplicator(rules, nil)

	matches := []*types.Match{
		makeMatch("np.aws.1", "AKIAZ52KNG5GARBXAAAA"),
		makeMatch("np.aws.1", "AKIAZ52KNG5GARBXBBBB"),
	}

	result := dedup.Deduplicate(matches)

	require.Len(t, result, 2)
}

func TestCrossRule_SingleMatch(t *testing.T) {
	dedup := NewCrossRuleDeduplicator(nil, nil)

	matches := []*types.Match{
		makeMatch("np.aws.1", "AKIAZ52KNG5GARBXTEST"),
	}

	result := dedup.Deduplicate(matches)

	require.Len(t, result, 1)
	assert.Equal(t, "np.aws.1", result[0].RuleID)
}

func TestCrossRule_EmptyInput(t *testing.T) {
	dedup := NewCrossRuleDeduplicator(nil, nil)
	result := dedup.Deduplicate(nil)
	assert.Nil(t, result)
}

func TestCrossRule_EmptyGroups(t *testing.T) {
	// Matches with empty capture groups should not be clustered together.
	rules := makeRules(
		struct{ id, pattern string }{"rule.a", `pattern_a`},
		struct{ id, pattern string }{"rule.b", `pattern_b`},
	)

	dedup := NewCrossRuleDeduplicator(rules, nil)

	matches := []*types.Match{
		makeMatch("rule.a", ""),
		makeMatch("rule.b", ""),
	}

	result := dedup.Deduplicate(matches)

	require.Len(t, result, 2)
}

func TestCrossRule_TransitiveChaining(t *testing.T) {
	// A shares value with B, B shares value with C, A doesn't share with C directly.
	// All three should be in one cluster via transitive union.
	rules := makeRules(
		struct{ id, pattern string }{"rule.a", `a`},
		struct{ id, pattern string }{"rule.b", `ab`},
		struct{ id, pattern string }{"rule.c", `c`},
	)

	canValidate := func(ruleID string) bool { return ruleID == "rule.b" }

	dedup := NewCrossRuleDeduplicator(rules, canValidate)

	matches := []*types.Match{
		makeMatch("rule.a", "VALUE_X"),
		makeMatch("rule.b", "VALUE_X", "VALUE_Y"),
		makeMatch("rule.c", "VALUE_Y"),
	}

	result := dedup.Deduplicate(matches)

	require.Len(t, result, 1)
	assert.Equal(t, "rule.b", result[0].RuleID)
}

func TestCrossRule_GroupCountTiebreaker(t *testing.T) {
	// Both have validators, but rule.combo has more groups.
	rules := makeRules(
		struct{ id, pattern string }{"rule.single", `pattern_short`},
		struct{ id, pattern string }{"rule.combo", `pattern_longer`},
	)

	canValidate := func(ruleID string) bool { return true }

	dedup := NewCrossRuleDeduplicator(rules, canValidate)

	matches := []*types.Match{
		makeMatch("rule.single", "SECRET123"),
		makeMatch("rule.combo", "SECRET123", "EXTRA_DATA"),
	}

	result := dedup.Deduplicate(matches)

	require.Len(t, result, 1)
	assert.Equal(t, "rule.combo", result[0].RuleID)
}

func TestCrossRule_PatternLengthTiebreaker(t *testing.T) {
	// Same validator status, same group count, same captured length.
	// Longer pattern wins.
	rules := makeRules(
		struct{ id, pattern string }{"rule.short", `[a-z]{10}`},
		struct{ id, pattern string }{"rule.long", `(?:aws_secret_key=)[a-z]{10}`},
	)

	dedup := NewCrossRuleDeduplicator(rules, nil)

	matches := []*types.Match{
		makeMatch("rule.short", "abcdefghij"),
		makeMatch("rule.long", "abcdefghij"),
	}

	result := dedup.Deduplicate(matches)

	require.Len(t, result, 1)
	assert.Equal(t, "rule.long", result[0].RuleID)
}

func TestCrossRule_NilCanValidate(t *testing.T) {
	// When canValidate is nil (validation disabled), scoring should still work.
	rules := makeRules(
		struct{ id, pattern string }{"np.aws.1", `short`},
		struct{ id, pattern string }{"np.aws.6", `longer_pattern`},
	)

	dedup := NewCrossRuleDeduplicator(rules, nil)

	matches := []*types.Match{
		makeMatch("np.aws.1", "AKIAZ52KNG5GARBXTEST"),
		makeMatch("np.aws.6", "AKIAZ52KNG5GARBXTEST", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
	}

	result := dedup.Deduplicate(matches)

	require.Len(t, result, 1)
	assert.Equal(t, "np.aws.6", result[0].RuleID)
}

func makeMatchWithOffset(ruleID string, start int64, groups ...string) *types.Match {
	m := makeMatch(ruleID, groups...)
	m.Location.Offset.Start = start
	return m
}

func TestCrossRuleDeduplicator_DeterministicAcrossRuns(t *testing.T) {
	// Build a scenario where two rules have identical matchScore:
	// same hasValidator=false, same groupCount=1, same groupsLen (same value length),
	// same patternLen (same pattern length). Only ruleID differs.
	// "rule.aaa" < "rule.zzz" lexicographically, so "rule.aaa" must always win.
	rules := makeRules(
		struct{ id, pattern string }{"rule.aaa", `[a-z]{5}`},
		struct{ id, pattern string }{"rule.zzz", `[a-z]{5}`},
	)

	dedup := NewCrossRuleDeduplicator(rules, nil)

	// Both matches share the same group value → single cluster.
	// Scores are identical on all criteria except ruleID.
	matches := []*types.Match{
		makeMatch("rule.aaa", "hello"),
		makeMatch("rule.zzz", "hello"),
	}

	// Run Deduplicate 20 times; always the same winner must be returned.
	var firstWinner string
	for i := 0; i < 20; i++ {
		result := dedup.Deduplicate(matches)
		require.Len(t, result, 1, "run %d: expected 1 result", i)
		if i == 0 {
			firstWinner = result[0].RuleID
		} else {
			assert.Equal(t, firstWinner, result[0].RuleID,
				"run %d: winner changed (nondeterministic tiebreak)", i)
		}
	}
	// The deterministic winner must be the lexicographically smaller RuleID.
	assert.Equal(t, "rule.aaa", firstWinner, "expected lexicographically smaller RuleID to win")
}

func TestCrossRuleDeduplicator_DeterministicClusterOrder(t *testing.T) {
	// Build 3 independent clusters (no shared group values) at distinct offsets.
	// Each cluster has exactly one match so the winner is unambiguous.
	// The output order must be deterministic across repeated calls.
	rules := makeRules(
		struct{ id, pattern string }{"rule.x", `x`},
		struct{ id, pattern string }{"rule.y", `y`},
		struct{ id, pattern string }{"rule.z", `z`},
	)

	dedup := NewCrossRuleDeduplicator(rules, nil)

	// Three non-overlapping clusters, placed at byte offsets 100, 50, 200.
	// After sorting by min start offset the expected order is: offset 50, 100, 200.
	matches := []*types.Match{
		makeMatchWithOffset("rule.x", 100, "unique_x"),
		makeMatchWithOffset("rule.y", 50, "unique_y"),
		makeMatchWithOffset("rule.z", 200, "unique_z"),
	}

	// Run 20 times; the output order must always match the sorted-by-offset order.
	for i := 0; i < 20; i++ {
		result := dedup.Deduplicate(matches)
		require.Len(t, result, 3, "run %d: expected 3 results", i)
		assert.Equal(t, "rule.y", result[0].RuleID, "run %d: first result should be offset 50 (rule.y)", i)
		assert.Equal(t, "rule.x", result[1].RuleID, "run %d: second result should be offset 100 (rule.x)", i)
		assert.Equal(t, "rule.z", result[2].RuleID, "run %d: third result should be offset 200 (rule.z)", i)
	}
}
