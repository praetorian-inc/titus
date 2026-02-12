package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRule(t *testing.T) {
	rule := Rule{
		ID:          "np.aws.1",
		Name:        "AWS API Key",
		Pattern:     `AKIA[0-9A-Z]{16}`,
		Description: "Detects AWS API keys",
		Examples:    []string{"AKIAIOSFODNN7EXAMPLE"},
		NegativeExamples: []string{"NOT_AN_AWS_KEY"},
		References:  []string{"https://aws.amazon.com/security"},
		Categories:  []string{"cloud", "aws", "credentials"},
	}

	assert.Equal(t, "np.aws.1", rule.ID)
	assert.Equal(t, "AWS API Key", rule.Name)
	assert.Equal(t, `AKIA[0-9A-Z]{16}`, rule.Pattern)
	assert.Equal(t, "Detects AWS API keys", rule.Description)
	require.Len(t, rule.Examples, 1)
	require.Len(t, rule.NegativeExamples, 1)
	require.Len(t, rule.References, 1)
	require.Len(t, rule.Categories, 3)
}

func TestRule_WithKeywords(t *testing.T) {
	rule := Rule{
		ID:       "np.aws.1",
		Name:     "AWS API Key",
		Pattern:  `AKIA[0-9A-Z]{16}`,
		Keywords: []string{"AKIA", "ASIA", "AIDA", "AROA"},
	}

	require.Len(t, rule.Keywords, 4)
	assert.Equal(t, "AKIA", rule.Keywords[0])
	assert.Equal(t, "ASIA", rule.Keywords[1])
	assert.Equal(t, "AIDA", rule.Keywords[2])
	assert.Equal(t, "AROA", rule.Keywords[3])
}

func TestRule_KeywordsOptional(t *testing.T) {
	// Rule without keywords (backwards compatible)
	rule := Rule{
		ID:      "np.test.1",
		Name:    "Test Rule",
		Pattern: `test`,
	}

	assert.Nil(t, rule.Keywords)
}

func TestRule_ComputeStructuralID(t *testing.T) {
	rule := Rule{
		ID:      "np.aws.1",
		Name:    "AWS API Key",
		Pattern: `AKIA[0-9A-Z]{16}`,
	}

	structuralID := rule.ComputeStructuralID()

	// Should be SHA-1 hex (40 chars)
	assert.Len(t, structuralID, 40)
	assert.NotEmpty(t, structuralID)

	// Same pattern should produce same ID
	rule2 := Rule{
		ID:      "different.id",
		Name:    "Different Name",
		Pattern: `AKIA[0-9A-Z]{16}`, // Same pattern
	}
	structuralID2 := rule2.ComputeStructuralID()
	assert.Equal(t, structuralID, structuralID2)

	// Different pattern should produce different ID
	rule3 := Rule{
		ID:      "np.aws.1",
		Name:    "AWS API Key",
		Pattern: `AKIA[0-9A-Z]{17}`, // Different pattern
	}
	structuralID3 := rule3.ComputeStructuralID()
	assert.NotEqual(t, structuralID, structuralID3)
}

func TestRule_MinimalFields(t *testing.T) {
	// Rule with only required fields
	rule := Rule{
		ID:      "np.test.1",
		Name:    "Test Rule",
		Pattern: `test`,
	}

	assert.Equal(t, "np.test.1", rule.ID)
	assert.Equal(t, "Test Rule", rule.Name)
	assert.Equal(t, "test", rule.Pattern)

	// Optional fields should be empty/nil
	assert.Empty(t, rule.Description)
	assert.Nil(t, rule.Examples)
	assert.Nil(t, rule.NegativeExamples)
	assert.Nil(t, rule.References)
	assert.Nil(t, rule.Categories)
}

func TestRuleset(t *testing.T) {
	ruleset := Ruleset{
		ID:          "aws-secrets",
		Name:        "AWS Secrets",
		Description: "Rules for detecting AWS credentials",
		RuleIDs:     []string{"np.aws.1", "np.aws.2", "np.aws.3"},
	}

	assert.Equal(t, "aws-secrets", ruleset.ID)
	assert.Equal(t, "AWS Secrets", ruleset.Name)
	assert.Equal(t, "Rules for detecting AWS credentials", ruleset.Description)
	require.Len(t, ruleset.RuleIDs, 3)
	assert.Equal(t, "np.aws.1", ruleset.RuleIDs[0])
}

func TestRuleset_EmptyRuleIDs(t *testing.T) {
	ruleset := Ruleset{
		ID:          "empty-ruleset",
		Name:        "Empty Ruleset",
		Description: "A ruleset with no rules",
		RuleIDs:     []string{},
	}

	require.NotNil(t, ruleset.RuleIDs)
	assert.Len(t, ruleset.RuleIDs, 0)
}

func TestRuleset_NilRuleIDs(t *testing.T) {
	ruleset := Ruleset{
		ID:          "nil-ruleset",
		Name:        "Nil Ruleset",
		Description: "A ruleset with nil rules",
		RuleIDs:     nil,
	}

	assert.Nil(t, ruleset.RuleIDs)
}
