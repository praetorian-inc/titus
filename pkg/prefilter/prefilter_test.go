package prefilter

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrefilter_RulesWithMatchingKeywords(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:       "rule1",
			Name:     "AWS Key",
			Pattern:  `AKIA[0-9A-Z]{16}`,
			Keywords: []string{"AKIA"},
		},
		{
			ID:       "rule2",
			Name:     "GitHub Token",
			Pattern:  `ghp_[A-Za-z0-9]{36}`,
			Keywords: []string{"ghp_"},
		},
	}

	pf := New(rules)
	content := []byte("Here is an AWS key: AKIAIOSFODNN7EXAMPLE")

	filtered := pf.Filter(content)

	// Should return rule1 (contains "AKIA"), not rule2
	require.Len(t, filtered, 1)
	assert.Equal(t, "rule1", filtered[0].ID)
}

func TestPrefilter_RulesWithoutKeywords(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:       "rule1",
			Name:     "Generic Secret",
			Pattern:  `secret\d+`,
			Keywords: nil, // No keywords - always run
		},
		{
			ID:       "rule2",
			Name:     "Password",
			Pattern:  `password=\w+`,
			Keywords: nil, // No keywords - always run
		},
	}

	pf := New(rules)
	content := []byte("test content without matches")

	filtered := pf.Filter(content)

	// Both rules should be returned (no keywords = always check)
	require.Len(t, filtered, 2)
}

func TestPrefilter_RulesWithNonMatchingKeywords(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:       "rule1",
			Name:     "AWS Key",
			Pattern:  `AKIA[0-9A-Z]{16}`,
			Keywords: []string{"AKIA"},
		},
		{
			ID:       "rule2",
			Name:     "GitHub Token",
			Pattern:  `ghp_[A-Za-z0-9]{36}`,
			Keywords: []string{"ghp_"},
		},
	}

	pf := New(rules)
	content := []byte("No keywords here")

	filtered := pf.Filter(content)

	// No matching keywords, so no rules should be returned
	assert.Empty(t, filtered)
}

func TestPrefilter_MixedRules(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:       "rule1",
			Name:     "AWS Key",
			Pattern:  `AKIA[0-9A-Z]{16}`,
			Keywords: []string{"AKIA", "ASIA"},
		},
		{
			ID:       "rule2",
			Name:     "Generic Secret",
			Pattern:  `secret\d+`,
			Keywords: nil, // Always check
		},
		{
			ID:       "rule3",
			Name:     "GitHub Token",
			Pattern:  `ghp_[A-Za-z0-9]{36}`,
			Keywords: []string{"ghp_"},
		},
	}

	pf := New(rules)
	content := []byte("AKIA test content")

	filtered := pf.Filter(content)

	// Should return rule1 (AKIA matches) and rule2 (no keywords)
	require.Len(t, filtered, 2)
	ids := []string{filtered[0].ID, filtered[1].ID}
	assert.Contains(t, ids, "rule1")
	assert.Contains(t, ids, "rule2")
}

func TestPrefilter_EmptyContent(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:       "rule1",
			Name:     "AWS Key",
			Pattern:  `AKIA[0-9A-Z]{16}`,
			Keywords: []string{"AKIA"},
		},
		{
			ID:       "rule2",
			Name:     "Generic Secret",
			Pattern:  `secret\d+`,
			Keywords: nil,
		},
	}

	pf := New(rules)
	content := []byte("")

	filtered := pf.Filter(content)

	// Empty content should only return rules with no keywords
	require.Len(t, filtered, 1)
	assert.Equal(t, "rule2", filtered[0].ID)
}

func TestPrefilter_MultipleKeywordsPerRule(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:       "rule1",
			Name:     "AWS Keys",
			Pattern:  `(AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}`,
			Keywords: []string{"AKIA", "ASIA", "AIDA", "AROA"},
		},
	}

	pf := New(rules)

	// Test each keyword separately
	for _, keyword := range rules[0].Keywords {
		content := []byte("Test " + keyword + " content")
		filtered := pf.Filter(content)
		require.Len(t, filtered, 1, "Should match keyword: %s", keyword)
		assert.Equal(t, "rule1", filtered[0].ID)
	}
}

func TestPrefilter_CaseInsensitive(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:       "rule1",
			Name:     "AWS Key",
			Pattern:  `AKIA[0-9A-Z]{16}`,
			Keywords: []string{"AKIA"},
		},
	}

	pf := New(rules)

	// Aho-Corasick should be case-sensitive by default
	// Content with lowercase should NOT match
	content := []byte("test akia lowercase")
	filtered := pf.Filter(content)
	assert.Empty(t, filtered, "Lowercase should not match")

	// Uppercase should match
	content = []byte("test AKIA uppercase")
	filtered = pf.Filter(content)
	require.Len(t, filtered, 1)
	assert.Equal(t, "rule1", filtered[0].ID)
}

func TestPrefilter_NoRules(t *testing.T) {
	pf := New([]*types.Rule{})
	content := []byte("test content")

	filtered := pf.Filter(content)
	assert.Empty(t, filtered)
}
