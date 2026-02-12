//go:build !wasm

package matcher

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPortableRegexpMatcher_Prefilter_WithKeywords(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "AWS Key",
			Pattern:      `AKIA[0-9A-Z]{16}`,
			StructuralID: computeRuleStructuralID(`AKIA[0-9A-Z]{16}`),
			Keywords:     []string{"AKIA"},
		},
		{
			ID:           "test.2",
			Name:         "GitHub Token",
			Pattern:      `ghp_[A-Za-z0-9]{36}`,
			StructuralID: computeRuleStructuralID(`ghp_[A-Za-z0-9]{36}`),
			Keywords:     []string{"ghp_"},
		},
	}

	m, err := NewPortableRegexp(rules, 0)
	require.NoError(t, err)

	// Content with AKIA should only match rule1
	content := []byte("AKIAIOSFODNN7EXAMPLE")
	matches, err := m.Match(content)

	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, "test.1", matches[0].RuleID)
}

func TestPortableRegexpMatcher_Prefilter_NoKeywordsAlwaysRun(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "AWS Key",
			Pattern:      `AKIA[0-9A-Z]{16}`,
			StructuralID: computeRuleStructuralID(`AKIA[0-9A-Z]{16}`),
			Keywords:     []string{"AKIA"},
		},
		{
			ID:           "test.2",
			Name:         "Generic Secret",
			Pattern:      `secret\d+`,
			StructuralID: computeRuleStructuralID(`secret\d+`),
			Keywords:     nil, // No keywords = always run
		},
	}

	m, err := NewPortableRegexp(rules, 0)
	require.NoError(t, err)

	// Content without keywords should only match rule without keywords
	content := []byte("secret123")
	matches, err := m.Match(content)

	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, "test.2", matches[0].RuleID)
}

func TestPortableRegexpMatcher_Prefilter_NoMatchingKeywords(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "AWS Key",
			Pattern:      `AKIA[0-9A-Z]{16}`,
			StructuralID: computeRuleStructuralID(`AKIA[0-9A-Z]{16}`),
			Keywords:     []string{"AKIA"},
		},
		{
			ID:           "test.2",
			Name:         "GitHub Token",
			Pattern:      `ghp_[A-Za-z0-9]{36}`,
			StructuralID: computeRuleStructuralID(`ghp_[A-Za-z0-9]{36}`),
			Keywords:     []string{"ghp_"},
		},
	}

	m, err := NewPortableRegexp(rules, 0)
	require.NoError(t, err)

	// Content without any keywords should find no matches
	content := []byte("No keywords here")
	matches, err := m.Match(content)

	require.NoError(t, err)
	assert.Empty(t, matches)
}

// computeRuleStructuralID is a test helper to compute StructuralID for a rule pattern.
func computeRuleStructuralID(pattern string) string {
	r := &types.Rule{Pattern: pattern}
	return r.ComputeStructuralID()
}
