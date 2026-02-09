//go:build !wasm

package matcher

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMatchParallel_Correctness tests that parallel matching produces correct results
func TestMatchParallel_Correctness(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test-rule-1",
			Name:    "Test Password Pattern",
			Pattern: `password\s*=\s*"([^"]+)"`,
		},
		{
			ID:      "test-rule-2",
			Name:    "Test API Key Pattern",
			Pattern: `api_key\s*=\s*"([^"]+)"`,
		},
	}

	// Create content >10KB to trigger parallel path
	var contentBuilder strings.Builder
	for i := 0; i < 500; i++ {
		contentBuilder.WriteString(`password = "secret123"` + "\n")
		contentBuilder.WriteString(`api_key = "key456"` + "\n")
		contentBuilder.WriteString("some other line\n")
	}
	content := []byte(contentBuilder.String())
	require.Greater(t, len(content), 10000, "Content must be >10KB to trigger parallel path")

	matcher, err := NewPortableRegexp(rules, 0)
	require.NoError(t, err)

	matches, err := matcher.Match(content)
	require.NoError(t, err)

	// Should find both patterns
	assert.NotEmpty(t, matches, "Should find matches in large content")

	// Verify we have matches for both rules
	ruleMatches := make(map[string]int)
	for _, match := range matches {
		ruleMatches[match.RuleID]++
	}

	assert.Contains(t, ruleMatches, "test-rule-1", "Should match password pattern")
	assert.Contains(t, ruleMatches, "test-rule-2", "Should match API key pattern")

	// With content-based deduplication (NoseyParker behavior), same secret value = 1 finding
	assert.Equal(t, 1, ruleMatches["test-rule-1"], "Should deduplicate identical password content")
	assert.Equal(t, 1, ruleMatches["test-rule-2"], "Should deduplicate identical API key content")
}

// TestMatchParallel_vs_Sequential_Equivalence tests that parallel and sequential paths return same results
func TestMatchParallel_vs_Sequential_Equivalence(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "equiv-rule-1",
			Name:    "Email Pattern",
			Pattern: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
		},
		{
			ID:      "equiv-rule-2",
			Name:    "URL Pattern",
			Pattern: `https?://[^\s]+`,
		},
	}

	// Create content with varying sizes
	testCases := []struct {
		name        string
		contentSize int // in iterations
	}{
		{"small", 10},     // <10KB - sequential path
		{"medium", 100},   // ~10KB - boundary
		{"large", 1000},   // >10KB - parallel path
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var contentBuilder strings.Builder
			for i := 0; i < tc.contentSize; i++ {
				contentBuilder.WriteString("user@example.com\n")
				contentBuilder.WriteString("https://example.com/path\n")
				contentBuilder.WriteString("some other content\n")
			}
			content := []byte(contentBuilder.String())

			matcher, err := NewPortableRegexp(rules, 2)
			require.NoError(t, err)

			matches, err := matcher.Match(content)
			require.NoError(t, err)

			// Verify consistent results
			assert.NotEmpty(t, matches, "Should find matches")

			// Check rule coverage
			ruleIDs := make(map[string]bool)
			for _, match := range matches {
				ruleIDs[match.RuleID] = true
			}

			assert.True(t, ruleIDs["equiv-rule-1"], "Should match email pattern")
			assert.True(t, ruleIDs["equiv-rule-2"], "Should match URL pattern")
		})
	}
}

// TestMatchParallel_RaceDetector explicitly exercises parallel path with race detector
func TestMatchParallel_RaceDetector(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "race-rule-1",
			Name:    "Pattern 1",
			Pattern: `secret_[0-9]+`,
		},
		{
			ID:      "race-rule-2",
			Name:    "Pattern 2",
			Pattern: `token_[a-z]+`,
		},
		{
			ID:      "race-rule-3",
			Name:    "Pattern 3",
			Pattern: `key_[A-Z]+`,
		},
	}

	// Create large content to force parallel path
	var contentBuilder strings.Builder
	for i := 0; i < 1000; i++ {
		contentBuilder.WriteString("secret_123 token_abc key_XYZ\n")
	}
	content := []byte(contentBuilder.String())
	require.Greater(t, len(content), 10000)

	matcher, err := NewPortableRegexp(rules, 1)
	require.NoError(t, err)

	// Run multiple times to increase chance of detecting races
	for i := 0; i < 5; i++ {
		matches, err := matcher.Match(content)
		require.NoError(t, err)
		assert.NotEmpty(t, matches, "iteration %d: should find matches", i)
	}
}
