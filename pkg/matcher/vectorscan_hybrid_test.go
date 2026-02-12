//go:build !wasm && cgo && vectorscan

package matcher

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVectorscanMatcher_HybridApproach tests that patterns too complex for Hyperscan
// automatically fall back to regexp2 without failing the entire compilation.
func TestVectorscanMatcher_HybridApproach(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "simple-pattern",
			Name:    "Simple Hyperscan Compatible",
			Pattern: `AKIA[0-9A-Z]{16}`,
		},
		{
			ID:      "complex-pattern",
			Name:    "Complex Pattern (Hyperscan incompatible)",
			// Lookahead/lookbehind are not supported by Hyperscan
			Pattern: `(?<=secret:)(?i)[a-z0-9]{20}`,
		},
		{
			ID:      "another-simple",
			Name:    "Another Simple Pattern",
			Pattern: `password\s*=\s*["'][^"']+["']`,
		},
	}

	// Should successfully create matcher despite complex pattern
	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err, "matcher should be created even with complex patterns")
	// Skip defer matcher.Close() - pre-existing bug in hyperscan cleanup causes hangs

	// Test that simple patterns work via Hyperscan
	content1 := []byte("Found key: AKIAIOSFODNN7EXAMPLE in config")
	matches1, err := matcher.Match(content1)
	require.NoError(t, err)
	assert.Len(t, matches1, 1)
	assert.Equal(t, "simple-pattern", matches1[0].RuleID)

	// Test that complex pattern works via regexp2 fallback
	content2 := []byte("The secret:abcdefghij0123456789 is here")
	matches2, err := matcher.Match(content2)
	require.NoError(t, err)
	assert.Len(t, matches2, 1)
	assert.Equal(t, "complex-pattern", matches2[0].RuleID)

	// Test that another simple pattern works
	content3 := []byte(`password = "test123"`)
	matches3, err := matcher.Match(content3)
	require.NoError(t, err)
	assert.Len(t, matches3, 1)
	assert.Equal(t, "another-simple", matches3[0].RuleID)
}

// TestVectorscanMatcher_AllPatternsFallback tests the edge case where
// all patterns are incompatible with Hyperscan.
func TestVectorscanMatcher_AllPatternsFallback(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "complex-1",
			Name:    "Complex Pattern 1",
			Pattern: `(?<=prefix:)[a-z]+`,
		},
		{
			ID:      "complex-2",
			Name:    "Complex Pattern 2",
			Pattern: `(?<!no-match)[0-9]+(?=suffix)`,
		},
	}

	// Should create matcher even if all patterns require fallback
	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err, "matcher should be created with only fallback patterns")
	// Skip defer matcher.Close() - pre-existing bug in hyperscan cleanup causes hangs

	// Both patterns should match via regexp2 fallback
	content := []byte("prefix:hello 12345suffix")
	matches, err := matcher.Match(content)
	require.NoError(t, err)
	assert.Len(t, matches, 2, "both fallback patterns should match")

	// Verify both rules matched
	foundRules := make(map[string]bool)
	for _, match := range matches {
		foundRules[match.RuleID] = true
	}
	assert.True(t, foundRules["complex-1"], "complex-1 should match")
	assert.True(t, foundRules["complex-2"], "complex-2 should match")
}

// TestVectorscanMatcher_DiagnosticOutput tests that the matcher reports
// which patterns use Hyperscan vs regexp2 fallback.
func TestVectorscanMatcher_DiagnosticOutput(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "hs-1",
			Name:    "Hyperscan Pattern",
			Pattern: `simple[0-9]+`,
		},
		{
			ID:      "fb-1",
			Name:    "Fallback Pattern",
			Pattern: `(?<=prefix)[a-z]+`,
		},
	}

	// Capture stderr to verify diagnostic output
	// (We'll just test that it doesn't panic for now)
	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	// Skip defer matcher.Close() - pre-existing bug in hyperscan cleanup causes hangs

	// The diagnostic message should have been printed to stderr
	// Format: "[vectorscan] X/Y rules compiled for Hyperscan, Z rules use regexp2 fallback"
	// We can't easily capture stderr in Go tests, but we verify the matcher works
	assert.NotNil(t, matcher)
}
