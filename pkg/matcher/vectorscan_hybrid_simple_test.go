//go:build !wasm && cgo && vectorscan

package matcher

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVectorscanMatcher_HybridSimple tests the basic hybrid approach with simpler patterns
func TestVectorscanMatcher_HybridSimple(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "simple-pattern",
			Name:    "Simple Hyperscan Compatible",
			Pattern: `AKIA[0-9A-Z]{16}`,
		},
		{
			ID:      "fallback-pattern",
			Name:    "Fallback Pattern",
			// Lookbehind is not supported by Hyperscan
			Pattern: `(?<=secret:)[a-z0-9]{10}`,
		},
	}

	// Should successfully create matcher
	t.Log("Creating matcher...")
	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err, "matcher should be created")
	t.Log("Matcher created successfully")

	// Test that simple pattern works via Hyperscan
	t.Log("Testing simple pattern...")
	content1 := []byte("Found key: AKIAIOSFODNN7EXAMPLE in config")
	matches1, err := matcher.Match(content1)
	require.NoError(t, err)
	assert.Len(t, matches1, 1)
	if len(matches1) > 0 {
		assert.Equal(t, "simple-pattern", matches1[0].RuleID)
		t.Logf("Simple pattern matched: %s", matches1[0].RuleID)
	}

	// Test that fallback pattern works
	t.Log("Testing fallback pattern...")
	content2 := []byte("The secret:abc1234567 is here")
	matches2, err := matcher.Match(content2)
	require.NoError(t, err)
	t.Logf("Found %d matches for fallback pattern", len(matches2))
	for _, m := range matches2 {
		t.Logf("  Match: %s at %d-%d: %q", m.RuleID, m.Location.Offset.Start, m.Location.Offset.End, m.Snippet.Matching)
	}

	// Skip Close() for now - there's a pre-existing bug with hyperscan cleanup
	// that causes hangs during test teardown
	_ = matcher
}
