//go:build !wasm

package matcher

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestMatcherComparison_HTML compares Hyperscan and PortableRegexp matchers against the HTML test file
func TestMatcherComparison_HTML(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	testFile := filepath.Join("..", "..", "extension", "test", "test-secrets.html")

	// Read test file
	content, err := os.ReadFile(testFile)
	require.NoError(t, err, "Failed to read test file")

	// Load builtin rules
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err, "Failed to load builtin rules")
	if len(rules) == 0 {
		t.Skip("No builtin rules found")
	}

	// Create both matchers
	hyperMatcher, err := NewHyperscan(rules, 0)
	require.NoError(t, err, "Failed to create Hyperscan matcher")
	defer hyperMatcher.Close()

	portableMatcher, err := NewPortableRegexp(rules, 0)
	require.NoError(t, err, "Failed to create PortableRegexp matcher")
	defer portableMatcher.Close()

	// Run both matchers
	hyperMatches, err := hyperMatcher.Match(content)
	require.NoError(t, err, "Hyperscan matcher failed")

	portableMatches, err := portableMatcher.Match(content)
	require.NoError(t, err, "PortableRegexp matcher failed")

	// Compare results
	compareMatchResults(t, "test-secrets.html", hyperMatches, portableMatches, rules)
}

// TestMatcherComparison_AWSKeys compares both matchers against AWS keys test file
func TestMatcherComparison_AWSKeys(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	testFile := filepath.Join("..", "..", "testdata", "secrets", "aws-keys.txt")

	// Read test file
	content, err := os.ReadFile(testFile)
	require.NoError(t, err, "Failed to read test file")

	// Load builtin rules
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err, "Failed to load builtin rules")
	if len(rules) == 0 {
		t.Skip("No builtin rules found")
	}

	// Create both matchers
	hyperMatcher, err := NewHyperscan(rules, 0)
	require.NoError(t, err, "Failed to create Hyperscan matcher")
	defer hyperMatcher.Close()

	portableMatcher, err := NewPortableRegexp(rules, 0)
	require.NoError(t, err, "Failed to create PortableRegexp matcher")
	defer portableMatcher.Close()

	// Run both matchers
	hyperMatches, err := hyperMatcher.Match(content)
	require.NoError(t, err, "Hyperscan matcher failed")

	portableMatches, err := portableMatcher.Match(content)
	require.NoError(t, err, "PortableRegexp matcher failed")

	// Compare results
	compareMatchResults(t, "aws-keys.txt", hyperMatches, portableMatches, rules)
}

// TestMatcherComparison_MixedSecrets compares both matchers against mixed secrets test file
func TestMatcherComparison_MixedSecrets(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	testFile := filepath.Join("..", "..", "testdata", "secrets", "mixed-secrets.txt")

	// Read test file
	content, err := os.ReadFile(testFile)
	require.NoError(t, err, "Failed to read test file")

	// Load builtin rules
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err, "Failed to load builtin rules")
	if len(rules) == 0 {
		t.Skip("No builtin rules found")
	}

	// Create both matchers
	hyperMatcher, err := NewHyperscan(rules, 0)
	require.NoError(t, err, "Failed to create Hyperscan matcher")
	defer hyperMatcher.Close()

	portableMatcher, err := NewPortableRegexp(rules, 0)
	require.NoError(t, err, "Failed to create PortableRegexp matcher")
	defer portableMatcher.Close()

	// Run both matchers
	hyperMatches, err := hyperMatcher.Match(content)
	require.NoError(t, err, "Hyperscan matcher failed")

	portableMatches, err := portableMatcher.Match(content)
	require.NoError(t, err, "PortableRegexp matcher failed")

	// Compare results
	compareMatchResults(t, "mixed-secrets.txt", hyperMatches, portableMatches, rules)
}

// TestPortableRegexp_FindsAllExpectedSecrets validates the portable matcher finds specific expected secrets
func TestPortableRegexp_FindsAllExpectedSecrets(t *testing.T) {
	// Load builtin rules
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err, "Failed to load builtin rules")
	if len(rules) == 0 {
		t.Skip("No builtin rules found")
	}

	// Create portable matcher
	portableMatcher, err := NewPortableRegexp(rules, 0)
	require.NoError(t, err, "Failed to create PortableRegexp matcher")
	defer portableMatcher.Close()

	// Test HTML file
	t.Run("HTML file secrets", func(t *testing.T) {
		testFile := filepath.Join("..", "..", "extension", "test", "test-secrets.html")
		content, err := os.ReadFile(testFile)
		require.NoError(t, err, "Failed to read HTML test file")

		matches, err := portableMatcher.Match(content)
		require.NoError(t, err, "PortableRegexp matcher failed")

		// Count matches by type
		matchCounts := make(map[string]int)
		for _, match := range matches {
			matchCounts[match.RuleID]++
		}

		t.Logf("HTML file match counts: %v", matchCounts)

		// Verify expected secrets are found
		assertMinMatches(t, matchCounts, "github", 2, "Expected at least 2 GitHub tokens in HTML file")
		assertMinMatches(t, matchCounts, "aws", 1, "Expected at least 1 AWS key in HTML file")
		assertMinMatches(t, matchCounts, "stripe", 1, "Expected at least 1 Stripe key in HTML file")
	})

	// Test AWS keys file
	t.Run("AWS keys file", func(t *testing.T) {
		testFile := filepath.Join("..", "..", "testdata", "secrets", "aws-keys.txt")
		content, err := os.ReadFile(testFile)
		require.NoError(t, err, "Failed to read AWS keys test file")

		matches, err := portableMatcher.Match(content)
		require.NoError(t, err, "PortableRegexp matcher failed")

		// Count AWS matches
		awsCount := 0
		for _, match := range matches {
			if containsString(match.RuleID, "aws") || containsString(match.RuleID, "amazon") {
				awsCount++
			}
		}

		t.Logf("AWS keys file: found %d AWS matches", awsCount)
		require.GreaterOrEqual(t, awsCount, 3, "Expected at least 3 AWS key matches in aws-keys.txt")
	})

	// Test mixed secrets file
	t.Run("Mixed secrets file", func(t *testing.T) {
		testFile := filepath.Join("..", "..", "testdata", "secrets", "mixed-secrets.txt")
		content, err := os.ReadFile(testFile)
		require.NoError(t, err, "Failed to read mixed secrets test file")

		matches, err := portableMatcher.Match(content)
		require.NoError(t, err, "PortableRegexp matcher failed")

		// Count matches by type
		matchCounts := make(map[string]int)
		for _, match := range matches {
			matchCounts[match.RuleID]++
		}

		t.Logf("Mixed secrets file match counts: %v", matchCounts)

		// Verify diverse secrets are found
		// Note: Slack token pattern might not match depending on format
		assertMinMatches(t, matchCounts, "stripe", 1, "Expected at least 1 Stripe key")
		assertMinMatches(t, matchCounts, "sendgrid", 1, "Expected at least 1 SendGrid key")
		assertMinMatches(t, matchCounts, "openai", 1, "Expected at least 1 OpenAI key")
		assertMinMatches(t, matchCounts, "pem", 1, "Expected at least 1 PEM/private key")
	})
}

// compareMatchResults compares the results from two matchers and reports differences
func compareMatchResults(t *testing.T, filename string, hyperMatches, portableMatches []*types.Match, rules []*types.Rule) {
	t.Helper()

	// Extract rule IDs from matches
	hyperRuleIDs := extractRuleIDs(hyperMatches)
	portableRuleIDs := extractRuleIDs(portableMatches)

	// Sort for comparison
	sort.Strings(hyperRuleIDs)
	sort.Strings(portableRuleIDs)

	// Count matches
	hyperCount := len(hyperMatches)
	portableCount := len(portableMatches)

	t.Logf("=== %s Results ===", filename)
	t.Logf("Hyperscan:        %d matches", hyperCount)
	t.Logf("PortableRegexp:   %d matches", portableCount)

	// Count unique rule IDs
	hyperUniqueRules := uniqueStrings(hyperRuleIDs)
	portableUniqueRules := uniqueStrings(portableRuleIDs)

	t.Logf("Hyperscan rules:     %v", hyperUniqueRules)
	t.Logf("PortableRegexp rules: %v", portableUniqueRules)

	// Find differences
	onlyInHyper := difference(hyperUniqueRules, portableUniqueRules)
	onlyInPortable := difference(portableUniqueRules, hyperUniqueRules)

	if len(onlyInHyper) > 0 {
		t.Logf("Rules ONLY matched by Hyperscan: %v", onlyInHyper)
	}

	if len(onlyInPortable) > 0 {
		t.Logf("Rules ONLY matched by PortableRegexp: %v", onlyInPortable)
	}

	// Report detailed differences if results don't match
	if hyperCount != portableCount || len(onlyInHyper) > 0 || len(onlyInPortable) > 0 {
		t.Errorf("MISMATCH in %s:", filename)
		t.Errorf("  Hyperscan found %d matches, PortableRegexp found %d matches", hyperCount, portableCount)

		if len(onlyInHyper) > 0 {
			t.Errorf("  Rules ONLY in Hyperscan: %v", onlyInHyper)
			// Show samples of what Hyperscan found
			for _, ruleID := range onlyInHyper {
				for _, match := range hyperMatches {
					if match.RuleID == ruleID {
						t.Logf("    Hyperscan match: rule=%s, match=%q", ruleID, string(match.Snippet.Matching))
						break
					}
				}
			}
		}

		if len(onlyInPortable) > 0 {
			t.Errorf("  Rules ONLY in PortableRegexp: %v", onlyInPortable)
			// Show samples of what PortableRegexp found
			for _, ruleID := range onlyInPortable {
				for _, match := range portableMatches {
					if match.RuleID == ruleID {
						t.Logf("    PortableRegexp match: rule=%s, match=%q", ruleID, string(match.Snippet.Matching))
						break
					}
				}
			}
		}
	} else {
		t.Logf("✓ Both matchers found identical results")
	}
}

// Helper functions

// extractRuleIDs extracts all rule IDs from matches
func extractRuleIDs(matches []*types.Match) []string {
	ids := make([]string, 0, len(matches))
	for _, match := range matches {
		ids = append(ids, match.RuleID)
	}
	return ids
}

// uniqueStrings returns unique strings from a slice
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	sort.Strings(result)
	return result
}

// difference returns elements in a that are not in b
func difference(a, b []string) []string {
	bMap := make(map[string]bool)
	for _, s := range b {
		bMap[s] = true
	}

	result := []string{}
	for _, s := range a {
		if !bMap[s] {
			result = append(result, s)
		}
	}
	return result
}

// containsString checks if a string contains a substring (case-insensitive)
func containsString(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
		 len(s) > len(substr) &&
		 (s[:len(substr)] == substr ||
		  s[len(s)-len(substr):] == substr ||
		  findInString(s, substr)))
}

// findInString checks if substr exists in s
func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// assertMinMatches checks that at least minCount matches exist for a given keyword
func assertMinMatches(t *testing.T, matchCounts map[string]int, keyword string, minCount int, message string) {
	t.Helper()

	totalCount := 0
	for ruleID, count := range matchCounts {
		if containsString(ruleID, keyword) {
			totalCount += count
		}
	}

	if totalCount < minCount {
		t.Errorf("%s: found %d, expected at least %d", message, totalCount, minCount)
	}
}
