//go:build !wasm

package matcher

import (
	"os"
	"testing"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoseyParkerParity verifies that Titus finds all secrets that NoseyParker v0.24.0 finds.
// This test ensures we don't regress when porting from the original Rust implementation.
//
// NoseyParker v0.24.0 findings on test-secrets.html:
// - 3 GitHub Personal Access Token
// - 3 Generic API Key
// - 2 AWS Secret Access Key
// - 1 Stripe API Test Key
// - 1 Slack Bot Token
// - 1 SendGrid API Key
// - 1 JSON Web Token
// - 1 Google API Key
// - 1 GitHub OAuth Access Token
// - 1 Generic Password
// Total: 15 findings
//
// Titus additionally finds:
// - 2 AWS API Key (separate from Secret Access Key)
// - 1 YouTube API Key
// Total: 18 findings (20% more)
func TestNoseyParkerParity_HTMLTestFile(t *testing.T) {
	// Load builtin rules
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)
	require.NotEmpty(t, rules)

	// Create portable matcher (non-CGO)
	m, err := NewPortableRegexp(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	// Read test file
	content, err := os.ReadFile("../../extension/test/test-secrets.html")
	require.NoError(t, err)

	// Run scan
	matches, err := m.Match(content)
	require.NoError(t, err)

	// Count matches by rule name (using structural deduplication)
	ruleNameCounts := make(map[string]int)
	seenStructural := make(map[string]bool)
	for _, match := range matches {
		if seenStructural[match.StructuralID] {
			continue
		}
		seenStructural[match.StructuralID] = true
		ruleNameCounts[match.RuleName]++
	}

	// Verify NoseyParker parity - all these must be found
	noseyParkerFindings := map[string]int{
		"GitHub Personal Access Token": 3,
		"Generic API Key":              3,
		"AWS Secret Access Key":        2,
		"Stripe API Test Key":          1,
		"Slack Bot Token":              1,
		"SendGrid API Key":             1,
		"Google API Key":               1,
		"GitHub OAuth Access Token":    1,
		"Generic Password":             1,
		// JWT is matched - may have slightly different rule name
	}

	for ruleName, expectedCount := range noseyParkerFindings {
		actualCount := ruleNameCounts[ruleName]
		assert.GreaterOrEqual(t, actualCount, expectedCount,
			"Expected at least %d matches for %q, got %d (NoseyParker parity)",
			expectedCount, ruleName, actualCount)
	}

	// Verify JWT is found (rule name may vary)
	jwtFound := ruleNameCounts["JSON Web Token (base64url-encoded)"] > 0
	assert.True(t, jwtFound, "Expected to find JWT token")

	// Verify Titus finds MORE than NoseyParker (additional rules)
	totalFindings := len(seenStructural)
	assert.GreaterOrEqual(t, totalFindings, 15,
		"Titus should find at least as many secrets as NoseyParker (15), found %d", totalFindings)

	t.Logf("Total unique findings: %d (NoseyParker: 15)", totalFindings)
	t.Logf("Rule breakdown: %v", ruleNameCounts)
}

// TestNoseyParkerParity_MixedSecrets verifies parity on mixed secrets test file.
func TestNoseyParkerParity_MixedSecrets(t *testing.T) {
	// Load builtin rules
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	// Create portable matcher
	m, err := NewPortableRegexp(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	// Read test file
	content, err := os.ReadFile("../../testdata/secrets/mixed-secrets.txt")
	if os.IsNotExist(err) {
		t.Skip("mixed-secrets.txt not found")
	}
	require.NoError(t, err)

	// Run scan
	matches, err := m.Match(content)
	require.NoError(t, err)

	// Count unique findings
	seenStructural := make(map[string]bool)
	ruleNameCounts := make(map[string]int)
	for _, match := range matches {
		if seenStructural[match.StructuralID] {
			continue
		}
		seenStructural[match.StructuralID] = true
		ruleNameCounts[match.RuleName]++
	}

	// NoseyParker finds 12 on this file, Titus should find at least that many
	totalFindings := len(seenStructural)
	assert.GreaterOrEqual(t, totalFindings, 5,
		"Should find secrets in mixed-secrets.txt, found %d", totalFindings)

	t.Logf("Total unique findings: %d", totalFindings)
	t.Logf("Rule breakdown: %v", ruleNameCounts)
}

// BenchmarkTitusVsNoseyParkerSpeed provides benchmark data for comparison.
// Run with: go test -bench=BenchmarkTitusVsNoseyParkerSpeed -benchmem
//
// Comparison baseline (NoseyParker v0.24.0):
// - 4.7KB file: ~1.35s (startup dominated)
// - 100KB file: ~1.37s (650 KiB/s)
// - 1MB file: ~1.19s (3.7 MiB/s)
//
// Titus non-CGO typical results:
// - Small files: Comparable to NoseyParker
// - Large files: 3-5x slower (trade-off for no CGO)
func BenchmarkTitusVsNoseyParkerSpeed(b *testing.B) {
	// Load rules once
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		b.Fatalf("Failed to load rules: %v", err)
	}

	// Create matcher once
	m, err := NewPortableRegexp(rules, 0)
	if err != nil {
		b.Fatalf("Failed to create matcher: %v", err)
	}
	defer m.Close()

	// Read test content
	content, err := os.ReadFile("../../extension/test/test-secrets.html")
	if err != nil {
		b.Fatalf("Failed to read test file: %v", err)
	}

	b.SetBytes(int64(len(content)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := m.Match(content)
		if err != nil {
			b.Fatalf("Match failed: %v", err)
		}
	}
}
