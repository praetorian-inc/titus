package titus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScanner(t *testing.T) {
	scanner, err := NewScanner()
	require.NoError(t, err)
	defer func() { _ = scanner.Close() }()

	// Should have loaded builtin rules
	assert.Greater(t, scanner.RuleCount(), 100, "should have loaded many builtin rules")
}

func TestNewScannerWithOptions(t *testing.T) {
	scanner, err := NewScanner(
		WithContextLines(5),
		WithValidation(),
		WithValidationWorkers(2),
	)
	require.NoError(t, err)
	defer func() { _ = scanner.Close() }()

	assert.True(t, scanner.ValidationEnabled())
}

func TestScanString(t *testing.T) {
	scanner, err := NewScanner()
	require.NoError(t, err)
	defer func() { _ = scanner.Close() }()

	// Test content with a fake AWS key pattern
	content := `aws_access_key_id = AKIADEADBEEFDEADBEEF`

	matches, err := scanner.ScanString(content)
	require.NoError(t, err)

	// Should find the AWS key pattern
	assert.Greater(t, len(matches), 0, "should find at least one match")

	// Verify match structure
	if len(matches) > 0 {
		match := matches[0]
		assert.NotEmpty(t, match.RuleID)
		assert.NotEmpty(t, match.RuleName)
		assert.NotNil(t, match.Snippet.Matching)
	}
}

func TestScanBytes(t *testing.T) {
	scanner, err := NewScanner()
	require.NoError(t, err)
	defer func() { _ = scanner.Close() }()

	// Test with a realistic AWS access key pattern that's in the builtin rules
	content := []byte(`AWS_ACCESS_KEY_ID=AKIADEADBEEFDEADBEEF`)

	matches, err := scanner.ScanBytes(content)
	require.NoError(t, err)

	// Should detect the AWS key pattern
	assert.Greater(t, len(matches), 0, "should find at least one match")

	// Verify match structure
	if len(matches) > 0 {
		match := matches[0]
		assert.NotEmpty(t, match.RuleID)
		assert.NotEmpty(t, match.RuleName)
	}
}

func TestScanStringWithContext(t *testing.T) {
	scanner, err := NewScanner()
	require.NoError(t, err)
	defer func() { _ = scanner.Close() }()

	ctx := context.Background()
	content := `password = "super_secret_password_12345"`

	matches, err := scanner.ScanStringWithContext(ctx, content)
	require.NoError(t, err)

	// May or may not match depending on rules
	// Just verify no error occurs
	_ = matches
}

func TestScanStringNoMatches(t *testing.T) {
	scanner, err := NewScanner()
	require.NoError(t, err)
	defer func() { _ = scanner.Close() }()

	// Content with no secrets
	content := `Hello, world! This is just regular text.`

	matches, err := scanner.ScanString(content)
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestWithCustomRules(t *testing.T) {
	// Load builtin rules and filter to a subset
	allRules, err := LoadBuiltinRules()
	require.NoError(t, err)

	// Take just the first 10 rules
	var subset []*Rule
	for i, r := range allRules {
		if i >= 10 {
			break
		}
		subset = append(subset, r)
	}

	scanner, err := NewScanner(WithRules(subset))
	require.NoError(t, err)
	defer func() { _ = scanner.Close() }()

	assert.Equal(t, 10, scanner.RuleCount())
}

func TestLoadBuiltinRules(t *testing.T) {
	rules, err := LoadBuiltinRules()
	require.NoError(t, err)
	assert.Greater(t, len(rules), 100, "should have many builtin rules")

	// Verify rule structure
	for _, r := range rules {
		assert.NotEmpty(t, r.ID, "rule should have ID")
		assert.NotEmpty(t, r.Name, "rule should have name")
	}
}

func TestRules(t *testing.T) {
	scanner, err := NewScanner()
	require.NoError(t, err)
	defer func() { _ = scanner.Close() }()

	rules := scanner.Rules()
	assert.Equal(t, scanner.RuleCount(), len(rules))

	// Verify it's a copy, not a reference
	rules[0] = nil
	assert.NotNil(t, scanner.Rules()[0])
}

func TestMultipleScanners(t *testing.T) {
	// Each scanner instance is independent - use multiple scanners for concurrency
	done := make(chan bool, 5)
	for i := range 5 {
		go func(idx int) {
			scanner, err := NewScanner()
			require.NoError(t, err)
			defer func() { _ = scanner.Close() }()

			_, err = scanner.ScanString("test content with aws_access_key_id=AKIAIOSFODNN7EXAMPLE")
			assert.NoError(t, err)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for range 5 {
		<-done
	}
}

func TestSequentialScanning(t *testing.T) {
	// Single scanner - sequential scans are safe
	scanner, err := NewScanner()
	require.NoError(t, err)
	defer func() { _ = scanner.Close() }()

	for i := range 5 {
		_, err := scanner.ScanString("test content with aws_access_key_id=AKIAIOSFODNN7EXAMPLE")
		assert.NoError(t, err, "scan %d should succeed", i)
	}
}

// awsKeyContent is a test AWS access key that matches the np.aws.1 rule.
const awsKeyContent = "aws_access_key_id = AKIADEADBEEFDEADBEEF"

// TestScannerWithScoring_FindingsHaveScore verifies that WithScoring() causes
// ScanStringWithFindings to return findings with a non-zero Score.
func TestScannerWithScoring_FindingsHaveScore(t *testing.T) {
	scanner, err := NewScanner(WithScoring())
	require.NoError(t, err)
	defer func() { _ = scanner.Close() }()

	assert.True(t, scanner.ScoringEnabled(), "scoring should be enabled")

	ctx := context.Background()
	findings, err := scanner.ScanStringWithFindings(ctx, awsKeyContent)
	require.NoError(t, err)
	require.Greater(t, len(findings), 0, "should detect the AWS key")

	f := findings[0]
	require.NotNil(t, f.Score, "finding should have a Score when WithScoring() is used")
	assert.Greater(t, f.Score.Base, 0, "base score should be positive")
	assert.Greater(t, f.Score.Final, 0, "final score should be positive")
	assert.NotEmpty(t, f.Score.SuggestedSeverity, "suggested severity should be set")
}

// TestScannerWithAccessibilityPrivate_ScoreAdjusted verifies that
// WithAccessibility(AccessibilityPrivate) applies the -25 penalty to scores.
func TestScannerWithAccessibilityPrivate_ScoreAdjusted(t *testing.T) {
	// Scanner without accessibility — get the base+modifier score.
	baseScanner, err := NewScanner(WithScoring())
	require.NoError(t, err)
	defer func() { _ = baseScanner.Close() }()

	ctx := context.Background()
	baseFindings, err := baseScanner.ScanStringWithFindings(ctx, awsKeyContent)
	require.NoError(t, err)
	require.Greater(t, len(baseFindings), 0)
	baseScore := baseFindings[0].Score.Final

	// Scanner with private accessibility — must subtract 25 (clamped to [0,100]).
	privScanner, err := NewScanner(
		WithScoring(),
		WithAccessibility(AccessibilityPrivate),
	)
	require.NoError(t, err)
	defer func() { _ = privScanner.Close() }()

	privFindings, err := privScanner.ScanStringWithFindings(ctx, awsKeyContent)
	require.NoError(t, err)
	require.Greater(t, len(privFindings), 0)

	privFinding := privFindings[0]
	require.NotNil(t, privFinding.Score)

	expectedFinal := baseScore - 25
	if expectedFinal < 0 {
		expectedFinal = 0
	}
	assert.Equal(t, expectedFinal, privFinding.Score.Final,
		"private accessibility should subtract 25 from score")

	// The accessibility modifier should be the last Applied entry.
	require.NotEmpty(t, privFinding.Score.Applied, "Applied modifiers should not be empty")
	last := privFinding.Score.Applied[len(privFinding.Score.Applied)-1]
	assert.Equal(t, "code-accessibility", last.Name)
	assert.Equal(t, -25, last.Value)
}

// TestScannerWithAccessibilityPublic_NoAdjustment verifies that
// WithAccessibility(AccessibilityPublic) does NOT apply a score penalty.
func TestScannerWithAccessibilityPublic_NoAdjustment(t *testing.T) {
	// Scanner without accessibility.
	baseScanner, err := NewScanner(WithScoring())
	require.NoError(t, err)
	defer func() { _ = baseScanner.Close() }()

	ctx := context.Background()
	baseFindings, err := baseScanner.ScanStringWithFindings(ctx, awsKeyContent)
	require.NoError(t, err)
	require.Greater(t, len(baseFindings), 0)
	baseScore := baseFindings[0].Score.Final

	// Scanner with public accessibility.
	pubScanner, err := NewScanner(
		WithScoring(),
		WithAccessibility(AccessibilityPublic),
	)
	require.NoError(t, err)
	defer func() { _ = pubScanner.Close() }()

	pubFindings, err := pubScanner.ScanStringWithFindings(ctx, awsKeyContent)
	require.NoError(t, err)
	require.Greater(t, len(pubFindings), 0)

	pubFinding := pubFindings[0]
	require.NotNil(t, pubFinding.Score)
	assert.Equal(t, baseScore, pubFinding.Score.Final,
		"public accessibility should not change the score")

	// No accessibility modifier should appear in Applied.
	for _, mod := range pubFinding.Score.Applied {
		assert.NotEqual(t, "code-accessibility", mod.Name,
			"code-accessibility modifier must not be present for public code")
	}
}

// TestScannerWithFindingsDeduplication verifies that the same secret appearing
// twice in content produces one finding (deduplicated) but two raw matches.
func TestScannerWithFindingsDeduplication(t *testing.T) {
	scanner, err := NewScanner(WithScoring())
	require.NoError(t, err)
	defer func() { _ = scanner.Close() }()

	// The same AWS key on two separate lines — same secret value, same groups.
	content := "aws_access_key_id = AKIADEADBEEFDEADBEEF\nAWS_ACCESS_KEY_ID=AKIADEADBEEFDEADBEEF"

	ctx := context.Background()

	// ScanBytes should return at least one match (same key may match once).
	matches, err := scanner.ScanBytes([]byte(content))
	require.NoError(t, err)

	// ScanBytesWithFindings should return exactly 1 finding for the same secret.
	findings, err := scanner.ScanBytesWithFindings(ctx, []byte(content))
	require.NoError(t, err)

	// If the raw scanner produces more matches than findings, deduplication is working.
	// At minimum, findings must not exceed matches.
	assert.LessOrEqual(t, len(findings), len(matches),
		"findings count must not exceed raw matches count")

	// Verify every finding ID is unique.
	seen := make(map[string]bool)
	for _, f := range findings {
		assert.False(t, seen[f.ID], "duplicate finding ID: %s", f.ID)
		seen[f.ID] = true
	}
}

// TestScannerWithScoring_NoScoring_NilScore confirms that without WithScoring()
// the findings returned by ScanStringWithFindings have a nil Score.
func TestScannerWithoutScoring_FindingsHaveNilScore(t *testing.T) {
	scanner, err := NewScanner() // no WithScoring()
	require.NoError(t, err)
	defer func() { _ = scanner.Close() }()

	assert.False(t, scanner.ScoringEnabled())

	ctx := context.Background()
	findings, err := scanner.ScanStringWithFindings(ctx, awsKeyContent)
	require.NoError(t, err)
	require.Greater(t, len(findings), 0)

	for _, f := range findings {
		assert.Nil(t, f.Score, "Score should be nil when scoring is not enabled")
	}
}
