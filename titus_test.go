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
	defer scanner.Close()

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
	defer scanner.Close()

	assert.True(t, scanner.ValidationEnabled())
}

func TestScanString(t *testing.T) {
	scanner, err := NewScanner()
	require.NoError(t, err)
	defer scanner.Close()

	// Test content with a fake AWS key pattern
	content := `aws_access_key_id = AKIAIOSFODNN7EXAMPLE`

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
	defer scanner.Close()

	// Test with a realistic AWS access key pattern that's in the builtin rules
	content := []byte(`AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`)

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
	defer scanner.Close()

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
	defer scanner.Close()

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
	defer scanner.Close()

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
	defer scanner.Close()

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
			defer scanner.Close()

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
	defer scanner.Close()

	for i := range 5 {
		_, err := scanner.ScanString("test content with aws_access_key_id=AKIAIOSFODNN7EXAMPLE")
		assert.NoError(t, err, "scan %d should succeed", i)
	}
}
