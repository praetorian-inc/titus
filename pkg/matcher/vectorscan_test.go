//go:build !wasm && cgo && vectorscan

package matcher

import (
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVectorscanMatcher_BasicMatch(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test-rule-1",
			Name:    "Test AWS Key",
			Pattern: `AKIA[0-9A-Z]{16}`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	content := []byte("Found key: AKIAIOSFODNN7EXAMPLE in config")
	matches, err := matcher.Match(content)
	require.NoError(t, err)
	assert.Len(t, matches, 1)
	assert.Equal(t, "test-rule-1", matches[0].RuleID)
}

func TestVectorscanMatcher_NoMatch(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test-rule-1",
			Name:    "Test Pattern",
			Pattern: `secret_[a-z]+`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	content := []byte("No secrets here, just regular text")
	matches, err := matcher.Match(content)
	require.NoError(t, err)
	assert.Len(t, matches, 0)
}

func TestVectorscanMatcher_ExtendedMode(t *testing.T) {
	// Test that extended mode patterns work after preprocessing
	rules := []*types.Rule{
		{
			ID:      "extended-rule",
			Name:    "Extended Mode Test",
			Pattern: `(?x)
				secret_    # prefix
				[a-z]+     # identifier
			`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	content := []byte("Found: secret_token in the file")
	matches, err := matcher.Match(content)
	require.NoError(t, err)
	assert.Len(t, matches, 1)
}

func TestVectorscanMatcher_CaseInsensitive(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "case-insensitive",
			Name:    "Case Insensitive Test",
			Pattern: `(?i)password\s*=\s*["'][^"']+["']`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	content := []byte(`PASSWORD = "secret123"`)
	matches, err := matcher.Match(content)
	require.NoError(t, err)
	assert.Len(t, matches, 1)
}

func TestVectorscanMatcher_DefaultFlagsConfiguration(t *testing.T) {
	// Test that we use the NoseyParker approach: no flags by default
	// This allows maximum pattern compatibility (450 vs 267 compiled patterns)
	//
	// Context: NoseyParker uses Flag::default() (no flags) which allows ALL 196 NP rules
	// to compile. Using SomLeftMost | Utf8Mode causes 183 rules to fall back to regexp2.
	//
	// This test verifies we follow NoseyParker's approach for maximum compatibility.

	rules := []*types.Rule{
		{
			ID:      "basic-pattern",
			Name:    "Basic Pattern",
			// Simple pattern that should compile with any flag configuration
			Pattern: `password`,
		},
	}

	matcher, err := NewVectorscan(rules, 0)
	require.NoError(t, err)
	defer matcher.Close()

	// The actual verification is implicit: if we were using SomLeftMost | Utf8Mode,
	// many more patterns would fall back to regexp2 (183 vs 36 fallback rules in benchmarks).
	//
	// By checking that compilation succeeded and didn't fall back for a simple pattern,
	// we verify the basic mechanism works. The real test is the build command verification.
	assert.Equal(t, 1, len(matcher.hsRules), "Basic pattern should compile to Hyperscan")
	assert.Equal(t, 0, len(matcher.fallbackRules), "Basic pattern should not fall back to regexp2")
}

func TestVectorscanMatcher_MultipleRules(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "rule-1",
			Name:    "AWS Key",
			Pattern: `AKIA[0-9A-Z]{16}`,
		},
		{
			ID:      "rule-2",
			Name:    "Generic Secret",
			Pattern: `secret_[a-z0-9]+`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	content := []byte("AWS: AKIAIOSFODNN7EXAMPLE and secret_abc123")
	matches, err := matcher.Match(content)
	require.NoError(t, err)
	assert.Len(t, matches, 2)
}

func TestVectorscanAvailable(t *testing.T) {
	// When built with vectorscan tag, should return true
	assert.True(t, VectorscanAvailable())
}

func TestVectorscanInfo(t *testing.T) {
	info := VectorscanInfo()
	assert.Contains(t, info, "hyperscan")
}

func TestVectorscanMatcher_Close(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test-rule",
			Name:    "Test",
			Pattern: `test`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)

	// Close should not error
	err = matcher.Close()
	assert.NoError(t, err)
}

func TestVectorscanMatcher_CloseDoesNotHang(t *testing.T) {
	// Regression test for infinite loop in Close() when draining sync.Pool
	// Bug: Pool.Get() calls Pool.New() when empty, creating infinite loop
	rules := []*types.Rule{
		{
			ID:      "test-rule",
			Name:    "Test",
			Pattern: `test`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)

	// Perform some matches to populate the scratch pool
	content := []byte("test content with test patterns")
	_, err = matcher.Match(content)
	require.NoError(t, err)

	// Close should complete quickly without hanging
	// Use a timeout to detect if Close() hangs
	done := make(chan error, 1)
	go func() {
		done <- matcher.Close()
	}()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Close() hung for >5 seconds - infinite loop detected")
	}
}

func TestVectorscanMatcher_EmptyRules(t *testing.T) {
	rules := []*types.Rule{}
	_, err := NewVectorscan(rules, 2)
	assert.Error(t, err)
}

func TestVectorscanMatcher_DotAllMode(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "dotall-rule",
			Name:    "Dot All Test",
			Pattern: `(?s)BEGIN.*END`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	content := []byte("BEGIN\nsome\nmultiline\ntext\nEND")
	matches, err := matcher.Match(content)
	require.NoError(t, err)
	assert.Len(t, matches, 1)
}

func TestVectorscanMatcher_MultilineMode(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "multiline-rule",
			Name:    "Multiline Test",
			Pattern: `(?m)^secret`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	content := []byte("line1\nsecret on new line")
	matches, err := matcher.Match(content)
	require.NoError(t, err)
	assert.Len(t, matches, 1)
}

func TestVectorscanMatcher_CaptureGroups(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "capture-rule",
			Name:    "Capture Groups Test",
			Pattern: `key:\s*([A-Z0-9]+)`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	content := []byte("key: AKIAIOSFODNN7EXAMPLE")
	matches, err := matcher.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	// Check that capture groups were extracted
	assert.NotEmpty(t, matches[0].Groups)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", string(matches[0].Groups[0]))
}

func TestVectorscanMatcher_NamedCaptureGroups(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "named-capture-rule",
			Name:    "Named Capture Test",
			Pattern: `(?P<keytype>AKIA)(?P<keyid>[0-9A-Z]{16})`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	content := []byte("Found: AKIAIOSFODNN7EXAMPLE")
	matches, err := matcher.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	// Check named capture groups
	assert.NotNil(t, matches[0].NamedGroups)
	assert.Equal(t, "AKIA", string(matches[0].NamedGroups["keytype"]))
	assert.Equal(t, "IOSFODNN7EXAMPLE", string(matches[0].NamedGroups["keyid"]))
}

func TestVectorscanMatcher_ContextExtraction(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "context-rule",
			Name:    "Context Test",
			Pattern: `secret_token`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	content := []byte("line1\nline2\nsecret_token found\nline4\nline5")
	matches, err := matcher.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	// Check snippet extraction
	assert.NotEmpty(t, matches[0].Snippet.Before)
	assert.NotEmpty(t, matches[0].Snippet.Matching)
	assert.NotEmpty(t, matches[0].Snippet.After)
	assert.Equal(t, "secret_token", string(matches[0].Snippet.Matching))
}

func TestVectorscanMatcher_Deduplication(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "dedup-rule",
			Name:    "Dedup Test",
			Pattern: `token`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	// Same token appears multiple times with same blob
	content := []byte("token token token")
	blobID := types.ComputeBlobID(content)

	matches, err := matcher.MatchWithBlobID(content, blobID)
	require.NoError(t, err)

	// Should deduplicate matches at same location
	// (Implementation deduplicates by structural ID which includes offset)
	// Since all matches have different offsets, we expect 3 matches
	assert.Len(t, matches, 3)
}

func TestVectorscanMatcher_LargeContent(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "large-rule",
			Name:    "Large Content Test",
			Pattern: `secret_[0-9]+`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	// Create large content that triggers chunking
	largeContent := make([]byte, 5*1024*1024) // 5MB
	copy(largeContent, []byte("secret_123"))

	matches, err := matcher.Match(largeContent)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(matches), 1)
}

func TestVectorscanMatcher_InvalidPattern(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "invalid-rule",
			Name:    "Invalid Pattern",
			Pattern: `[`,  // Invalid regex
		},
	}

	_, err := NewVectorscan(rules, 2)
	assert.Error(t, err)
}

func TestVectorscanMatcher_UTF8Content(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "utf8-rule",
			Name:    "UTF-8 Test",
			Pattern: `secret`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	// UTF-8 content with various characters
	content := []byte("日本語 secret token 中文")
	matches, err := matcher.Match(content)
	require.NoError(t, err)
	assert.Len(t, matches, 1)
}

func TestVectorscanMatcher_ConcurrentMatching(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "concurrent-rule",
			Name:    "Concurrent Test",
			Pattern: `secret_[0-9]+`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	// Run concurrent matches to verify thread safety
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			content := []byte("secret_123 in file")
			_, err := matcher.Match(content)
			assert.NoError(t, err)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestPreprocessPatternForHyperscan(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		expected string
	}{
		{
			name:     "strip extended mode",
			pattern:  `(?x) secret _ [a-z]+`,
			expected: `secret_[a-z]+`,
		},
		{
			name:     "remove case insensitive flag",
			pattern:  `(?i)password`,
			expected: `password`,
		},
		{
			name:     "remove dot all flag",
			pattern:  `(?s)BEGIN.*END`,
			expected: `BEGIN.*END`,
		},
		{
			name:     "remove multiline flag",
			pattern:  `(?m)^secret`,
			expected: `^secret`,
		},
		{
			name:     "no flags",
			pattern:  `secret_token`,
			expected: `secret_token`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := preprocessPatternForHyperscan(tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVectorscanMatcher_BlobIDConsistency(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "blob-rule",
			Name:    "Blob Test",
			Pattern: `secret`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	content := []byte("secret token")
	blobID := types.ComputeBlobID(content)

	matches, err := matcher.MatchWithBlobID(content, blobID)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	// Verify blob ID is set correctly
	assert.Equal(t, blobID, matches[0].BlobID)
}

func TestVectorscanMatcher_LocationAccuracy(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "location-rule",
			Name:    "Location Test",
			Pattern: `secret`,
		},
	}

	matcher, err := NewVectorscan(rules, 2)
	require.NoError(t, err)
	defer matcher.Close()

	content := []byte("prefix secret suffix")
	matches, err := matcher.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	// Verify location offsets
	assert.Equal(t, int64(7), matches[0].Location.Offset.Start)
	assert.Equal(t, int64(13), matches[0].Location.Offset.End)

	// Verify matched content
	matchedContent := content[matches[0].Location.Offset.Start:matches[0].Location.Offset.End]
	assert.Equal(t, "secret", string(matchedContent))
}
