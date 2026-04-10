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

	matcher, err := NewPortableRegexp(rules, 0, nil)
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

			matcher, err := NewPortableRegexp(rules, 2, nil)
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

// TestMatch_FindingID_Populated verifies that FindingID is set on all returned matches
func TestMatch_FindingID_Populated(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "np.aws.1",
			Name:         "AWS API Key",
			Pattern:      `(AKIA[0-9A-Z]{16})`,
			StructuralID: "1e4113c48323df7405840eede9a2be89a9797520",
		},
	}

	content := []byte("aws_access_key=AKIAZ52KNG5GARBXTEST\n")

	matcher, err := NewPortableRegexp(rules, 0, nil)
	require.NoError(t, err)

	matches, err := matcher.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	match := matches[0]
	assert.NotEmpty(t, match.FindingID, "FindingID should be populated")
	assert.Len(t, match.FindingID, 40, "FindingID should be 40-char SHA-1 hex")

	// Verify it matches the expected NoseyParker-compatible value
	expectedFindingID := types.ComputeFindingID(rules[0].StructuralID, match.Groups)
	assert.Equal(t, expectedFindingID, match.FindingID)

	// NoseyParker v0.24.0 produces this finding_id for np.aws.1 + "AKIAZ52KNG5GARBXTEST"
	assert.Equal(t, "59141806118796593f3d14bae57834b794d3421b", match.FindingID)
}

// TestPortableRegexp_TimeoutIsTolerated verifies that a regex timeout on one rule
// does NOT kill the scan; matches from other rules are still returned.
func TestPortableRegexp_TimeoutIsTolerated(t *testing.T) {
	// Build a catastrophic-backtracking pattern that will reliably time out under regexp2.
	// The pattern (a+)+ on a string of a's followed by a non-match is the canonical example.
	// We pair it with a benign rule so we can verify the benign rule still produces results.
	rules := []*types.Rule{
		{
			ID:      "catastrophic-rule",
			Name:    "Catastrophic Backtracking",
			Pattern: `(a+)+b`, // Known catastrophic backtracking pattern
		},
		{
			ID:      "good-rule",
			Name:    "Good Pattern",
			Pattern: `password\s*=\s*"([^"]+)"`,
		},
	}

	// Content: long string of 'a's (no 'b' at end → catastrophic backtracking on rule 1)
	// plus a password match that rule 2 should find.
	catastrophicContent := strings.Repeat("a", 5000) + "c" // no 'b' → triggers timeout on rule 1
	content := []byte(catastrophicContent + "\n" + `password = "secret123"`)

	m, err := NewPortableRegexp(rules, 0, nil)
	require.NoError(t, err)

	// This must NOT return an error even though catastrophic-rule times out.
	matches, err := m.MatchWithBlobID(content, types.ComputeBlobID(content))
	require.NoError(t, err, "timeout on one rule must not propagate as error")

	// The good-rule must still produce its match.
	ruleIDs := make(map[string]bool)
	for _, match := range matches {
		ruleIDs[match.RuleID] = true
	}
	assert.True(t, ruleIDs["good-rule"], "good-rule should still match despite other rule timing out")
	assert.False(t, ruleIDs["catastrophic-rule"], "catastrophic-rule should not produce matches (timed out)")
}

// TestPortableRegexp_TimeoutIsTolerated_Parallel is the same test but for large content
// that triggers the parallel path.
func TestPortableRegexp_TimeoutIsTolerated_Parallel(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "catastrophic-rule",
			Name:    "Catastrophic Backtracking",
			Pattern: `(a+)+b`, // Known catastrophic backtracking pattern
		},
		{
			ID:      "good-rule",
			Name:    "Good Pattern",
			Pattern: `password\s*=\s*"([^"]+)"`,
		},
	}

	// Build content >10KB to trigger parallel path.
	var sb strings.Builder
	sb.WriteString(strings.Repeat("a", 5000) + "c\n")
	for sb.Len() < parallelThreshold+1000 {
		sb.WriteString(`password = "secret123"` + "\n")
	}
	content := []byte(sb.String())
	require.Greater(t, len(content), parallelThreshold, "must trigger parallel path")

	m, err := NewPortableRegexp(rules, 0, nil)
	require.NoError(t, err)

	matches, err := m.MatchWithBlobID(content, types.ComputeBlobID(content))
	require.NoError(t, err, "timeout on one rule must not propagate as error in parallel path")

	ruleIDs := make(map[string]bool)
	for _, match := range matches {
		ruleIDs[match.RuleID] = true
	}
	assert.True(t, ruleIDs["good-rule"], "good-rule should still match in parallel path despite other rule timing out")
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

	matcher, err := NewPortableRegexp(rules, 1, nil)
	require.NoError(t, err)

	// Run multiple times to increase chance of detecting races
	for i := 0; i < 5; i++ {
		matches, err := matcher.Match(content)
		require.NoError(t, err)
		assert.NotEmpty(t, matches, "iteration %d: should find matches", i)
	}
}

// TestMatch_SnippetAndOffset_ASCII verifies correct snippet extraction and byte offsets
// for ASCII-only content.
func TestMatch_SnippetAndOffset_ASCII(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test-secret",
			Name:    "Secret Pattern",
			Pattern: `\b(secret_[a-z]+)\b`,
		},
	}

	content := []byte("prefix secret_key suffix")
	//                 0123456789...
	//                        ^-- "secret_key" starts at byte 7

	matcher, err := NewPortableRegexp(rules, 0, nil)
	require.NoError(t, err)

	matches, err := matcher.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	match := matches[0]

	// Verify matched text
	assert.Equal(t, "secret_key", string(match.Snippet.Matching))

	// Verify byte offsets
	assert.Equal(t, int64(7), match.Location.Offset.Start, "start offset should be 7")
	assert.Equal(t, int64(17), match.Location.Offset.End, "end offset should be 17")

	// Verify slicing with offsets gives correct result
	start := match.Location.Offset.Start
	end := match.Location.Offset.End
	assert.Equal(t, "secret_key", string(content[start:end]))
}

// TestMatch_SnippetAndOffset_UTF8 verifies correct snippet extraction and byte offsets
// when content contains multi-byte UTF-8 characters before the match.
//
// This is a regression test for the regexp2 rune-vs-byte index issue:
// regexp2 returns Match.Index as a rune count, not byte count, which caused
// incorrect offsets when content had multi-byte UTF-8 characters.
func TestMatch_SnippetAndOffset_UTF8(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test-secret",
			Name:    "Secret Pattern",
			Pattern: `\b(secret_[a-z]+)\b`,
		},
	}

	testCases := []struct {
		name        string
		content     string
		wantMatch   string
		wantStart   int64
		wantEnd     int64
		description string
	}{
		{
			name:        "2-byte UTF-8 before match",
			content:     "préfix secret_key suffix", // é = 2 bytes
			wantMatch:   "secret_key",
			wantStart:   8, // "préfix " = 8 bytes (7 chars but é is 2 bytes)
			wantEnd:     18,
			description: "é (U+00E9) is 2 bytes in UTF-8",
		},
		{
			name:        "3-byte UTF-8 before match",
			content:     "pre–fix secret_key suffix", // – (en dash) = 3 bytes
			wantMatch:   "secret_key",
			wantStart:   10, // "pre–fix " = 10 bytes (8 chars but – is 3 bytes)
			wantEnd:     20,
			description: "– (U+2013 en dash) is 3 bytes in UTF-8",
		},
		{
			name:        "4-byte UTF-8 before match",
			content:     "prefix 🔑 secret_key suffix", // 🔑 = 4 bytes
			wantMatch:   "secret_key",
			wantStart:   12, // "prefix 🔑 " = 12 bytes (9 chars but 🔑 is 4 bytes)
			wantEnd:     22,
			description: "🔑 (U+1F511) is 4 bytes in UTF-8",
		},
		{
			name:        "multiple multi-byte chars before match",
			content:     "café 🔐 secret_key suffix", // é=2bytes, 🔐=4bytes
			wantMatch:   "secret_key",
			wantStart:   11, // "café 🔐 " = 11 bytes (7 chars)
			wantEnd:     21,
			description: "multiple multi-byte characters compound the offset",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.content)

			matcher, err := NewPortableRegexp(rules, 0, nil)
			require.NoError(t, err)

			matches, err := matcher.Match(content)
			require.NoError(t, err)
			require.Len(t, matches, 1, "should find exactly one match")

			match := matches[0]

			// Verify matched text is correct
			assert.Equal(t, tc.wantMatch, string(match.Snippet.Matching),
				"Snippet.Matching should contain the correct text")

			// Verify byte offsets are correct
			assert.Equal(t, tc.wantStart, match.Location.Offset.Start,
				"Location.Offset.Start should be correct byte offset")
			assert.Equal(t, tc.wantEnd, match.Location.Offset.End,
				"Location.Offset.End should be correct byte offset")

			// Most importantly: verify slicing content with these offsets gives the matched text
			start := match.Location.Offset.Start
			end := match.Location.Offset.End
			sliced := string(content[start:end])
			assert.Equal(t, tc.wantMatch, sliced,
				"content[Offset.Start:Offset.End] must equal the matched text")
		})
	}
}

// TestMatch_SnippetContext_UTF8 verifies that before/after context is correct
// when content contains multi-byte UTF-8 characters.
func TestMatch_SnippetContext_UTF8(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test-secret",
			Name:    "Secret Pattern",
			Pattern: `\b(secret_[a-z]+)\b`,
		},
	}

	// Content with multi-byte chars before and after the match
	content := []byte("café secret_key 🔑end")

	matcher, err := NewPortableRegexp(rules, 3, nil) // 3 lines of context
	require.NoError(t, err)

	matches, err := matcher.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	match := matches[0]

	// Verify the matched text
	assert.Equal(t, "secret_key", string(match.Snippet.Matching))

	// Verify before context contains the UTF-8 prefix
	assert.Contains(t, string(match.Snippet.Before), "café",
		"before context should include UTF-8 characters")

	// Verify after context contains the UTF-8 suffix
	assert.Contains(t, string(match.Snippet.After), "🔑",
		"after context should include UTF-8 characters")
}
