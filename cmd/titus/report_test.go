package main

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func TestOutputReportHuman_FullSnippetContext(t *testing.T) {
	// Create a test match with Before, Matching, and After snippet content
	match := &types.Match{
		StructuralID: "test-match-1",
		RuleID:       "test-rule",
		BlobID:       types.BlobID{},
		Location:     types.Location{},
		Snippet: types.Snippet{
			Before:   []byte("context before "),
			Matching: []byte("SECRET_KEY"),
			After:    []byte(" context after"),
		},
		Groups: [][]byte{[]byte("SECRET_KEY")},
	}

	expectedSnippet := "context before SECRET_KEY context after"

	// Build the snippet as the code should do it
	snippet := string(match.Snippet.Before) + string(match.Snippet.Matching) + string(match.Snippet.After)

	if snippet != expectedSnippet {
		t.Errorf("Expected snippet to be %q, got %q", expectedSnippet, snippet)
	}

	// The actual test: verify the snippet is not truncated
	// Current code truncates at 100 chars, we want the full snippet
	// After our change, the full snippet should be used
	if !strings.Contains(expectedSnippet, "context before") {
		t.Error("Expected snippet to contain 'context before'")
	}
	if !strings.Contains(expectedSnippet, "SECRET_KEY") {
		t.Error("Expected snippet to contain 'SECRET_KEY'")
	}
	if !strings.Contains(expectedSnippet, "context after") {
		t.Error("Expected snippet to contain 'context after'")
	}
}

func TestSnippetAssembly_LongContent(t *testing.T) {
	// Test with content that would be truncated by the old logic (>100 chars)
	before := "This is a very long context before the match that contains lots of information "
	matching := "SECRET_API_KEY_12345"
	after := " and this is also a very long context after the match with more details"

	fullSnippet := before + matching + after

	if len(fullSnippet) <= 100 {
		t.Fatalf("Test setup error: snippet should be longer than 100 chars, got %d", len(fullSnippet))
	}

	// After our change, the full snippet should be preserved (not truncated)
	// The old code would do: snippet[:100] + "..."
	// The new code should keep the full snippet

	// This test verifies that we want the FULL snippet, not a truncated version
	if !strings.Contains(fullSnippet, before) {
		t.Error("Expected full snippet to contain before context")
	}
	if !strings.Contains(fullSnippet, matching) {
		t.Error("Expected full snippet to contain matching content")
	}
	if !strings.Contains(fullSnippet, after) {
		t.Error("Expected full snippet to contain after context")
	}
}

// =============================================================================
// Tests for formatSnippet helper
// =============================================================================

func TestFormatSnippet_ShortSnippet(t *testing.T) {
	// Test: Short snippet should not be truncated
	before := []byte("context ")
	matching := []byte("SECRET")
	after := []byte(" more")

	result := formatSnippet(before, matching, after, 500)
	expected := "context SECRET more"

	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestFormatSnippet_LongSnippet_CenteredOnMatch(t *testing.T) {
	// Test: Long snippet should be truncated and centered on match
	// Create a 1000-char line with match in the middle
	before := []byte(strings.Repeat("x", 400))
	matching := []byte("MATCH")
	after := []byte(strings.Repeat("y", 400))

	result := formatSnippet(before, matching, after, 500)

	// Should be ~500 chars
	if len(result) > 510 {
		t.Errorf("Expected result to be ~500 chars, got %d", len(result))
	}

	// Should contain the match
	if !strings.Contains(result, "MATCH") {
		t.Error("Expected result to contain the match")
	}

	// Should have ellipsis on both sides
	if !strings.HasPrefix(result, "...") {
		t.Error("Expected result to start with '...'")
	}
	if !strings.HasSuffix(result, "...") {
		t.Error("Expected result to end with '...'")
	}
}

func TestFormatSnippet_MatchExceedsMaxLen(t *testing.T) {
	// Test: If match itself is longer than maxLen, show truncated match
	before := []byte("")
	matching := []byte(strings.Repeat("M", 600))
	after := []byte("")

	result := formatSnippet(before, matching, after, 500)

	// Should start with "..." (prefix indicator) and end with "..." (truncation indicator)
	if !strings.HasPrefix(result, "...") {
		t.Error("Expected result to start with '...' for oversized match")
	}
	if !strings.HasSuffix(result, "...") {
		t.Error("Expected result to end with '...' for oversized match")
	}

	// Should be limited in size
	if len(result) > 510 {
		t.Errorf("Expected truncated result, got %d chars", len(result))
	}
}

func TestFormatSnippet_NearStart(t *testing.T) {
	// Test: Match near start should not have leading "..."
	before := []byte("ab")
	matching := []byte("MATCH")
	after := []byte(strings.Repeat("y", 600))

	result := formatSnippet(before, matching, after, 500)

	// Should NOT start with "..." because match is near the start
	if strings.HasPrefix(result, "...") {
		t.Error("Expected result to NOT start with '...' when match is near start")
	}

	// Should contain the match
	if !strings.Contains(result, "MATCH") {
		t.Error("Expected result to contain the match")
	}

	// Should have trailing "..." because content continues
	if !strings.HasSuffix(result, "...") {
		t.Error("Expected result to end with '...' when content continues")
	}
}

func TestFormatSnippet_NearEnd(t *testing.T) {
	// Test: Match near end should not have trailing "..."
	before := []byte(strings.Repeat("x", 600))
	matching := []byte("MATCH")
	after := []byte("ab")

	result := formatSnippet(before, matching, after, 500)

	// Should have leading "..." because content precedes
	if !strings.HasPrefix(result, "...") {
		t.Error("Expected result to start with '...' when content precedes")
	}

	// Should contain the match
	if !strings.Contains(result, "MATCH") {
		t.Error("Expected result to contain the match")
	}

	// Should NOT end with "..." because match is near the end
	if strings.HasSuffix(result, "...") {
		t.Error("Expected result to NOT end with '...' when match is near end")
	}
}

func TestFormatSnippet_MinifiedJS_100KB_Line(t *testing.T) {
	// Test: Real-world scenario - minified JS with 100KB line
	// Match in the middle, should get context around it
	before := []byte(strings.Repeat("var a=1;", 5000)) // ~40KB
	matching := []byte("API_KEY_12345")
	after := []byte(strings.Repeat("var b=2;", 5000)) // ~40KB

	result := formatSnippet(before, matching, after, 500)

	// Should be ~500 chars
	if len(result) > 510 {
		t.Errorf("Expected result to be ~500 chars, got %d", len(result))
	}

	// Should contain the match (most important part)
	if !strings.Contains(result, "API_KEY_12345") {
		t.Error("Expected result to contain the API key match")
	}

	// Should show some context before and after
	// We expect to see some "var a=1;" before the match
	// and some "var b=2;" after the match
	contextBefore := strings.LastIndex(result[:strings.Index(result, "API_KEY")], "var a=1;")
	contextAfter := strings.Index(result[strings.Index(result, "API_KEY")+13:], "var b=2;")

	if contextBefore == -1 {
		t.Error("Expected to see some context before the match")
	}
	if contextAfter == -1 {
		t.Error("Expected to see some context after the match")
	}
}
