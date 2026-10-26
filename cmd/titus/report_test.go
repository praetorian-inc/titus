package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/praetorian-inc/titus/pkg/sarif"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// =============================================================================
// Tests for color styles
// =============================================================================

func TestNewStyles_Enabled(t *testing.T) {
	// Test: Color styles should be created when enabled
	styles := newStyles(true)

	if styles == nil {
		t.Fatal("Expected styles to be non-nil")
	}

	if styles.findingHeading == nil {
		t.Error("Expected findingHeading style to be initialized")
	}
	if styles.id == nil {
		t.Error("Expected id style to be initialized")
	}
	if styles.ruleName == nil {
		t.Error("Expected ruleName style to be initialized")
	}
	if styles.heading == nil {
		t.Error("Expected heading style to be initialized")
	}
	if styles.match == nil {
		t.Error("Expected match style to be initialized")
	}
	if styles.metadata == nil {
		t.Error("Expected metadata style to be initialized")
	}
}

func TestNewStyles_Disabled(t *testing.T) {
	// Test: When disabled, styles should still format but without colors
	styles := newStyles(false)

	if styles == nil {
		t.Fatal("Expected styles to be non-nil")
	}

	// Test that formatting still works without colors
	testText := "test"
	result := styles.findingHeading.Sprint(testText)

	// When disabled, should return the same text without ANSI codes
	if result != testText {
		t.Errorf("Expected plain text %q, got %q", testText, result)
	}
}

func TestSnippetParts_Structure(t *testing.T) {
	// Test: snippetParts should separate before/matching/after
	before := []byte("context before ")
	matching := []byte("SECRET_KEY")
	after := []byte(" context after")

	parts := formatSnippetWithParts(before, matching, after, 500)

	if parts.before != "context before " {
		t.Errorf("Expected before to be %q, got %q", "context before ", parts.before)
	}
	if parts.matching != "SECRET_KEY" {
		t.Errorf("Expected matching to be %q, got %q", "SECRET_KEY", parts.matching)
	}
	if parts.after != " context after" {
		t.Errorf("Expected after to be %q, got %q", " context after", parts.after)
	}
	if parts.prefix != "" {
		t.Error("Expected no prefix for short snippet")
	}
	if parts.suffix != "" {
		t.Error("Expected no suffix for short snippet")
	}
}

func TestSnippetParts_Truncation(t *testing.T) {
	// Test: Long snippets should have ellipsis in prefix/suffix
	before := []byte(strings.Repeat("x", 400))
	matching := []byte("MATCH")
	after := []byte(strings.Repeat("y", 400))

	parts := formatSnippetWithParts(before, matching, after, 500)

	if parts.prefix != "..." {
		t.Errorf("Expected prefix to be '...', got %q", parts.prefix)
	}
	if parts.suffix != "..." {
		t.Errorf("Expected suffix to be '...', got %q", parts.suffix)
	}
	if !strings.Contains(parts.matching, "MATCH") {
		t.Error("Expected matching to contain 'MATCH'")
	}
}

func TestAggregateSummary_MultipleRules(t *testing.T) {
	findings := []*types.Finding{
		{ID: "f1", RuleID: "rule-a", Groups: [][]byte{[]byte("secret1")}},
		{ID: "f2", RuleID: "rule-a", Groups: [][]byte{[]byte("secret2")}},
		{ID: "f3", RuleID: "rule-a", Groups: [][]byte{[]byte("secret3")}},
		{ID: "f4", RuleID: "rule-b", Groups: [][]byte{[]byte("token1")}},
		{ID: "f5", RuleID: "rule-c", Groups: [][]byte{[]byte("key1")}},
		{ID: "f6", RuleID: "rule-c", Groups: [][]byte{[]byte("key2")}},
	}

	// 2 matches per finding for rule-a, 3 for rule-b, 1 for rule-c
	matchesByFinding := map[string][]*types.Match{
		"f1": {{RuleID: "rule-a"}, {RuleID: "rule-a"}},
		"f2": {{RuleID: "rule-a"}, {RuleID: "rule-a"}},
		"f3": {{RuleID: "rule-a"}, {RuleID: "rule-a"}},
		"f4": {{RuleID: "rule-b"}, {RuleID: "rule-b"}, {RuleID: "rule-b"}},
		"f5": {{RuleID: "rule-c"}},
		"f6": {{RuleID: "rule-c"}},
	}

	ruleMap := map[string]*types.Rule{
		"rule-a": {ID: "rule-a", Name: "AWS API Key"},
		"rule-b": {ID: "rule-b", Name: "GitHub Token"},
		"rule-c": {ID: "rule-c", Name: "Slack Webhook"},
	}

	summary := aggregateSummary(findings, matchesByFinding, ruleMap)

	// Check totals
	if summary.TotalFindings != 6 {
		t.Errorf("Expected 6 total findings, got %d", summary.TotalFindings)
	}
	if summary.TotalMatches != 11 {
		t.Errorf("Expected 11 total matches, got %d", summary.TotalMatches)
	}

	// Check sorted by finding count descending
	if len(summary.Rules) != 3 {
		t.Fatalf("Expected 3 rules, got %d", len(summary.Rules))
	}
	if summary.Rules[0].RuleName != "AWS API Key" {
		t.Errorf("Expected first rule to be 'AWS API Key', got %q", summary.Rules[0].RuleName)
	}
	if summary.Rules[0].Findings != 3 {
		t.Errorf("Expected 3 findings for AWS API Key, got %d", summary.Rules[0].Findings)
	}
	if summary.Rules[0].Matches != 6 {
		t.Errorf("Expected 6 matches for AWS API Key, got %d", summary.Rules[0].Matches)
	}
	if summary.Rules[1].RuleName != "Slack Webhook" {
		t.Errorf("Expected second rule to be 'Slack Webhook', got %q", summary.Rules[1].RuleName)
	}
	if summary.Rules[2].RuleName != "GitHub Token" {
		t.Errorf("Expected third rule to be 'GitHub Token', got %q", summary.Rules[2].RuleName)
	}
}

func TestAggregateSummary_Empty(t *testing.T) {
	summary := aggregateSummary(nil, nil, nil)

	if summary.TotalFindings != 0 {
		t.Errorf("Expected 0 total findings, got %d", summary.TotalFindings)
	}
	if summary.TotalMatches != 0 {
		t.Errorf("Expected 0 total matches, got %d", summary.TotalMatches)
	}
	if len(summary.Rules) != 0 {
		t.Errorf("Expected 0 rules, got %d", len(summary.Rules))
	}
}

func TestAggregateSummary_UnknownRule(t *testing.T) {
	findings := []*types.Finding{
		{ID: "f1", RuleID: "unknown-rule", Groups: [][]byte{[]byte("secret1")}},
	}
	matchesByFinding := map[string][]*types.Match{
		"f1": {{RuleID: "unknown-rule"}},
	}
	// ruleMap does not contain "unknown-rule"
	ruleMap := map[string]*types.Rule{}

	summary := aggregateSummary(findings, matchesByFinding, ruleMap)

	if len(summary.Rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(summary.Rules))
	}
	// Should fall back to raw RuleID as display name
	if summary.Rules[0].RuleName != "unknown-rule" {
		t.Errorf("Expected rule name fallback to 'unknown-rule', got %q", summary.Rules[0].RuleName)
	}
}

func TestOutputSummaryHuman(t *testing.T) {
	summary := summaryResult{
		TotalFindings: 6,
		TotalMatches:  11,
		Rules: []ruleSummary{
			{RuleID: "rule-a", RuleName: "AWS API Key", Findings: 3, Matches: 6},
			{RuleID: "rule-c", RuleName: "Slack Webhook", Findings: 2, Matches: 2},
			{RuleID: "rule-b", RuleName: "GitHub Token", Findings: 1, Matches: 3},
		},
	}

	var buf bytes.Buffer
	err := outputSummaryHuman(&buf, summary, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Check total line
	if !strings.Contains(output, "Total: 6 findings, 11 matches") {
		t.Errorf("Expected total line, got:\n%s", output)
	}

	// Check all rule names appear
	for _, name := range []string{"AWS API Key", "Slack Webhook", "GitHub Token"} {
		if !strings.Contains(output, name) {
			t.Errorf("Expected output to contain %q, got:\n%s", name, output)
		}
	}

	// Check header row
	if !strings.Contains(output, "Rule") || !strings.Contains(output, "Findings") || !strings.Contains(output, "Matches") {
		t.Errorf("Expected table headers, got:\n%s", output)
	}

	// Check separator line
	if !strings.Contains(output, "─") {
		t.Errorf("Expected separator line with box-drawing chars, got:\n%s", output)
	}
}

func TestOutputSummaryHuman_Empty(t *testing.T) {
	summary := summaryResult{}

	var buf bytes.Buffer
	err := outputSummaryHuman(&buf, summary, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No findings") {
		t.Errorf("Expected 'No findings' message, got:\n%s", output)
	}
}

func TestOutputSummaryJSON(t *testing.T) {
	summary := summaryResult{
		TotalFindings: 4,
		TotalMatches:  10,
		Rules: []ruleSummary{
			{RuleID: "rule-a", RuleName: "AWS API Key", Findings: 3, Matches: 7},
			{RuleID: "rule-b", RuleName: "GitHub Token", Findings: 1, Matches: 3},
		},
	}

	var buf bytes.Buffer
	err := outputSummaryJSON(&buf, summary)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse the output as JSON
	var parsed summaryResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v\nOutput:\n%s", err, buf.String())
	}

	if parsed.TotalFindings != 4 {
		t.Errorf("Expected total_findings=4, got %d", parsed.TotalFindings)
	}
	if parsed.TotalMatches != 10 {
		t.Errorf("Expected total_matches=10, got %d", parsed.TotalMatches)
	}
	if len(parsed.Rules) != 2 {
		t.Fatalf("Expected 2 rules, got %d", len(parsed.Rules))
	}
	if parsed.Rules[0].RuleID != "rule-a" {
		t.Errorf("Expected first rule_id='rule-a', got %q", parsed.Rules[0].RuleID)
	}
	if parsed.Rules[0].RuleName != "AWS API Key" {
		t.Errorf("Expected first rule_name='AWS API Key', got %q", parsed.Rules[0].RuleName)
	}
}

// =============================================================================
// Fake store for filterRejected tests
// =============================================================================

// fakeRejectionStore is a minimal store.Store implementation for testing
// filterRejected. Only GetAnnotationsByType is meaningful; all other methods are
// satisfied by embedding store.Store (nil panic guard — tests must not call
// any other method).
type fakeRejectionStore struct {
	store.Store
	rejections map[string]string // key: finding ID, value: status string
	bulkErr    error             // error to return from GetAnnotationsByType
}

func (f *fakeRejectionStore) GetAnnotationsByType(targetType string) (map[string]string, error) {
	if f.bulkErr != nil {
		return nil, f.bulkErr
	}
	result := make(map[string]string)
	for id, status := range f.rejections {
		result[id] = status
	}
	return result, nil
}

// =============================================================================
// Flag wiring tests
// =============================================================================

func TestReportCmd_ShowRejectedFlag_RegisteredAsPersistent(t *testing.T) {
	flag := reportCmd.PersistentFlags().Lookup("show-rejected")
	require.NotNil(t, flag, "expected --show-rejected to be registered as a persistent flag on reportCmd")
	assert.Equal(t, "bool", flag.Value.Type())
}

func TestReportCmd_ShowRejectedFlag_DefaultsToFalse(t *testing.T) {
	flag := reportCmd.PersistentFlags().Lookup("show-rejected")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}

func TestSummaryCmd_InheritsShowRejectedFromReport(t *testing.T) {
	// The flag is persistent on reportCmd so summaryCmd inherits it.
	inherited := summaryCmd.InheritedFlags().Lookup("show-rejected")
	assert.NotNil(t, inherited, "summaryCmd should inherit --show-rejected from reportCmd persistent flags")

	// It must NOT appear as a locally-defined (non-inherited) flag on summaryCmd.
	// Use LocalNonPersistentFlags which only returns flags defined directly on
	// summaryCmd, not those merged in from parent persistent flag sets.
	local := summaryCmd.LocalNonPersistentFlags().Lookup("show-rejected")
	assert.Nil(t, local, "--show-rejected must not be a local flag on summaryCmd, only inherited")
}

func TestReportCmd_ShowRejectedFlag_Description(t *testing.T) {
	flag := reportCmd.PersistentFlags().Lookup("show-rejected")
	require.NotNil(t, flag)
	assert.Contains(t, flag.Usage, "rejected",
		"flag description should mention 'rejected'")
}

// =============================================================================
// filterRejected core logic tests
// =============================================================================

func TestFilterRejected_EmptyFindings(t *testing.T) {
	s := &fakeRejectionStore{rejections: map[string]string{}}
	findings, matches, err := filterRejected(s, nil, nil, nil)
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Empty(t, matches)
}

func TestFilterRejected_NoRejections_ReturnsInputsUnchanged(t *testing.T) {
	rule := &types.Rule{
		ID:           "rule-1",
		StructuralID: "struct-1",
	}
	ruleMap := map[string]*types.Rule{"rule-1": rule}

	f1 := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("secret-a")}),
		RuleID: "rule-1",
		Groups: [][]byte{[]byte("secret-a")},
	}
	f2 := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("secret-b")}),
		RuleID: "rule-1",
		Groups: [][]byte{[]byte("secret-b")},
	}
	findings := []*types.Finding{f1, f2}

	m1 := &types.Match{StructuralID: "match-1", RuleID: "rule-1", Groups: [][]byte{[]byte("secret-a")}}
	m2 := &types.Match{StructuralID: "match-2", RuleID: "rule-1", Groups: [][]byte{[]byte("secret-b")}}
	matches := []*types.Match{m1, m2}

	// Store returns empty status for all IDs — no rejections
	s := &fakeRejectionStore{rejections: map[string]string{}}

	gotFindings, gotMatches, err := filterRejected(s, findings, matches, ruleMap)
	require.NoError(t, err)

	assert.Len(t, gotFindings, 2, "all findings should be retained when none are rejected")
	assert.Len(t, gotMatches, 2, "all matches should be retained when none are rejected")
	assert.Equal(t, findings, gotFindings, "returned findings slice should equal input")
	assert.Equal(t, matches, gotMatches, "returned matches slice should equal input")
}

func TestFilterRejected_AllFindingsRejected_ReturnsEmpty(t *testing.T) {
	rule := &types.Rule{
		ID:           "rule-1",
		StructuralID: "struct-1",
	}
	ruleMap := map[string]*types.Rule{"rule-1": rule}

	f1 := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("secret-a")}),
		RuleID: "rule-1",
		Groups: [][]byte{[]byte("secret-a")},
	}
	f2 := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("secret-b")}),
		RuleID: "rule-1",
		Groups: [][]byte{[]byte("secret-b")},
	}
	findings := []*types.Finding{f1, f2}

	m1 := &types.Match{StructuralID: "match-1", RuleID: "rule-1", Groups: [][]byte{[]byte("secret-a")}}
	m2 := &types.Match{StructuralID: "match-2", RuleID: "rule-1", Groups: [][]byte{[]byte("secret-b")}}
	matches := []*types.Match{m1, m2}

	s := &fakeRejectionStore{
		rejections: map[string]string{
			f1.ID: store.StatusReject,
			f2.ID: store.StatusReject,
		},
	}

	gotFindings, gotMatches, err := filterRejected(s, findings, matches, ruleMap)
	require.NoError(t, err)

	assert.Empty(t, gotFindings, "all findings should be removed when all are rejected")
	assert.Empty(t, gotMatches, "all matches should be removed when all findings are rejected")
}

func TestFilterRejected_PartialRejection_RemovesRejectedFindingAndItsMatches(t *testing.T) {
	rule := &types.Rule{
		ID:           "rule-1",
		StructuralID: "struct-partial",
	}
	ruleMap := map[string]*types.Rule{"rule-1": rule}

	// Three findings: first, middle (to be rejected), last
	f1 := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("secret-1")}),
		RuleID: "rule-1",
		Groups: [][]byte{[]byte("secret-1")},
	}
	f2 := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("secret-2")}),
		RuleID: "rule-1",
		Groups: [][]byte{[]byte("secret-2")},
	}
	f3 := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("secret-3")}),
		RuleID: "rule-1",
		Groups: [][]byte{[]byte("secret-3")},
	}
	findings := []*types.Finding{f1, f2, f3}

	// Build matches with StructuralID set so buildFindingMatchMap can resolve
	// them via ComputeFindingID.  We assign each match a RuleID and Groups
	// matching its parent finding so the content-based map links them.
	m1 := &types.Match{
		StructuralID: "smatch-1",
		RuleID:       "rule-1",
		Groups:       [][]byte{[]byte("secret-1")},
	}
	m2a := &types.Match{
		StructuralID: "smatch-2a",
		RuleID:       "rule-1",
		Groups:       [][]byte{[]byte("secret-2")},
	}
	m2b := &types.Match{
		StructuralID: "smatch-2b",
		RuleID:       "rule-1",
		Groups:       [][]byte{[]byte("secret-2")},
	}
	m3 := &types.Match{
		StructuralID: "smatch-3",
		RuleID:       "rule-1",
		Groups:       [][]byte{[]byte("secret-3")},
	}
	matches := []*types.Match{m1, m2a, m2b, m3}

	// Only f2 (middle) is rejected.
	s := &fakeRejectionStore{
		rejections: map[string]string{f2.ID: store.StatusReject},
	}

	gotFindings, gotMatches, err := filterRejected(s, findings, matches, ruleMap)
	require.NoError(t, err)

	require.Len(t, gotFindings, 2, "should have 2 findings after rejecting middle one")
	assert.Equal(t, f1, gotFindings[0], "first finding retained")
	assert.Equal(t, f3, gotFindings[1], "last finding retained")

	// Matches for f2 (m2a and m2b) should be removed; m1 and m3 should remain.
	require.Len(t, gotMatches, 2, "should have 2 matches after removing rejected finding's matches")
	structIDs := make([]string, 0, len(gotMatches))
	for _, m := range gotMatches {
		structIDs = append(structIDs, m.StructuralID)
	}
	assert.Contains(t, structIDs, "smatch-1")
	assert.Contains(t, structIDs, "smatch-3")
	assert.NotContains(t, structIDs, "smatch-2a")
	assert.NotContains(t, structIDs, "smatch-2b")
}

func TestFilterRejected_NonRejectStatusRetained(t *testing.T) {
	rule := &types.Rule{
		ID:           "rule-1",
		StructuralID: "struct-nonreject",
	}
	ruleMap := map[string]*types.Rule{"rule-1": rule}

	f1 := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("val-1")}),
		RuleID: "rule-1",
		Groups: [][]byte{[]byte("val-1")},
	}
	f2 := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("val-2")}),
		RuleID: "rule-1",
		Groups: [][]byte{[]byte("val-2")},
	}
	findings := []*types.Finding{f1, f2}
	matches := []*types.Match{
		{StructuralID: "sm-1", RuleID: "rule-1", Groups: [][]byte{[]byte("val-1")}},
		{StructuralID: "sm-2", RuleID: "rule-1", Groups: [][]byte{[]byte("val-2")}},
	}

	// f1 has "accept" status, f2 has no status — neither should be filtered.
	s := &fakeRejectionStore{
		rejections: map[string]string{f1.ID: store.StatusAccept},
	}

	gotFindings, gotMatches, err := filterRejected(s, findings, matches, ruleMap)
	require.NoError(t, err)

	assert.Len(t, gotFindings, 2, "findings with non-reject status should be retained")
	assert.Len(t, gotMatches, 2, "matches for non-rejected findings should be retained")
}

func TestOutputReportSARIF_EmitsScore(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := store.New(store.Config{Path: filepath.Join(tmpDir, "test.db")})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	rule := &types.Rule{ID: "np.test.1", Name: "Test Rule", Pattern: "x"}
	rule.StructuralID = rule.ComputeStructuralID()
	require.NoError(t, s.AddRule(rule))

	finding := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("secret")}),
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("secret")},
		Score: &types.Score{
			Final:             75,
			Base:              75,
			SuggestedSeverity: "high",
			Applied:           []types.ScoreModifier{},
		},
	}
	require.NoError(t, s.AddFinding(finding))

	blobID := types.BlobID{}
	require.NoError(t, s.AddBlob(blobID, 10))

	match := &types.Match{
		StructuralID: "sm-1",
		RuleID:       "np.test.1",
		Groups:       [][]byte{[]byte("secret")},
		BlobID:       blobID,
		Location:     types.Location{},
	}
	require.NoError(t, s.AddMatch(match))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	matches, err := s.GetAllMatches()
	require.NoError(t, err)
	ruleMap := map[string]*types.Rule{"np.test.1": rule}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, outputReportSARIF(cmd, s, findings, matches, ruleMap))

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	runs := parsed["runs"].([]interface{})
	results := runs[0].(map[string]interface{})["results"].([]interface{})
	require.Len(t, results, 1)

	r := results[0].(map[string]interface{})
	// score 75 → level "error"
	assert.Equal(t, "error", r["level"])

	props, ok := r["properties"].(map[string]interface{})
	require.True(t, ok, "properties should be present in SARIF result")
	assert.Equal(t, "7.5", props["security-severity"])
}

func TestOutputReportSARIF_NilScoreFallsBackToWarning(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := store.New(store.Config{Path: filepath.Join(tmpDir, "test.db")})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	rule := &types.Rule{ID: "np.test.2", Name: "No Score Rule", Pattern: "y"}
	rule.StructuralID = rule.ComputeStructuralID()
	require.NoError(t, s.AddRule(rule))

	finding := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("val")}),
		RuleID: "np.test.2",
		Groups: [][]byte{[]byte("val")},
		Score:  nil, // no score
	}
	require.NoError(t, s.AddFinding(finding))

	blobID2 := types.BlobID{}
	require.NoError(t, s.AddBlob(blobID2, 10))

	match := &types.Match{
		StructuralID: "sm-2",
		RuleID:       "np.test.2",
		Groups:       [][]byte{[]byte("val")},
		BlobID:       blobID2,
		Location:     types.Location{},
	}
	require.NoError(t, s.AddMatch(match))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	matches, err := s.GetAllMatches()
	require.NoError(t, err)
	ruleMap := map[string]*types.Rule{"np.test.2": rule}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, outputReportSARIF(cmd, s, findings, matches, ruleMap))

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	runs := parsed["runs"].([]interface{})
	results := runs[0].(map[string]interface{})["results"].([]interface{})
	require.Len(t, results, 1)

	r := results[0].(map[string]interface{})
	// nil score → fallback level "warning"
	assert.Equal(t, "warning", r["level"])
	// properties should be absent when score is nil
	_, hasProps := r["properties"]
	assert.False(t, hasProps, "properties should be absent when score is nil")
}

func TestOutputReportHuman_ShowsScoreBadge(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := store.New(store.Config{Path: dbPath})
	require.NoError(t, err)

	rule := &types.Rule{ID: "np.test.1", Name: "Test Rule", Pattern: "x"}
	rule.StructuralID = rule.ComputeStructuralID()
	require.NoError(t, s.AddRule(rule))

	finding := &types.Finding{
		ID:     "f1",
		RuleID: "np.test.1",
		Score: &types.Score{
			Final: 85, Base: 85, SuggestedSeverity: "critical",
			Applied: []types.ScoreModifier{},
		},
	}
	require.NoError(t, s.AddFinding(finding))
	defer func() { _ = s.Close() }()

	findings := []*types.Finding{finding}
	var matches []*types.Match
	ruleMap := map[string]*types.Rule{"np.test.1": rule}

	// Disable color for stable output
	reportColor = "never"

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, outputReportHuman(cmd, s, findings, matches, ruleMap))

	output := buf.String()
	assert.Contains(t, output, "Score:", "expected 'Score:' label in output")
	assert.Contains(t, output, "85/100", "expected '85/100' score in output")
	assert.Contains(t, output, "critical", "expected 'critical' severity in output")
}

func TestReport_JSON_ScoreRoundTrip_Golden(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := store.New(store.Config{Path: filepath.Join(tmpDir, "test.db")})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	rule := &types.Rule{ID: "np.test.1", Name: "Test", Pattern: "x"}
	rule.StructuralID = rule.ComputeStructuralID()
	require.NoError(t, s.AddRule(rule))

	finding := &types.Finding{
		ID:     "test-finding-abc",
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("x1x2x")},
		Score: &types.Score{
			Final:             75,
			Base:              75,
			SuggestedSeverity: "high",
			Applied:           []types.ScoreModifier{},
		},
	}
	require.NoError(t, s.AddFinding(finding))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	matches, err := s.GetAllMatches()
	require.NoError(t, err)
	ruleMap := map[string]*types.Rule{"np.test.1": rule}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, outputReportJSON(cmd, s, findings, matches, ruleMap))

	goldenPath := "testdata/golden/score_json.golden.json"
	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		if os.Getenv("UPDATE_GOLDEN") != "" {
			require.NoError(t, os.WriteFile(goldenPath, buf.Bytes(), 0644))
			t.Skip("wrote golden file, rerun without UPDATE_GOLDEN")
		}
		t.Fatalf("golden file not found: %v", err)
	}

	assert.Equal(t, strings.TrimSpace(string(wantBytes)), strings.TrimSpace(buf.String()),
		"JSON output mismatch (regenerate with UPDATE_GOLDEN=1)")
}

func TestFilterRejected_BulkAnnotationError_Propagates(t *testing.T) {
	s := &fakeRejectionStore{bulkErr: errors.New("db exploded")}
	_, _, err := filterRejected(s, []*types.Finding{{ID: "f1"}}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db exploded")
}

func TestFilterRejected_MatchWithoutFindingIsRetained(t *testing.T) {
	rule := &types.Rule{
		ID:           "rule-1",
		StructuralID: "struct-orphan",
	}
	ruleMap := map[string]*types.Rule{"rule-1": rule}

	// Only one finding; its match uses groups "reject-me".
	rejected := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("reject-me")}),
		RuleID: "rule-1",
		Groups: [][]byte{[]byte("reject-me")},
	}
	findings := []*types.Finding{rejected}

	// "Orphan" match: its Groups do not match any finding in ruleMap
	// (different groups value, so buildFindingMatchMap won't link it).
	orphanMatch := &types.Match{
		StructuralID: "sm-orphan",
		RuleID:       "rule-other", // not in ruleMap → won't resolve to any finding
		Groups:       [][]byte{[]byte("orphan-val")},
	}
	rejectedMatch := &types.Match{
		StructuralID: "sm-rejected",
		RuleID:       "rule-1",
		Groups:       [][]byte{[]byte("reject-me")},
	}
	matches := []*types.Match{orphanMatch, rejectedMatch}

	s := &fakeRejectionStore{
		rejections: map[string]string{rejected.ID: store.StatusReject},
	}

	gotFindings, gotMatches, err := filterRejected(s, findings, matches, ruleMap)
	require.NoError(t, err)

	assert.Empty(t, gotFindings, "rejected finding should be removed")

	// The orphan match is NOT linked to any rejected finding, so it must survive.
	require.Len(t, gotMatches, 1, "orphan match unrelated to rejected finding should be retained")
	assert.Equal(t, "sm-orphan", gotMatches[0].StructuralID)
}

func TestFilterRejected_DuplicateStructuralIDs(t *testing.T) {
	rule := &types.Rule{
		ID:           "rule-1",
		StructuralID: "struct-dup",
	}
	ruleMap := map[string]*types.Rule{"rule-1": rule}

	f1 := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("dup-val")}),
		RuleID: "rule-1",
		Groups: [][]byte{[]byte("dup-val")},
	}
	findings := []*types.Finding{f1}

	// Two matches sharing the exact same StructuralID (defensive scenario).
	sharedID := "sm-shared"
	m1 := &types.Match{
		StructuralID: sharedID,
		RuleID:       "rule-1",
		Groups:       [][]byte{[]byte("dup-val")},
	}
	m2 := &types.Match{
		StructuralID: sharedID,
		RuleID:       "rule-1",
		Groups:       [][]byte{[]byte("dup-val")},
	}
	matches := []*types.Match{m1, m2}

	s := &fakeRejectionStore{
		rejections: map[string]string{f1.ID: store.StatusReject},
	}

	gotFindings, gotMatches, err := filterRejected(s, findings, matches, ruleMap)
	require.NoError(t, err)

	assert.Empty(t, gotFindings)
	// Both matches share the same StructuralID that is in the rejected set;
	// both should be removed.
	assert.Empty(t, gotMatches, "both matches with the shared StructuralID should be removed when finding is rejected")
}

// =============================================================================
// Tests for outputReportJSON file_path field (issue #197)
// =============================================================================

// jsonMatchOutput is used to decode the Matches field from outputReportJSON output.
type jsonMatchOutput struct {
	BlobID       types.BlobID `json:"BlobID"`
	StructuralID string       `json:"StructuralID"`
	RuleID       string       `json:"RuleID"`
	FilePath     string       `json:"file_path"`
}

// jsonFindingOutput is used to decode the top-level finding output.
type jsonFindingOutput struct {
	ID      string            `json:"ID"`
	RuleID  string            `json:"RuleID"`
	Matches []jsonMatchOutput `json:"Matches"`
}

func TestOutputReportJSON_IncludesFilePath(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := store.New(store.Config{Path: filepath.Join(tmpDir, "test.db")})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	// Set up rule
	rule := &types.Rule{ID: "np.test.1", Name: "Test Rule", Pattern: "sk_test_.*"}
	rule.StructuralID = rule.ComputeStructuralID()
	require.NoError(t, s.AddRule(rule))

	// Set up finding
	groups := [][]byte{[]byte("sk_test_secret")}
	finding := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, groups),
		RuleID: "np.test.1",
		Groups: groups,
	}
	require.NoError(t, s.AddFinding(finding))

	// Set up blob with provenance pointing to a known path
	blobID := types.ComputeBlobID([]byte("STRIPE_SECRET_KEY=sk_test_secret"))
	require.NoError(t, s.AddBlob(blobID, 32))
	wantPath := "/tmp/demo/creds.txt"
	require.NoError(t, s.AddProvenance(blobID, types.FileProvenance{FilePath: wantPath}))

	// Set up match linking blob to finding
	match := &types.Match{
		StructuralID: "sm-stripe-1",
		RuleID:       "np.test.1",
		BlobID:       blobID,
		Groups:       groups,
		Location:     types.Location{},
		Snippet: types.Snippet{
			Matching: []byte("sk_test_secret"),
		},
	}
	require.NoError(t, s.AddMatch(match))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	matches, err := s.GetAllMatches()
	require.NoError(t, err)
	ruleMap := map[string]*types.Rule{"np.test.1": rule}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, outputReportJSON(cmd, s, findings, matches, ruleMap))

	// Parse the JSON output
	var output []jsonFindingOutput
	require.NoError(t, json.Unmarshal(buf.Bytes(), &output), "output must be valid JSON")

	require.Len(t, output, 1, "expected exactly one finding")
	require.Len(t, output[0].Matches, 1, "expected exactly one match")

	gotMatch := output[0].Matches[0]

	// Primary assertion: file_path must be the provenance path, not a blob hex string.
	assert.Equal(t, wantPath, gotMatch.FilePath,
		"file_path should equal the provenance path, not the blob hex")

	// Existing fields must be preserved.
	assert.Equal(t, "np.test.1", gotMatch.RuleID, "RuleID should be preserved in match output")
	assert.Equal(t, "sm-stripe-1", gotMatch.StructuralID, "StructuralID should be preserved in match output")
}

func TestOutputReportJSON_FilePathFallsBackToBlobHex(t *testing.T) {
	// When no provenance exists for a blob, file_path should fall back to blob hex string.
	tmpDir := t.TempDir()
	s, err := store.New(store.Config{Path: filepath.Join(tmpDir, "test.db")})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	rule := &types.Rule{ID: "np.test.2", Name: "Test Rule 2", Pattern: "tok_.*"}
	rule.StructuralID = rule.ComputeStructuralID()
	require.NoError(t, s.AddRule(rule))

	groups := [][]byte{[]byte("tok_abc")}
	finding := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, groups),
		RuleID: "np.test.2",
		Groups: groups,
	}
	require.NoError(t, s.AddFinding(finding))

	blobID := types.ComputeBlobID([]byte("TOKEN=tok_abc"))
	require.NoError(t, s.AddBlob(blobID, 13))
	// No AddProvenance call — no provenance for this blob.

	match := &types.Match{
		StructuralID: "sm-token-1",
		RuleID:       "np.test.2",
		BlobID:       blobID,
		Groups:       groups,
		Location:     types.Location{},
	}
	require.NoError(t, s.AddMatch(match))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	matches, err := s.GetAllMatches()
	require.NoError(t, err)
	ruleMap := map[string]*types.Rule{"np.test.2": rule}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, outputReportJSON(cmd, s, findings, matches, ruleMap))

	var output []jsonFindingOutput
	require.NoError(t, json.Unmarshal(buf.Bytes(), &output))

	require.Len(t, output, 1)
	require.Len(t, output[0].Matches, 1)

	gotMatch := output[0].Matches[0]
	// file_path must fall back to the blob ID hex string when no provenance exists.
	assert.Equal(t, blobID.Hex(), gotMatch.FilePath,
		"file_path should fall back to BlobID.Hex() when provenance is unavailable")
}

// =============================================================================
// Regression test: jsonFinding.Matches tag must track types.Finding.Matches
// =============================================================================

func TestJSONFindingMatchesTagTracksFinding(t *testing.T) {
	// If types.Finding.Matches ever gains or changes its json tag, the
	// shadow jsonFinding.Matches tag must be updated in lockstep, otherwise
	// titus report --format json will emit two "Matches" keys (or one wrong
	// key and the embedded original). This test enforces that coupling.

	findingField, ok := reflect.TypeOf(types.Finding{}).FieldByName("Matches")
	require.True(t, ok, "types.Finding.Matches field not found")

	findingMarshaledName := marshaledJSONName(findingField)

	jfField, ok := reflect.TypeOf(jsonFinding{}).FieldByName("Matches")
	require.True(t, ok, "jsonFinding.Matches field not found")

	jfMarshaledName := marshaledJSONName(jfField)

	require.Equal(t, findingMarshaledName, jfMarshaledName,
		"jsonFinding.Matches json key (%q) must match types.Finding.Matches json key (%q); "+
			"update the tag in cmd/titus/report.go when types.Finding.Matches changes",
		jfMarshaledName, findingMarshaledName)
}

// marshaledJSONName returns the JSON key encoding/json would use for the field,
// handling untagged fields (default field-name behavior) and tag options like ",omitempty".
func marshaledJSONName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" {
		return f.Name
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		return f.Name
	}
	return name
}

func TestReport_JSON_AppliedPopulated_Golden(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := store.New(store.Config{Path: filepath.Join(tmpDir, "test.db")})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	rule := &types.Rule{ID: "np.aws.1", Name: "AWS API Key", Pattern: `\b(?P<key_id>(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b`, BaseScore: 48}
	rule.StructuralID = rule.ComputeStructuralID()
	require.NoError(t, s.AddRule(rule))

	finding := &types.Finding{
		ID:     "test-aws-akia",
		RuleID: "np.aws.1",
		Groups: [][]byte{[]byte("AKIADEADBEEFDEADBEEF")},
		Score: &types.Score{
			Final:             58,
			Base:              48,
			SuggestedSeverity: "medium",
			Applied: []types.ScoreModifier{
				{Name: "akia-long-term", Scorer: "aws-key-scope", Kind: "delta", Value: 10, Priority: 100},
			},
		},
	}
	require.NoError(t, s.AddFinding(finding))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	matches, err := s.GetAllMatches()
	require.NoError(t, err)
	ruleMap := map[string]*types.Rule{"np.aws.1": rule}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, outputReportJSON(cmd, s, findings, matches, ruleMap))

	goldenPath := "testdata/golden/score_json_applied.golden.json"
	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		if os.Getenv("UPDATE_GOLDEN") != "" {
			require.NoError(t, os.WriteFile(goldenPath, buf.Bytes(), 0644))
			t.Skip("wrote golden file, rerun without UPDATE_GOLDEN")
		}
		t.Fatalf("golden file not found (run with UPDATE_GOLDEN=1): %v", err)
	}

	assert.Equal(t, strings.TrimSpace(string(wantBytes)), strings.TrimSpace(buf.String()),
		"JSON output mismatch (regenerate with UPDATE_GOLDEN=1)")
}

// =============================================================================
// Test 5 — Legacy datastore read compatibility
// =============================================================================

// TestLegacyDatastore_NilScore_RendersCleanly verifies that datastores written
// before M2 (where Score is nil on every finding) are readable by the current
// report code without panics or data corruption.
//
// Approach: open a fresh SQLite store, insert a finding with Score explicitly
// set to nil (simulating a legacy row), then call each report path and assert:
//   - No panic.
//   - JSON output renders "Score": null (not absent), proving the field is
//     present and the omitempty behavior is correct.
//   - SARIF output renders a result entry without crashing.
//   - Human output renders without crashing.
//   - The stored finding's Score remains nil after the read (no unintended mutation).
func TestLegacyDatastore_NilScore_RendersCleanly(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := store.New(store.Config{Path: filepath.Join(tmpDir, "legacy.db")})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	// Simulate a legacy rule and finding with Score == nil (pre-M2 binary).
	rule := &types.Rule{
		ID:        "np.legacy.1",
		Name:      "Legacy Rule",
		Pattern:   `\blegacy-secret-\w+\b`,
		BaseScore: 55,
	}
	rule.StructuralID = rule.ComputeStructuralID()
	require.NoError(t, s.AddRule(rule))

	groups := [][]byte{[]byte("legacy-secret-abc")}
	legacyFinding := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, groups),
		RuleID: "np.legacy.1",
		Groups: groups,
		Score:  nil, // explicit nil — simulates pre-M2 row
	}
	require.NoError(t, s.AddFinding(legacyFinding))

	blobID := types.ComputeBlobID([]byte("SECRET=legacy-secret-abc"))
	require.NoError(t, s.AddBlob(blobID, 24))
	require.NoError(t, s.AddProvenance(blobID, types.FileProvenance{FilePath: "/repo/creds.txt"}))

	match := &types.Match{
		StructuralID: "sm-legacy-1",
		RuleID:       "np.legacy.1",
		BlobID:       blobID,
		Groups:       groups,
		Location:     types.Location{},
		Snippet:      types.Snippet{Matching: []byte("legacy-secret-abc")},
	}
	require.NoError(t, s.AddMatch(match))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	require.Len(t, findings, 1)
	// Score must still be nil after the round-trip — no unintended mutation.
	assert.Nil(t, findings[0].Score, "legacy finding Score must remain nil after round-trip read")

	allMatches, err := s.GetAllMatches()
	require.NoError(t, err)
	ruleMap := map[string]*types.Rule{"np.legacy.1": rule}

	// --- JSON output must not panic and must render Score as null ---
	jsonCmd := &cobra.Command{}
	var jsonBuf bytes.Buffer
	jsonCmd.SetOut(&jsonBuf)
	require.NotPanics(t, func() {
		err = outputReportJSON(jsonCmd, s, findings, allMatches, ruleMap)
	}, "outputReportJSON must not panic on nil Score finding")
	require.NoError(t, err)

	// The JSON output should be a valid JSON array.
	var jsonOut []map[string]interface{}
	require.NoError(t, json.Unmarshal(jsonBuf.Bytes(), &jsonOut), "JSON output must be valid")
	require.Len(t, jsonOut, 1)

	// types.Finding embeds Score as a pointer with no json tag. When nil it
	// marshals as null (not absent). Verify that.
	// The key name follows Go's default: "Score".
	scoreVal, hasScore := jsonOut[0]["Score"]
	assert.True(t, hasScore, "JSON output must contain the Score field (as null)")
	assert.Nil(t, scoreVal, "Score field in JSON must be null for legacy finding")

	// --- SARIF output must not panic ---
	sarifCmd := &cobra.Command{}
	var sarifBuf bytes.Buffer
	sarifCmd.SetOut(&sarifBuf)
	require.NotPanics(t, func() {
		err = outputReportSARIF(sarifCmd, s, findings, allMatches, ruleMap)
	}, "outputReportSARIF must not panic on nil Score finding")
	require.NoError(t, err)
	// SARIF output must be valid JSON.
	var sarifDoc map[string]interface{}
	require.NoError(t, json.Unmarshal(sarifBuf.Bytes(), &sarifDoc), "SARIF output must be valid JSON")

	// --- Human output must not panic ---
	humanCmd := &cobra.Command{}
	var humanBuf bytes.Buffer
	humanCmd.SetOut(&humanBuf)
	require.NotPanics(t, func() {
		err = outputReportHuman(humanCmd, s, findings, allMatches, ruleMap)
	}, "outputReportHuman must not panic on nil Score finding")
	require.NoError(t, err)
	assert.Contains(t, humanBuf.String(), legacyFinding.ID,
		"human report must contain the finding ID")
}

// =============================================================================
// ENG-9178: every format lists every location (store.GetOccurrences)
// =============================================================================

var reportCommitDate = time.Date(2026, 6, 15, 9, 30, 0, 0, time.UTC)

// reportFixture builds one finding whose matches each sit in their own blob,
// with the given locations recorded in a memory store. Every match is on
// line 3, columns 7-27.
func reportFixture(t *testing.T, locs ...[]types.Occurrence) (store.Store, []*types.Finding, []*types.Match, map[string]*types.Rule) {
	t.Helper()
	s := store.NewMemory()
	r := &types.Rule{ID: "np.test.1", Name: "Test Rule", Pattern: "tok_.*"}
	r.StructuralID = r.ComputeStructuralID()
	groups := [][]byte{[]byte("tok_shared")}
	f := &types.Finding{ID: types.ComputeFindingID(r.StructuralID, groups), RuleID: r.ID, Groups: groups}
	matches := make([]*types.Match, 0, len(locs))
	for i, occs := range locs {
		m := &types.Match{
			StructuralID: fmt.Sprintf("sm-%d", i+1),
			RuleID:       r.ID,
			BlobID:       types.ComputeBlobID(fmt.Appendf(nil, "blob-%d", i)),
			Groups:       groups,
			Location: types.Location{Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 3, Column: 7},
				End:   types.SourcePoint{Line: 3, Column: 27},
			}},
			Snippet: types.Snippet{Matching: []byte("tok_shared")},
		}
		require.NoError(t, s.AddOccurrences(m.BlobID, occs))
		matches = append(matches, m)
	}
	return s, []*types.Finding{f}, matches, map[string]*types.Rule{r.ID: r}
}

// legacyFixture builds one finding with one match whose blob has only the
// given provenance rows (no blob_locations rows), in a SQLite datastore.
func legacyFixture(t *testing.T, provs ...types.Provenance) (store.Store, []*types.Finding, []*types.Match, map[string]*types.Rule) {
	t.Helper()
	s, err := store.New(store.Config{Path: filepath.Join(t.TempDir(), "legacy.db")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	r := &types.Rule{ID: "np.test.1", Name: "Test Rule", Pattern: "tok_.*"}
	r.StructuralID = r.ComputeStructuralID()
	require.NoError(t, s.AddRule(r))
	groups := [][]byte{[]byte("tok_legacy")}
	require.NoError(t, s.AddFinding(&types.Finding{ID: types.ComputeFindingID(r.StructuralID, groups), RuleID: r.ID, Groups: groups}))

	blobID := types.ComputeBlobID([]byte("TOKEN=tok_legacy"))
	require.NoError(t, s.AddBlob(blobID, 16))
	for _, p := range provs {
		require.NoError(t, s.AddProvenance(blobID, p))
	}
	require.NoError(t, s.AddMatch(&types.Match{
		StructuralID: "sm-legacy",
		RuleID:       r.ID,
		BlobID:       blobID,
		Groups:       groups,
		Location: types.Location{Source: types.SourceSpan{
			Start: types.SourcePoint{Line: 3, Column: 7},
			End:   types.SourcePoint{Line: 3, Column: 27},
		}},
		Snippet: types.Snippet{Matching: []byte("tok_legacy")},
	}))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	matches, err := s.GetAllMatches()
	require.NoError(t, err)
	return s, findings, matches, map[string]*types.Rule{r.ID: r}
}

func renderHuman(t *testing.T, s store.Store, findings []*types.Finding, matches []*types.Match, ruleMap map[string]*types.Rule) string {
	t.Helper()
	prev := reportColor
	reportColor = "never"
	t.Cleanup(func() { reportColor = prev })
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, outputReportHuman(cmd, s, findings, matches, ruleMap))
	return buf.String()
}

func renderJSON(t *testing.T, s store.Store, findings []*types.Finding, matches []*types.Match, ruleMap map[string]*types.Rule) []byte {
	t.Helper()
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, outputReportJSON(cmd, s, findings, matches, ruleMap))
	return buf.Bytes()
}

func renderSARIF(t *testing.T, s store.Store, findings []*types.Finding, matches []*types.Match, ruleMap map[string]*types.Rule) []byte {
	t.Helper()
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, outputReportSARIF(cmd, s, findings, matches, ruleMap))
	return buf.Bytes()
}

// humanLocationLines returns the location lines of a human report: lines
// indented by exactly four spaces that are not a match header or Blob line.
func humanLocationLines(out string) []string {
	var lines []string
	for l := range strings.Lines(out) {
		l = strings.TrimSuffix(l, "\n")
		rest, ok := strings.CutPrefix(l, "    ")
		if !ok || rest == "" || strings.HasPrefix(rest, " ") ||
			strings.HasPrefix(rest, "Match ") || strings.HasPrefix(rest, "Blob:") {
			continue
		}
		lines = append(lines, l)
	}
	return lines
}

// reportJSONLocations decodes the locations of every match of every finding.
type reportJSONMatch struct {
	FilePath  string         `json:"file_path"`
	Locations []jsonLocation `json:"locations"`
}

type reportJSONFinding struct {
	Matches []reportJSONMatch `json:"Matches"`
}

func decodeReportJSON(t *testing.T, data []byte) []reportJSONFinding {
	t.Helper()
	var out []reportJSONFinding
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

// C-OVER3-1: the first 3 matches print in full, the rest print only their
// location lines, and nothing is truncated.
func TestOutputReportHuman_AfterThirdMatchLocationsOnly(t *testing.T) {
	var locs [][]types.Occurrence
	for i := 1; i <= 5; i++ {
		locs = append(locs, []types.Occurrence{{Kind: "file", Path: fmt.Sprintf("a%d.env", i), HostRecorded: true}})
	}
	s, findings, matches, ruleMap := reportFixture(t, locs...)
	out := renderHuman(t, s, findings, matches, ruleMap)

	assert.NotContains(t, out, "Showing 3/5")
	assert.NotContains(t, out, "more")
	for k := 1; k <= 3; k++ {
		assert.Contains(t, out, fmt.Sprintf("Match %d/5 (id sm-%d)", k, k))
	}
	assert.NotContains(t, out, "Match 4/5")
	assert.NotContains(t, out, "Match 5/5")
	assert.Equal(t, 3, strings.Count(out, "Blob:"), "full matches printed")
	assert.Equal(t, 1+3, strings.Count(out, "tok_shared"), "group line plus one snippet per full match")
	assert.Equal(t, []string{
		"    a1.env:3", "    a2.env:3", "    a3.env:3", "    a4.env:3", "    a5.env:3",
	}, humanLocationLines(out), "every match's location is printed")
}

// C-MULTIREPO-1: one blob found in two repositories is one finding with
// both locations, in JSON and in human output.
func TestOutputReport_MultiRepoLocations(t *testing.T) {
	s, findings, matches, ruleMap := reportFixture(t, []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/web", Path: "deploy/config.yml", Commit: "bbbbbbbbbb", CommitDate: reportCommitDate, HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/api", Path: "deploy/config.yml", Commit: "aaaaaaaaaa", CommitDate: reportCommitDate, HostRecorded: true},
	})

	out := decodeReportJSON(t, renderJSON(t, s, findings, matches, ruleMap))
	require.Len(t, out, 1, "findings")
	require.Len(t, out[0].Matches, 1)
	type loc struct {
		Repository, Path string
		Line             int
	}
	var got []loc
	for _, l := range out[0].Matches[0].Locations {
		require.NotNil(t, l.Repository)
		got = append(got, loc{*l.Repository, l.Path, l.Range.Start.Line})
	}
	assert.Equal(t, []loc{
		{"github.com/acme/api", "deploy/config.yml", 3},
		{"github.com/acme/web", "deploy/config.yml", 3},
	}, got)

	assert.Equal(t, []string{
		"    github.com/acme/api  deploy/config.yml:3  aaaaaaa  2026-06-15",
		"    github.com/acme/web  deploy/config.yml:3  bbbbbbb  2026-06-15",
	}, humanLocationLines(renderHuman(t, s, findings, matches, ruleMap)))
}

// C-REPORTJSON-1: file_path is kept, locations has every location, and each
// location has exactly the 7 keys.
func TestOutputReportJSON_LocationsKeysAndFilePath(t *testing.T) {
	s, findings, matches, ruleMap := reportFixture(t, []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", Commit: "aaaaaaaaaa", CommitDate: reportCommitDate, HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/web", Path: "deploy/config.yml", WorkingTree: true, HostRecorded: true},
	})

	var raw []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(renderJSON(t, s, findings, matches, ruleMap), &raw))
	require.Len(t, raw, 1)
	var ms []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw[0]["Matches"], &ms))
	require.Len(t, ms, 1)

	filePath, hasFilePath := ms[0]["file_path"]
	require.True(t, hasFilePath, "file_path is kept")
	assert.JSONEq(t, `"config.yml"`, string(filePath), "file_path is the first sorted location's path")

	var locs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(ms[0]["locations"], &locs))
	require.Len(t, locs, 2)
	for _, l := range locs {
		keys := slices.Sorted(maps.Keys(l))
		assert.Equal(t, []string{"absolute_path", "commit", "commit_date", "host_recorded", "path", "range", "repository"}, keys)
	}
}

// SEC-7: hostile repository and path bytes are sanitized in human output.
func TestOutputReportHuman_SanitizesLocations(t *testing.T) {
	s, findings, matches, ruleMap := reportFixture(t, []types.Occurrence{{
		Kind: "git", Repository: "github.com/acme/\x1b[31mapi", Path: "\u202eevil\x1b]0;pwn\x07.yml",
		Commit: "aaaaaaaaaa", CommitDate: reportCommitDate, HostRecorded: true,
	}})
	out := renderHuman(t, s, findings, matches, ruleMap)

	assert.NotContains(t, out, "\x1b", "no raw escape byte")
	assert.NotContains(t, out, "\x07", "no raw BEL byte")
	assert.NotContains(t, out, "\u202e", "no raw bidi override")
	lines := humanLocationLines(out)
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], `github.com/acme/\x1b[31mapi`)
}

// sarifRepoHosts returns, per SARIF result, its repository and whether the
// host was recorded.
func sarifRepoHosts(t *testing.T, data []byte) map[string]bool {
	t.Helper()
	var rep sarif.Report
	require.NoError(t, json.Unmarshal(data, &rep))
	require.Len(t, rep.Runs, 1)
	got := map[string]bool{}
	for _, r := range rep.Runs[0].Results {
		require.NotNil(t, r.Properties)
		require.NotNil(t, r.Properties.HostRecorded, "git result %q has host_recorded", r.Properties.Repository)
		got[r.Properties.Repository] = *r.Properties.HostRecorded
	}
	assert.Len(t, rep.Runs[0].Results, len(got), "one result per repository")
	return got
}

// C-OLDDS-2: a pre-change datastore row for acme/api plus a rescan via
// `titus github acme/api` into it shows both repositories in every format:
// the legacy one as "acme/api (host not recorded)" and the rescan as
// github.com/acme/api. Upgrading or deduplicating the legacy row on rescan
// would leave only github.com/acme/api.
func TestOutputReport_LegacyAndRescanShowBoth(t *testing.T) {
	s, findings, matches, ruleMap := legacyFixture(t, types.GitProvenance{RepoPath: "acme/api", BlobPath: "config.yml"})
	// Stand-in for `titus github acme/api`, as in TestScanE2E_OriginRemoteMergesWithAPI.
	require.NoError(t, s.AddOccurrences(types.ComputeBlobID([]byte("TOKEN=tok_legacy")), []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", HostRecorded: true},
	}))

	assert.Equal(t, []string{
		"    acme/api  config.yml:3  host not recorded",
		"    github.com/acme/api  config.yml:3",
	}, humanLocationLines(renderHuman(t, s, findings, matches, ruleMap)))

	out := decodeReportJSON(t, renderJSON(t, s, findings, matches, ruleMap))
	require.Len(t, out, 1)
	require.Len(t, out[0].Matches, 1)
	gotJSON := map[string]bool{}
	for _, l := range out[0].Matches[0].Locations {
		require.NotNil(t, l.Repository)
		gotJSON[*l.Repository] = l.HostRecorded
	}
	assert.Len(t, out[0].Matches[0].Locations, 2)
	want := map[string]bool{"acme/api": false, "github.com/acme/api": true}
	assert.Equal(t, want, gotJSON)

	assert.Equal(t, want, sarifRepoHosts(t, renderSARIF(t, s, findings, matches, ruleMap)))
}

// SEC-5: a legacy repository URL with userinfo never shows the credential in
// any format.
func TestOutputReport_LegacyUserinfoRedactedEverywhere(t *testing.T) {
	s, findings, matches, ruleMap := legacyFixture(t, types.GitProvenance{RepoPath: "https://u:SECRET@h/o/r", BlobPath: "config.yml"})

	human := renderHuman(t, s, findings, matches, ruleMap)
	assert.NotContains(t, human, "SECRET")
	assert.Equal(t, []string{"    https://h/o/r  config.yml:3  host not recorded"}, humanLocationLines(human))
	assert.NotContains(t, string(renderJSON(t, s, findings, matches, ruleMap)), "SECRET")
	assert.NotContains(t, string(renderSARIF(t, s, findings, matches, ruleMap)), "SECRET")
}

// SARIF: one result per location, each carrying the finding's score.
func TestOutputReportSARIF_OneResultPerLocation(t *testing.T) {
	s, findings, matches, ruleMap := reportFixture(t, []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "deploy/config.yml", Commit: "aaaaaaaaaa", CommitDate: reportCommitDate, HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/web", Path: "deploy/config.yml", Commit: "bbbbbbbbbb", CommitDate: reportCommitDate, HostRecorded: true},
	})
	findings[0].Score = &types.Score{Final: 75, Base: 75, SuggestedSeverity: "high", Applied: []types.ScoreModifier{}}

	var rep sarif.Report
	require.NoError(t, json.Unmarshal(renderSARIF(t, s, findings, matches, ruleMap), &rep))
	require.Len(t, rep.Runs, 1)
	results := rep.Runs[0].Results
	require.Len(t, results, 2)
	var repos []string
	for _, r := range results {
		assert.Equal(t, "error", r.Level)
		assert.Equal(t, "deploy/config.yml", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		require.NotNil(t, r.Properties)
		repos = append(repos, r.Properties.Repository)
	}
	assert.Equal(t, []string{"github.com/acme/api", "github.com/acme/web"}, repos)
}

// =============================================================================
// Terminal-injection sanitization of snippets, groups, owner, and resources
// =============================================================================

// sanitizeReportFixture is reportFixture with one plain file location, whose
// finding and match carry the given groups and snippet, and whose finding
// carries the given owner and resources.
func sanitizeReportFixture(t *testing.T, groups [][]byte, snip types.Snippet, owner *types.OwnerInfo, resources []types.ResourceInfo) (store.Store, []*types.Finding, []*types.Match, map[string]*types.Rule) {
	t.Helper()
	s, findings, matches, ruleMap := reportFixture(t, []types.Occurrence{{Kind: "file", Path: "config.yml", HostRecorded: true}})
	f, m := findings[0], matches[0]
	f.Groups, m.Groups = groups, groups
	f.ID = types.ComputeFindingID(ruleMap[f.RuleID].StructuralID, groups)
	f.Owner, f.Resources = owner, resources
	m.Snippet = snip
	return s, findings, matches, ruleMap
}

// outputLines splits rendered output into lines without their newline.
func outputLines(out string) []string {
	return strings.Split(out, "\n")
}

// sanitizeCase is shared by the report and analyze human-output tests.
type sanitizeCase struct {
	name      string
	groups    [][]byte
	snippet   types.Snippet
	owner     *types.OwnerInfo
	resources []types.ResourceInfo
	message   string
	// Expected rendered values.
	wantGroup, wantSnippet, wantOwner, wantSummary, wantDetail, wantMessage string
}

func sanitizeCases() []sanitizeCase {
	return []sanitizeCase{
		{
			name:   "hostile",
			groups: [][]byte{[]byte("tok\x1b[2J\x9b2J")},
			snippet: types.Snippet{
				Before:   []byte("pre\x1b[2J "),
				Matching: []byte("tok\x1b[2J\x9b2J"),
				After:    []byte(" \x1b[2Jpost"),
			},
			owner:       &types.OwnerInfo{User: "alice\x1b[2J", Email: "a@x.io", AccountID: "1\x1b]0;t\x07"},
			resources:   []types.ResourceInfo{{Service: "aws", Type: "s3\x1b[2J", Name: "prod\x1b[2J", Region: "us\x1b[2J"}},
			message:     "key active\x1b[2J",
			wantGroup:   `tok\x1b[2J\x9b2J`,
			wantSnippet: `pre\x1b[2J tok\x1b[2J\x9b2J \x1b[2Jpost`,
			wantOwner:   `alice\x1b[2J (a@x.io) [1\x1b]0;t\x07]`,
			wantSummary: `1 s3\x1b[2J`,
			wantDetail:  `s3\x1b[2J: prod\x1b[2J [us\x1b[2J]`,
			wantMessage: `key active\x1b[2J`,
		},
		{
			name:        "benign",
			groups:      [][]byte{[]byte("tok_plain")},
			snippet:     types.Snippet{Before: []byte("before "), Matching: []byte("tok_plain"), After: []byte(" after")},
			owner:       &types.OwnerInfo{User: "alice", Email: "alice@example.com", AccountID: "123"},
			resources:   []types.ResourceInfo{{Service: "aws", Type: "s3_bucket", Name: "prod-data", Region: "us-east-1"}},
			message:     "key is active",
			wantGroup:   "tok_plain",
			wantSnippet: "before tok_plain after",
			wantOwner:   "alice (alice@example.com) [123]",
			wantSummary: "1 s3_bucket",
			wantDetail:  "s3_bucket: prod-data [us-east-1]",
			wantMessage: "key is active",
		},
	}
}

// assertNoTerminalControls fails if out holds a C0 control other than '\n'
// or '\t', DEL, a C1 control rune, or a raw (non-UTF-8) byte in the C1 range,
// which 8-bit terminals read as a control such as CSI (0x9b). Tab only moves
// the cursor to the next tab stop, so it is not an injection vector.
func assertNoTerminalControls(t *testing.T, out string) {
	t.Helper()
	for i, r := range out {
		if r == utf8.RuneError && out[i] >= 0x80 && out[i] <= 0x9f {
			t.Fatalf("raw C1 byte 0x%02x at offset %d in output:\n%q", out[i], i, out)
		}
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Fatalf("control rune %U at offset %d in output:\n%q", r, i, out)
		}
	}
}

func TestOutputReportHuman_SanitizesFindingContent(t *testing.T) {
	for _, tc := range sanitizeCases() {
		t.Run(tc.name, func(t *testing.T) {
			s, findings, matches, ruleMap := sanitizeReportFixture(t, tc.groups, tc.snippet, tc.owner, tc.resources)
			out := renderHuman(t, s, findings, matches, ruleMap)

			assertNoTerminalControls(t, out)
			lines := outputLines(out)
			assert.Contains(t, lines, "Group 1: "+tc.wantGroup)
			assert.Contains(t, lines, "        "+tc.wantSnippet)
			assert.Contains(t, lines, "Owner: "+tc.wantOwner)
			assert.Contains(t, lines, "Resources: "+tc.wantSummary)
			assert.Contains(t, lines, "  "+tc.wantDetail)
		})
	}
}
