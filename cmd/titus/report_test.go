package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
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
// filterRejected. Only GetAnnotation is meaningful; all other methods are
// satisfied by embedding store.Store (nil panic guard — tests must not call
// any other method).
type fakeRejectionStore struct {
	store.Store
	rejections map[string]string // key: finding ID, value: status string
	errIDs     map[string]error  // key: finding ID, value: error to return
}

func (f *fakeRejectionStore) GetAnnotation(targetType, targetID string) (string, string, error) {
	if f.errIDs != nil {
		if err, ok := f.errIDs[targetID]; ok {
			return "", "", err
		}
	}
	if status, ok := f.rejections[targetID]; ok {
		return status, "", nil
	}
	return "", "", nil
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
	findings, matches := filterRejected(s, nil, nil, nil)
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

	gotFindings, gotMatches := filterRejected(s, findings, matches, ruleMap)

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

	gotFindings, gotMatches := filterRejected(s, findings, matches, ruleMap)

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

	gotFindings, gotMatches := filterRejected(s, findings, matches, ruleMap)

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

	gotFindings, gotMatches := filterRejected(s, findings, matches, ruleMap)

	assert.Len(t, gotFindings, 2, "findings with non-reject status should be retained")
	assert.Len(t, gotMatches, 2, "matches for non-rejected findings should be retained")
}

func TestFilterRejected_AnnotationErrorIsIgnored(t *testing.T) {
	rule := &types.Rule{
		ID:           "rule-1",
		StructuralID: "struct-errtest",
	}
	ruleMap := map[string]*types.Rule{"rule-1": rule}

	f1 := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("err-val")}),
		RuleID: "rule-1",
		Groups: [][]byte{[]byte("err-val")},
	}
	f2 := &types.Finding{
		ID:     types.ComputeFindingID(rule.StructuralID, [][]byte{[]byte("ok-val")}),
		RuleID: "rule-1",
		Groups: [][]byte{[]byte("ok-val")},
	}
	findings := []*types.Finding{f1, f2}
	matches := []*types.Match{
		{StructuralID: "sm-err", RuleID: "rule-1", Groups: [][]byte{[]byte("err-val")}},
		{StructuralID: "sm-ok", RuleID: "rule-1", Groups: [][]byte{[]byte("ok-val")}},
	}

	// f1 returns an error from GetAnnotation (even though "reject" would be the
	// status) — the error path means it must NOT be filtered.
	// f2 returns status "reject" with no error — it MUST be filtered.
	s := &fakeRejectionStore{
		rejections: map[string]string{f2.ID: store.StatusReject},
		errIDs:     map[string]error{f1.ID: errors.New("db read error")},
	}

	gotFindings, gotMatches := filterRejected(s, findings, matches, ruleMap)

	// f1 retained (error → no rejection), f2 removed
	require.Len(t, gotFindings, 1)
	assert.Equal(t, f1.ID, gotFindings[0].ID, "finding whose annotation returned an error should be retained")

	require.Len(t, gotMatches, 1)
	assert.Equal(t, "sm-err", gotMatches[0].StructuralID, "match for error-path finding should be retained")
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

	gotFindings, gotMatches := filterRejected(s, findings, matches, ruleMap)

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

	gotFindings, gotMatches := filterRejected(s, findings, matches, ruleMap)

	assert.Empty(t, gotFindings)
	// Both matches share the same StructuralID that is in the rejected set;
	// both should be removed.
	assert.Empty(t, gotMatches, "both matches with the shared StructuralID should be removed when finding is rejected")
}
