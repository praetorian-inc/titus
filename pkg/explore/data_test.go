package explore

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func TestBuildFindingRow(t *testing.T) {
	rule := &types.Rule{
		ID:         "np.aws.1",
		Name:       "AWS API Key",
		Categories: []string{"cloud", "aws"},
	}
	rule.StructuralID = rule.ComputeStructuralID()

	ruleMap := map[string]*types.Rule{"np.aws.1": rule}

	finding := &types.Finding{
		ID:     "test-finding-id",
		RuleID: "np.aws.1",
		Groups: [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")},
	}

	matches := []*types.Match{
		{
			StructuralID: "match-1",
			RuleID:       "np.aws.1",
			RuleName:     "AWS API Key",
			Snippet:      types.Snippet{Matching: []byte("AKIAIOSFODNN7EXAMPLE")},
			ValidationResult: &types.ValidationResult{
				Status:     types.StatusValid,
				Confidence: 0.95,
				Message:    "Active credential",
			},
		},
		{
			StructuralID: "match-2",
			RuleID:       "np.aws.1",
			RuleName:     "AWS API Key",
			Snippet:      types.Snippet{Matching: []byte("AKIAIOSFODNN7EXAMPLE")},
			ValidationResult: &types.ValidationResult{
				Status:     types.StatusValid,
				Confidence: 0.90,
				Message:    "Active credential",
			},
		},
	}

	row := buildFindingRow(finding, matches, ruleMap, nil)

	if row.RuleName != "AWS API Key" {
		t.Errorf("expected rule name 'AWS API Key', got '%s'", row.RuleName)
	}
	if row.MatchCount != 2 {
		t.Errorf("expected 2 matches, got %d", row.MatchCount)
	}
	if row.ValidationStatus != "valid" {
		t.Errorf("expected validation 'valid', got '%s'", row.ValidationStatus)
	}
	if row.Confidence < 0.92 || row.Confidence > 0.93 {
		t.Errorf("expected mean confidence ~0.925, got %f", row.Confidence)
	}
	if len(row.Categories) != 2 {
		t.Errorf("expected 2 categories, got %d", len(row.Categories))
	}
	if len(row.Matches) != 2 {
		t.Errorf("expected 2 match rows, got %d", len(row.Matches))
	}
}

func TestBuildMatchRow(t *testing.T) {
	match := &types.Match{
		StructuralID: "match-1",
		BlobID:       types.BlobID{},
		RuleName:     "AWS API Key",
		Location: types.Location{
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 10, Column: 5},
				End:   types.SourcePoint{Line: 10, Column: 25},
			},
		},
		NamedGroups: map[string][]byte{
			"token": []byte("AKIAIOSFODNN7EXAMPLE"),
		},
		Snippet: types.Snippet{
			Before:   []byte("key = "),
			Matching: []byte("AKIAIOSFODNN7EXAMPLE"),
			After:    []byte("\n"),
		},
		ValidationResult: &types.ValidationResult{
			Status:     types.StatusValid,
			Confidence: 0.95,
			Message:    "Active credential",
		},
	}

	row := buildMatchRow(match, nil)

	if row.ValidationStatus != "valid" {
		t.Errorf("expected validation 'valid', got '%s'", row.ValidationStatus)
	}
	if row.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", row.Confidence)
	}
	if row.Message != "Active credential" {
		t.Errorf("expected message 'Active credential', got '%s'", row.Message)
	}
	if len(row.NamedGroups) != 1 {
		t.Errorf("expected 1 named group, got %d", len(row.NamedGroups))
	}
	if string(row.NamedGroups["token"]) != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("expected token group value 'AKIAIOSFODNN7EXAMPLE'")
	}
}

func TestFormatGroups(t *testing.T) {
	tests := []struct {
		groups   [][]byte
		expected string
	}{
		{nil, ""},
		{[][]byte{[]byte("val1")}, "val1"},
		{[][]byte{[]byte("val1"), []byte("val2")}, "val1, val2"},
	}

	for _, tt := range tests {
		result := formatGroups(tt.groups)
		if result != tt.expected {
			t.Errorf("formatGroups(%v) = %q, want %q", tt.groups, result, tt.expected)
		}
	}
}

func TestRenderValidationStatus(t *testing.T) {
	// Just ensure these don't panic
	renderValidationStatus("valid")
	renderValidationStatus("invalid")
	renderValidationStatus("undetermined")
	renderValidationStatus("")
}

func TestRenderAnnotationStatus(t *testing.T) {
	// Just ensure these don't panic
	renderAnnotationStatus("accept")
	renderAnnotationStatus("reject")
	renderAnnotationStatus("")
}

// TestGroupMatchesByFinding_CustomRule verifies that matches for custom
// rules (not present in ruleMap) are still grouped onto their findings via
// the RuleID + Groups fallback. Regression test for the bug where the
// explore TUI rendered "No matches" for custom-rule findings.
func TestGroupMatchesByFinding_CustomRule(t *testing.T) {
	// Custom rule: deliberately NOT inserted into ruleMap, mimicking a
	// rule loaded via --rules at scan time.
	finding := &types.Finding{
		ID:     "finding-custom-1",
		RuleID: "ps.cred.1",
		Groups: [][]byte{[]byte("supersecret")},
	}

	matches := []*types.Match{
		{
			StructuralID: "match-a",
			RuleID:       "ps.cred.1",
			RuleName:     "PowerShell Hardcoded Credential",
			Groups:       [][]byte{[]byte("supersecret")},
		},
		{
			StructuralID: "match-b",
			RuleID:       "ps.cred.1",
			RuleName:     "PowerShell Hardcoded Credential",
			Groups:       [][]byte{[]byte("supersecret")},
		},
		{
			// Different groups — must not be paired with the finding.
			StructuralID: "match-c",
			RuleID:       "ps.cred.1",
			RuleName:     "PowerShell Hardcoded Credential",
			Groups:       [][]byte{[]byte("other")},
		},
	}

	ruleMap := map[string]*types.Rule{} // empty: custom rule not in builtins

	got := groupMatchesByFinding([]*types.Finding{finding}, matches, ruleMap)

	paired := got[finding.ID]
	if len(paired) != 2 {
		t.Fatalf("expected 2 matches paired with custom-rule finding, got %d", len(paired))
	}
	if paired[0].StructuralID != "match-a" || paired[1].StructuralID != "match-b" {
		t.Errorf("unexpected matches paired: %+v", paired)
	}

	// Sanity: buildFindingRow surfaces the friendly name from m.RuleName
	// when the rule is missing from ruleMap.
	row := buildFindingRow(finding, paired, ruleMap, nil)
	if row.RuleName != "PowerShell Hardcoded Credential" {
		t.Errorf("expected RuleName fallback to match-record RuleName, got %q", row.RuleName)
	}
	if row.MatchCount != 2 {
		t.Errorf("expected MatchCount=2, got %d", row.MatchCount)
	}
}

// TestGroupMatchesByFinding_BuiltinFastPath verifies that builtin rules
// (present in ruleMap) continue to flow through the structural-ID fast
// path and are grouped correctly.
func TestGroupMatchesByFinding_BuiltinFastPath(t *testing.T) {
	r := &types.Rule{
		ID:   "np.aws.1",
		Name: "AWS API Key",
	}
	r.StructuralID = r.ComputeStructuralID()
	ruleMap := map[string]*types.Rule{r.ID: r}

	groups := [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")}
	findingID := types.ComputeFindingID(r.StructuralID, groups)

	finding := &types.Finding{
		ID:     findingID,
		RuleID: r.ID,
		Groups: groups,
	}

	matches := []*types.Match{
		{StructuralID: "m1", RuleID: r.ID, RuleName: r.Name, Groups: groups},
		{StructuralID: "m2", RuleID: r.ID, RuleName: r.Name, Groups: groups},
	}

	got := groupMatchesByFinding([]*types.Finding{finding}, matches, ruleMap)
	if len(got[finding.ID]) != 2 {
		t.Fatalf("expected 2 matches via fast path, got %d", len(got[finding.ID]))
	}
}

// TestGroupMatchesByFinding_MixedBuiltinAndCustom verifies that a datastore
// containing both builtin-rule findings and custom-rule findings is handled
// correctly: builtin findings use the structural-ID fast path; custom findings
// fall back to RuleID + Groups matching. The two passes must not interfere.
func TestGroupMatchesByFinding_MixedBuiltinAndCustom(t *testing.T) {
	// Builtin rule — present in ruleMap.
	builtin := &types.Rule{ID: "np.aws.6", Name: "AWS API Credentials"}
	builtin.StructuralID = builtin.ComputeStructuralID()
	ruleMap := map[string]*types.Rule{builtin.ID: builtin}

	builtinGroups := [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE"), []byte("secret")}
	builtinFindingID := types.ComputeFindingID(builtin.StructuralID, builtinGroups)

	builtinFinding := &types.Finding{
		ID:     builtinFindingID,
		RuleID: builtin.ID,
		Groups: builtinGroups,
	}

	// Custom rule — NOT in ruleMap.
	customFinding := &types.Finding{
		ID:     "custom-finding-1",
		RuleID: "acme.token.1",
		Groups: [][]byte{[]byte("ABCDEFGHIJKLMNOP1234567890ABCDEF")},
	}

	matches := []*types.Match{
		// Builtin match.
		{StructuralID: "builtin-m1", RuleID: builtin.ID, RuleName: builtin.Name, Groups: builtinGroups},
		// Custom match.
		{StructuralID: "custom-m1", RuleID: "acme.token.1", RuleName: "ACME Token", Groups: [][]byte{[]byte("ABCDEFGHIJKLMNOP1234567890ABCDEF")}},
		// Unrelated match (different groups) — must not be paired with custom finding.
		{StructuralID: "custom-m2", RuleID: "acme.token.1", RuleName: "ACME Token", Groups: [][]byte{[]byte("other")}},
	}

	got := groupMatchesByFinding([]*types.Finding{builtinFinding, customFinding}, matches, ruleMap)

	if len(got[builtinFinding.ID]) != 1 || got[builtinFinding.ID][0].StructuralID != "builtin-m1" {
		t.Errorf("builtin finding: expected 1 match 'builtin-m1', got %+v", got[builtinFinding.ID])
	}
	if len(got[customFinding.ID]) != 1 || got[customFinding.ID][0].StructuralID != "custom-m1" {
		t.Errorf("custom finding: expected 1 match 'custom-m1', got %+v", got[customFinding.ID])
	}
}

// TestGroupMatchesByFinding_FastPathNotOverwrittenByFallback verifies that a
// finding already resolved via the structural-ID fast path is not re-processed
// by the RuleID+Groups fallback. Regression guard for the fast-path skip check
// in groupMatchesByFinding.
func TestGroupMatchesByFinding_FastPathNotOverwrittenByFallback(t *testing.T) {
	r := &types.Rule{ID: "np.github.1", Name: "GitHub Token"}
	r.StructuralID = r.ComputeStructuralID()
	ruleMap := map[string]*types.Rule{r.ID: r}

	groups := [][]byte{[]byte("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}
	findingID := types.ComputeFindingID(r.StructuralID, groups)

	finding := &types.Finding{
		ID:     findingID,
		RuleID: r.ID,
		Groups: groups,
	}

	matches := []*types.Match{
		// This match is resolved by the fast path.
		{StructuralID: "fast-m1", RuleID: r.ID, RuleName: r.Name, Groups: groups},
	}

	got := groupMatchesByFinding([]*types.Finding{finding}, matches, ruleMap)

	// Fast path sets matchesByFinding[findingID] = [fast-m1].
	// Fallback must skip this finding (it already has matches) and not
	// append fast-m1 a second time.
	paired := got[finding.ID]
	if len(paired) != 1 {
		t.Fatalf("expected exactly 1 match (no duplicate from fallback), got %d", len(paired))
	}
	if paired[0].StructuralID != "fast-m1" {
		t.Errorf("expected 'fast-m1', got %q", paired[0].StructuralID)
	}
}
