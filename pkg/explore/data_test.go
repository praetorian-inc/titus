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
