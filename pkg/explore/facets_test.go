package explore

import (
	"testing"
)

func TestBuildFacets(t *testing.T) {
	findings := []*findingRow{
		{RuleName: "AWS API Key", Categories: []string{"cloud", "aws"}, ValidationStatus: "valid"},
		{RuleName: "AWS API Key", Categories: []string{"cloud", "aws"}, ValidationStatus: "invalid"},
		{RuleName: "GitHub Token", Categories: []string{"scm"}, ValidationStatus: "valid"},
	}

	fs := buildFacets(findings)

	// Check rule name facet
	ruleNames := fs.Values[facetRuleName]
	if len(ruleNames) != 2 {
		t.Errorf("expected 2 rule names, got %d", len(ruleNames))
	}

	// Check category facet
	cats := fs.Values[facetCategory]
	if len(cats) != 3 { // aws, cloud, scm
		t.Errorf("expected 3 categories, got %d", len(cats))
	}

	// Check validation facet
	vals := fs.Values[facetValidation]
	if len(vals) != 2 { // valid, invalid
		t.Errorf("expected 2 validation statuses, got %d", len(vals))
	}
}

func TestFacetFiltering(t *testing.T) {
	findings := []*findingRow{
		{RuleName: "AWS API Key", Categories: []string{"cloud"}, ValidationStatus: "valid"},
		{RuleName: "GitHub Token", Categories: []string{"scm"}, ValidationStatus: "invalid"},
		{RuleName: "Slack Token", Categories: []string{"chat"}, ValidationStatus: "valid"},
	}

	fs := buildFacets(findings)

	// No filters - all match
	for _, f := range findings {
		if !fs.matchesFinding(f) {
			t.Errorf("expected %s to match with no filters", f.RuleName)
		}
	}

	// Select "valid" in validation facet
	for _, v := range fs.Values[facetValidation] {
		if v.Value == "valid" {
			v.Selected = true
		}
	}

	// Only valid findings should match
	if !fs.matchesFinding(findings[0]) { // AWS - valid
		t.Error("expected AWS to match valid filter")
	}
	if fs.matchesFinding(findings[1]) { // GitHub - invalid
		t.Error("expected GitHub to NOT match valid filter")
	}
	if !fs.matchesFinding(findings[2]) { // Slack - valid
		t.Error("expected Slack to match valid filter")
	}
}

func TestFacetReset(t *testing.T) {
	findings := []*findingRow{
		{RuleName: "Test", Categories: []string{"cat"}, ValidationStatus: "valid"},
	}
	fs := buildFacets(findings)

	// Select a value
	fs.Values[facetValidation][0].Selected = true
	if !fs.hasActiveFilters() {
		t.Error("expected active filters after selection")
	}

	// Reset
	fs.resetAll()
	if fs.hasActiveFilters() {
		t.Error("expected no active filters after reset")
	}
}

func TestFacetCrossFacetFiltering(t *testing.T) {
	findings := []*findingRow{
		{RuleName: "AWS API Key", Categories: []string{"cloud"}, ValidationStatus: "valid"},
		{RuleName: "GitHub Token", Categories: []string{"cloud"}, ValidationStatus: "invalid"},
		{RuleName: "Slack Token", Categories: []string{"chat"}, ValidationStatus: "valid"},
	}

	fs := buildFacets(findings)

	// Select "cloud" category AND "valid" validation (intersection)
	for _, v := range fs.Values[facetCategory] {
		if v.Value == "cloud" {
			v.Selected = true
		}
	}
	for _, v := range fs.Values[facetValidation] {
		if v.Value == "valid" {
			v.Selected = true
		}
	}

	// Only AWS should match (cloud AND valid)
	if !fs.matchesFinding(findings[0]) {
		t.Error("expected AWS to match (cloud AND valid)")
	}
	if fs.matchesFinding(findings[1]) {
		t.Error("expected GitHub to NOT match (cloud but invalid)")
	}
	if fs.matchesFinding(findings[2]) {
		t.Error("expected Slack to NOT match (valid but chat, not cloud)")
	}
}
