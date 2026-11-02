package explore

import (
	"slices"
	"testing"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
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

func TestVisibleOccurrences(t *testing.T) {
	api1 := types.Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "a.env"}
	api2 := types.Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "b.env"}
	web := types.Occurrence{Kind: "git", Repository: "github.com/acme/web", Path: ".env"}
	file := types.Occurrence{Kind: "file", Path: "dump/creds.txt", HostRecorded: true}
	ext := types.Occurrence{Kind: "extended", Path: "k/creds", HostRecorded: true}
	conf := types.Occurrence{Kind: "extended", Source: "confluence", Path: "SPACE/Page", HostRecorded: true}
	all := []types.Occurrence{api1, api2, web, file, ext, conf}

	tests := []struct {
		name string
		sel  map[string]bool
		want []types.Occurrence
	}{
		{"nil selection shows all", nil, all},
		{"empty selection shows all", map[string]bool{}, all},
		{"one repository (C-EXPLORE-1)", map[string]bool{"github.com/acme/web": true}, []types.Occurrence{web}},
		{"repository with two locations", map[string]bool{"github.com/acme/api": true}, []types.Occurrence{api1, api2}},
		{"every repository hides keyless", map[string]bool{"github.com/acme/api": true, "github.com/acme/web": true}, []types.Occurrence{api1, api2, web}},
		{"extended source is selectable", map[string]bool{"confluence": true}, []types.Occurrence{conf}},
		{"repository and source together", map[string]bool{"github.com/acme/web": true, "confluence": true}, []types.Occurrence{web, conf}},
		{"unknown repository shows none", map[string]bool{"github.com/acme/other": true}, nil},
		{"empty-string key never selects keyless", map[string]bool{"": true}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := visibleOccurrences(all, tt.sel)
			if !slices.Equal(got, tt.want) {
				t.Errorf("visibleOccurrences = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// visibleLocationCount sums the visible locations over a finding's matches.
func visibleLocationCount(f *findingRow, sel map[string]bool) int {
	n := 0
	for _, mr := range f.Matches {
		n += len(visibleOccurrences(mr.Occurrences, sel))
	}
	return n
}

// TestRepositoryFacet_DropsFindingWithNoVisibleLocation verifies that, with the
// Repository facet set, a finding passes exactly when at least one of its
// locations is visible, and that location counts narrow per C-EXPLORE-1.
func TestRepositoryFacet_DropsFindingWithNoVisibleLocation(t *testing.T) {
	s := store.NewMemory()
	add := func(content string, occs ...types.Occurrence) *types.Match {
		t.Helper()
		id := types.ComputeBlobID([]byte(content))
		if err := s.AddOccurrences(id, occs); err != nil {
			t.Fatalf("AddOccurrences: %v", err)
		}
		return &types.Match{StructuralID: content, BlobID: id, RuleID: "r"}
	}
	mixed := add("mixed",
		types.Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "a.env", Commit: "1111111"},
		types.Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "b.env", Commit: "2222222"},
		types.Occurrence{Kind: "git", Repository: "github.com/acme/web", Path: ".env", Commit: "3333333"},
	)
	apiOnly := add("api-only", types.Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "c.env", Commit: "4444444"})
	fileOnly := add("file-only", types.Occurrence{Kind: "file", Path: "dump/creds.txt"})

	rules := map[string]*types.Rule{}
	findings := []*findingRow{
		buildFindingRow(&types.Finding{ID: "mixed", RuleID: "r"}, []*types.Match{mixed}, rules, s),
		buildFindingRow(&types.Finding{ID: "api-only", RuleID: "r"}, []*types.Match{apiOnly}, rules, s),
		buildFindingRow(&types.Finding{ID: "file-only", RuleID: "r"}, []*types.Match{fileOnly}, rules, s),
	}
	fs := buildFacets(findings)
	for _, v := range fs.Values[facetRepository] {
		v.Selected = v.Value == "github.com/acme/web"
	}
	sel := fs.selectedValues(facetRepository)
	if len(sel) != 1 {
		t.Fatalf("fixture: expected github.com/acme/web to be a facet value, got %+v", fs.Values[facetRepository])
	}

	wantPass := map[string]bool{"mixed": true, "api-only": false, "file-only": false}
	for _, f := range findings {
		pass := fs.matchesFinding(f)
		if pass != wantPass[f.FindingID] {
			t.Errorf("matchesFinding(%s) = %v, want %v", f.FindingID, pass, wantPass[f.FindingID])
		}
		if visible := visibleLocationCount(f, sel); pass != (visible > 0) {
			t.Errorf("%s: matchesFinding = %v but %d visible locations", f.FindingID, pass, visible)
		}
	}

	// C-EXPLORE-1: 1 visible location with the facet set, 3 once cleared.
	if got := visibleLocationCount(findings[0], sel); got != 1 {
		t.Errorf("visible locations with facet set = %d, want 1", got)
	}
	fs.resetAll()
	cleared := fs.selectedValues(facetRepository)
	if got := visibleLocationCount(findings[0], cleared); got != 3 {
		t.Errorf("visible locations after clearing = %d, want 3", got)
	}
	if !fs.matchesFinding(findings[2]) {
		t.Error("with no selection, a repository-less finding must pass")
	}
}

// TestExtendedSourceFacet covers an extended location with source
// "confluence": it is a facet value, selecting it shows its one location and
// passes its finding, and an exclusion pattern "confluence" excludes it.
func TestExtendedSourceFacet(t *testing.T) {
	s := store.NewMemory()
	id := types.ComputeBlobID([]byte("confluence-secret"))
	conf := types.ExtendedProvenance{Payload: map[string]any{"source": "confluence", "path": "SPACE/Page"}}
	if err := s.AddProvenance(id, conf); err != nil {
		t.Fatalf("AddProvenance: %v", err)
	}
	if err := s.AddOccurrences(id, types.OccurrencesOf(conf)); err != nil {
		t.Fatalf("AddOccurrences: %v", err)
	}
	gitID := types.ComputeBlobID([]byte("git-secret"))
	if err := s.AddOccurrences(gitID, []types.Occurrence{{Kind: "git", Repository: "github.com/acme/web", Path: ".env", Commit: "3333333"}}); err != nil {
		t.Fatalf("AddOccurrences git: %v", err)
	}
	rules := map[string]*types.Rule{}
	confRow := buildFindingRow(&types.Finding{ID: "conf", RuleID: "r"}, []*types.Match{{StructuralID: "c", BlobID: id, RuleID: "r"}}, rules, s)
	gitRow := buildFindingRow(&types.Finding{ID: "git", RuleID: "r"}, []*types.Match{{StructuralID: "g", BlobID: gitID, RuleID: "r"}}, rules, s)

	if !slices.Equal(confRow.Repositories, []string{"confluence"}) {
		t.Fatalf("Repositories = %q, want [confluence]", confRow.Repositories)
	}
	fs := buildFacets([]*findingRow{confRow, gitRow})
	found := false
	for _, v := range fs.Values[facetRepository] {
		if v.Value == "confluence" {
			found, v.Selected = true, true
		}
	}
	if !found {
		t.Fatalf("no confluence facet value in %+v", fs.Values[facetRepository])
	}
	sel := fs.selectedValues(facetRepository)
	if got := visibleLocationCount(confRow, sel); got != 1 {
		t.Errorf("visible confluence locations = %d, want 1", got)
	}
	if !fs.matchesFinding(confRow) {
		t.Error("confluence finding must pass with confluence selected")
	}
	if fs.matchesFinding(gitRow) {
		t.Error("git-only finding must not pass with confluence selected")
	}

	m := &Model{excludePatterns: []string{"confluence"}}
	if !m.matchesExclusion(confRow) {
		t.Error(`exclusion "confluence" must exclude the confluence finding`)
	}
	if m.matchesExclusion(gitRow) {
		t.Error(`exclusion "confluence" must not exclude the git finding`)
	}
}
