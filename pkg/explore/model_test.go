package explore

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// newTestModel builds a Model over rows the same way New does, without a
// datastore on disk.
func newTestModel(rows []*findingRow) Model {
	m := Model{
		data:           &exploreData{findings: rows},
		filters:        newFilterPane(buildFacets(rows)),
		findings:       newFindingsPane(rows),
		details:        newDetailsPane(),
		focus:          paneFindings,
		showFilters:    true,
		filterWidthPct: 30,
	}
	m.findings.focused = true
	m.findings.setSize(120, 12)
	m.details.setSize(120, 60)
	if f := m.findings.selectedFinding(); f != nil {
		m.details.setFinding(f)
	}
	return m
}

// contentLines renders every line of the pane before scrolling and clipping.
// Only tests read it: they inspect content that View would scroll out of
// sight.
func (dp detailsPane) contentLines() []string {
	return slices.Concat(dp.content()...)
}

func selectFacetValue(t *testing.T, m *Model, id facetID, value string) {
	t.Helper()
	for _, v := range m.filters.facets.Values[id] {
		if v.Value == value {
			v.Selected = true
			return
		}
	}
	t.Fatalf("facet value %q not found", value)
}

// firstInt returns the first capture group of re in s as an int.
func firstInt(t *testing.T, re *regexp.Regexp, s, what string) int {
	t.Helper()
	sub := re.FindStringSubmatch(s)
	if sub == nil {
		t.Fatalf("%s: no match for %s in:\n%s", what, re, s)
	}
	n, err := strconv.Atoi(sub[1])
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	return n
}

var (
	locationsHeadingRe = regexp.MustCompile(`Locations (\d+):`)
	matchNavigatorRe   = regexp.MustCompile(`Match \d+/(\d+)`)
)

// detailsLocations reads N from the details pane's "Locations N:" heading.
func detailsLocations(t *testing.T, m Model) int {
	t.Helper()
	return firstInt(t, locationsHeadingRe, stripAnsi(strings.Join(m.details.contentLines(), "\n")), "details_locations")
}

// navDenominator reads N from the details pane's "Match i/N" navigator.
func navDenominator(t *testing.T, m Model) int {
	t.Helper()
	return firstInt(t, matchNavigatorRe, stripAnsi(strings.Join(m.details.contentLines(), "\n")), "nm_denominator")
}

// countCell reads the findings-table count cell of the row for ruleName.
func countCell(t *testing.T, fp findingsPane, ruleName string) int {
	t.Helper()
	re := regexp.MustCompile(regexp.QuoteMeta(ruleName) + `\s+(\d+)\s`)
	return firstInt(t, re, stripAnsi(fp.View()), "row_count")
}

// C-EXPLORE-1 (outcome-plan-1.json): a finding with locations
// github.com/acme/api x2 and github.com/acme/web x1. With the Repository
// facet set to github.com/acme/web the details pane, the findings count cell
// and the match navigator all count locations inside that repository only
// (1/1/1). After clearing, the totals return (3/3). The "narrows findings
// only" reading gives 3/3/1 with the facet set and fails here.
func TestModel_CExplore1_RepositoryFacetNarrowsLocations(t *testing.T) {
	s, match := occurrenceFixture(t)
	target := buildFindingRow(&types.Finding{ID: "f1", RuleID: match.RuleID}, []*types.Match{match}, map[string]*types.Rule{}, s)
	apiOnly := &findingRow{
		FindingID:    "f2",
		RuleName:     "Zeta Token",
		Repositories: []string{"github.com/acme/api"},
		Matches: []*matchRow{{Occurrences: []types.Occurrence{
			{Kind: "git", Repository: "github.com/acme/api", Path: "z.env"},
		}}},
	}
	m := newTestModel([]*findingRow{target, apiOnly})
	if got := m.findings.selectedFinding(); got != target {
		t.Fatalf("fixture: expected the C-EXPLORE-1 finding selected first, got %+v", got)
	}

	selectFacetValue(t, &m, facetRepository, "github.com/acme/web")
	m.applyFilters()

	if len(m.findings.rows) != 1 || m.findings.rows[0] != target {
		t.Fatalf("expected only the C-EXPLORE-1 finding under the facet, got %d rows", len(m.findings.rows))
	}
	if got := detailsLocations(t, m); got != 1 {
		t.Errorf("details_locations = %d, want 1", got)
	}
	if got := countCell(t, m.findings, target.RuleName); got != 1 {
		t.Errorf("row_count = %d, want 1", got)
	}
	if got := navDenominator(t, m); got != 1 {
		t.Errorf("nm_denominator = %d, want 1", got)
	}

	m.filters.facets.resetAll()
	m.applyFilters()

	if got := detailsLocations(t, m); got != 3 {
		t.Errorf("after clear: details_locations = %d, want 3", got)
	}
	if got := countCell(t, m.findings, target.RuleName); got != 3 {
		t.Errorf("after clear: row_count = %d, want 3", got)
	}
}
