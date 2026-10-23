package explore

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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
		MatchCount:   1,
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

// splitFinding has an api-only first match and a web-only second match, so
// under the github.com/acme/web facet only the second match is navigable.
func splitFinding() (*findingRow, *matchRow, *matchRow) {
	apiMatch := &matchRow{StructuralID: "m-api", Occurrences: []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "a.env"},
	}}
	apiMatch.Snippet.Matching = []byte("api-secret")
	webMatch := &matchRow{StructuralID: "m-web", Occurrences: []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/web", Path: "w.env"},
	}}
	webMatch.Snippet.Matching = []byte("web-secret")
	f := &findingRow{
		FindingID:    "f1",
		RuleName:     "Split",
		Repositories: []string{"github.com/acme/api", "github.com/acme/web"},
		MatchCount:   2,
		Matches:      []*matchRow{apiMatch, webMatch},
	}
	return f, apiMatch, webMatch
}

func TestModel_CopySecretUsesVisibleSelectedMatch(t *testing.T) {
	f, _, _ := splitFinding()
	m := newTestModel([]*findingRow{f})
	selectFacetValue(t, &m, facetRepository, "github.com/acme/web")
	m.applyFilters()
	m.focus = paneDetails

	m.copySecretToClipboard()

	if m.pendingClipboard != "web-secret" {
		t.Errorf("copied %q, want the visible match's secret %q", m.pendingClipboard, "web-secret")
	}
}

func TestModel_MoveNextStaysWithinVisibleMatches(t *testing.T) {
	f, apiMatch, webMatch := splitFinding()
	// Web first: the only visible match is also the last navigable one, so a
	// step bounded by len(Matches) would move past it.
	f.Matches = []*matchRow{webMatch, apiMatch}
	m := newTestModel([]*findingRow{f})
	selectFacetValue(t, &m, facetRepository, "github.com/acme/web")
	m.applyFilters()
	m.focus = paneDetails

	m.moveNext()

	if got := m.details.selectedMatch(); got != webMatch {
		gotID := "<nil>"
		if got != nil {
			gotID = got.StructuralID
		}
		t.Errorf("after moveNext selected match = %q, want the only visible match %q", gotID, webMatch.StructuralID)
	}
}

func TestModel_MouseScrollDetailsOffsetClamped(t *testing.T) {
	f, _, _ := splitFinding()
	m := newTestModel([]*findingRow{f})
	m.width, m.height = 200, 50
	m.details.setSize(120, 8)
	maxOff := m.details.maxOffset()
	if maxOff < 4 {
		t.Fatalf("fixture: details content must overflow the pane, maxOffset = %d", maxOff)
	}

	// (150, 40) is inside the details pane: right of the filters, below the findings.
	for range 100 {
		m.handleMouseScroll(150, 40, false)
	}
	if m.details.offset != maxOff {
		t.Fatalf("offset after scrolling past the end = %d, want %d", m.details.offset, maxOff)
	}
	m.handleMouseScroll(150, 40, true)
	if m.details.offset != maxOff-3 {
		t.Errorf("one scroll up moved offset to %d, want %d", m.details.offset, maxOff-3)
	}
}

func runeKey(r rune) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}} }

func ruleNameOf(f *findingRow) string {
	if f == nil {
		return "<nil>"
	}
	return f.RuleName
}

// Item 2: the facet change re-sorts the rows; the highlighted finding and the
// details pane must stay on a, not jump to whatever lands on the old index.
func TestModel_FacetChangeKeepsSelectedFinding(t *testing.T) {
	a, b := selectionFixture()
	m := newTestModel([]*findingRow{a, b})
	m.findings.sortBy = sortByMatches
	m.findings.sort()
	m.findings.cursor = slices.Index(m.findings.rows, a)
	m.details.setFinding(a)
	if m.findings.cursor != 1 {
		t.Fatalf("fixture: want a at index 1 (b=2 before a=4), got %d", m.findings.cursor)
	}

	selectFacetValue(t, &m, facetRepository, "github.com/acme/web")
	m.applyFilters()

	if got := m.findings.selectedFinding(); got != a {
		t.Errorf("selected finding = %q, want a", ruleNameOf(got))
	}
	if m.details.finding != a {
		t.Errorf("details finding = %q, want a", ruleNameOf(m.details.finding))
	}
}

// Item 3: s re-sorts; the highlighted row and the details pane must agree,
// and both stay on the finding selected before the sort.
func TestModel_SortKeyKeepsDetailsOnHighlightedRow(t *testing.T) {
	a, b := selectionFixture()
	m := newTestModel([]*findingRow{a, b}) // rule name asc: a, b; a selected
	if m.findings.selectedFinding() != a || m.details.finding != a {
		t.Fatalf("fixture: want a selected and shown first")
	}

	next, _ := m.Update(runeKey('s'))
	m = next.(Model)

	if m.findings.rows[0] != b {
		t.Fatalf("fixture: Locations sort should put b first, got %q", m.findings.rows[0].RuleName)
	}
	if got := m.findings.selectedFinding(); got != a {
		t.Errorf("highlighted after s = %q, want a", ruleNameOf(got))
	}
	if m.details.finding != m.findings.selectedFinding() {
		t.Errorf("details shows %q but row %q is highlighted", ruleNameOf(m.details.finding), ruleNameOf(m.findings.selectedFinding()))
	}
}

// Item 4: a stale offset past maxOffset (content shrank) must be clamped on
// wheel-up, matching the keyboard Up path.
func TestModel_MouseScrollUpClampsStaleOffset(t *testing.T) {
	f, _, _ := splitFinding()
	m := newTestModel([]*findingRow{f})
	m.width, m.height = 200, 50
	m.details.setSize(120, 8)
	maxOff := m.details.maxOffset()
	if maxOff < 4 {
		t.Fatalf("fixture: details content must overflow the pane, maxOffset = %d", maxOff)
	}
	m.details.offset = maxOff + 10

	m.handleMouseScroll(150, 40, true)

	if m.details.offset != maxOff-3 {
		t.Errorf("wheel up from stale offset = %d, want %d", m.details.offset, maxOff-3)
	}
}

// Item 4: A/R (moveNext) in the details pane moves to the next match and,
// like l, starts it scrolled to the top.
func TestModel_MoveNextInDetailsResetsOffset(t *testing.T) {
	f, apiMatch, webMatch := splitFinding()
	m := newTestModel([]*findingRow{f})
	m.focus = paneDetails
	m.details.offset = 2

	m.moveNext()

	if got := m.details.selectedMatch(); got != webMatch {
		t.Fatalf("fixture: moveNext should go from %q to %q", apiMatch.StructuralID, webMatch.StructuralID)
	}
	if m.details.offset != 0 {
		t.Errorf("offset after moveNext = %d, want 0", m.details.offset)
	}
}

// Item 5: the facet change driven by keys through Model.Update, with the
// filters pane focused, reaches the findings and details panes.
func TestModel_FiltersPaneKeysNarrowAndClearLocations(t *testing.T) {
	s, match := occurrenceFixture(t)
	target := buildFindingRow(&types.Finding{ID: "f1", RuleID: match.RuleID}, []*types.Match{match}, map[string]*types.Rule{}, s)
	m := newTestModel([]*findingRow{target})
	m.setFocus(paneFilters)
	m.filters.cursor = slices.IndexFunc(m.filters.items, func(it filterItem) bool {
		return it.Kind == filterItemValue && it.FacetID == facetRepository && it.Label == "github.com/acme/web"
	})
	if m.filters.cursor < 0 {
		t.Fatalf("fixture: no github.com/acme/web item in the filters pane")
	}

	next, _ := m.Update(runeKey('x'))
	m = next.(Model)

	if got := detailsLocations(t, m); got != 1 {
		t.Errorf("after toggle: details_locations = %d, want 1", got)
	}
	if got := countCell(t, m.findings, target.RuleName); got != 1 {
		t.Errorf("after toggle: row_count = %d, want 1", got)
	}
	if got := navDenominator(t, m); got != 1 {
		t.Errorf("after toggle: nm_denominator = %d, want 1", got)
	}

	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlR})
	m = next.(Model)

	if got := detailsLocations(t, m); got != 3 {
		t.Errorf("after reset: details_locations = %d, want 3", got)
	}
	if got := countCell(t, m.findings, target.RuleName); got != 3 {
		t.Errorf("after reset: row_count = %d, want 3", got)
	}
}
