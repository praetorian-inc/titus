package explore

import (
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/praetorian-inc/titus/pkg/types"
)

func occsIn(repo string, n int) []types.Occurrence {
	occs := make([]types.Occurrence, n)
	for i := range occs {
		occs[i] = types.Occurrence{Kind: "git", Repository: repo, Path: "f.env"}
	}
	return occs
}

func TestFindingsPane_HeaderAndSortNameSayLocations(t *testing.T) {
	if got := sortFieldNames[sortByMatches]; got != "Locations" {
		t.Errorf("sortFieldNames[sortByMatches] = %q, want %q", got, "Locations")
	}

	fp := newFindingsPane([]*findingRow{{RuleName: "r", Matches: []*matchRow{{Occurrences: occsIn("github.com/acme/api", 1)}}}})
	fp.setSize(120, 10)
	fp.sortBy = sortByMatches
	v := stripAnsi(fp.View())

	if !strings.Contains(v, " Locs ^ ") {
		t.Errorf("header has no %q column:\n%s", "Locs", v)
	}
	if !strings.Contains(v, "[sort: Locations]") {
		t.Errorf("title has no %q:\n%s", "[sort: Locations]", v)
	}
	if strings.Contains(v, "Matches") {
		t.Errorf("view still says Matches:\n%s", v)
	}
}

func TestFindingsPane_CountCellSumsVisibleLocationsAcrossMatches(t *testing.T) {
	m1 := &matchRow{Occurrences: append(occsIn("github.com/acme/api", 2), occsIn("github.com/acme/web", 1)...)}
	m2 := &matchRow{Occurrences: append(occsIn("github.com/acme/web", 1), types.Occurrence{Kind: "file", Path: "plain.txt"})}
	f := &findingRow{RuleName: "Multi", MatchCount: 5, Matches: []*matchRow{m1, m2}}
	fp := newFindingsPane([]*findingRow{f})
	fp.setSize(120, 10)

	if got := countCell(t, fp, "Multi"); got != 5 {
		t.Errorf("unfiltered count = %d, want 5", got)
	}

	fp.setRepoFilter(map[string]bool{"github.com/acme/web": true})
	if got := countCell(t, fp, "Multi"); got != 2 {
		t.Errorf("count under web facet = %d, want 2 (one per match; the file location has no repository)", got)
	}
	if v := stripAnsi(fp.View()); strings.Contains(v, "2/5") {
		t.Errorf("count cell must be a plain number, got N/M text:\n%s", v)
	}
}

func TestFindingsPane_LocationSortUsesVisibleCount(t *testing.T) {
	// a: 3 api + 1 web = 4 total, 1 visible under web.
	// b: 2 web = 2 total, 2 visible under web.
	a := &findingRow{RuleName: "a", MatchCount: 4, Matches: []*matchRow{{Occurrences: append(occsIn("github.com/acme/api", 3), occsIn("github.com/acme/web", 1)...)}}}
	b := &findingRow{RuleName: "b", MatchCount: 2, Matches: []*matchRow{{Occurrences: occsIn("github.com/acme/web", 2)}}}
	fp := newFindingsPane([]*findingRow{a, b})
	fp.sortBy = sortByMatches
	fp.sort()
	if fp.rows[0] != b {
		t.Fatalf("unfiltered ascending location sort: want b (2) before a (4), got %q first", fp.rows[0].RuleName)
	}

	fp.setRepoFilter(map[string]bool{"github.com/acme/web": true})
	fp.setFilteredRows([]*findingRow{b, a})

	if fp.rows[0] != a {
		t.Errorf("location sort under web facet: want a (1) before b (2), got %q first", fp.rows[0].RuleName)
	}
}

// largeFindingSet builds n findings of 2 matches x 5 locations each, spread
// over three repositories, so visible counts vary per finding.
func largeFindingSet(n int) []*findingRow {
	repos := []string{"github.com/acme/api", "github.com/acme/web", "github.com/acme/ops"}
	rows := make([]*findingRow, n)
	for i := range rows {
		matches := make([]*matchRow, 2)
		for j := range matches {
			occs := make([]types.Occurrence, 5)
			for k := range occs {
				occs[k] = types.Occurrence{Kind: "git", Repository: repos[(i*7+j+k*k)%len(repos)], Path: "f.env"}
			}
			matches[j] = &matchRow{Occurrences: occs}
		}
		rows[i] = &findingRow{RuleName: "r", MatchCount: 10, Matches: matches}
	}
	return rows
}

func BenchmarkFindingsPane_SetFilteredRowsLocationSort(b *testing.B) {
	rows := largeFindingSet(3000)
	fp := newFindingsPane(slices.Clone(rows))
	fp.sortBy = sortByMatches
	fp.setRepoFilter(map[string]bool{"github.com/acme/web": true})
	for b.Loop() {
		fp.setFilteredRows(slices.Clone(rows))
	}
}

// A filters-pane key re-sorts the shown rows; 3000 findings under one
// selected repository must re-sort well inside one frame budget.
func TestFindingsPane_SetFilteredRowsLocationSortIsFast(t *testing.T) {
	rows := largeFindingSet(3000)
	fp := newFindingsPane(slices.Clone(rows))
	fp.sortBy = sortByMatches
	fp.setRepoFilter(map[string]bool{"github.com/acme/web": true})

	start := time.Now()
	fp.setFilteredRows(slices.Clone(rows))
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Errorf("setFilteredRows on 3000 rows took %v, want < 100ms", d)
	}
	for i := 1; i < len(fp.rows); i++ {
		if fp.locationCount(fp.rows[i-1]) > fp.locationCount(fp.rows[i]) {
			t.Fatalf("rows not in ascending location order at %d", i)
		}
	}
}

// selectionFixture: a has api x3 + web x1 (4 total, 1 under web); b has web x2.
func selectionFixture() (a, b *findingRow) {
	a = &findingRow{FindingID: "a", RuleName: "a", Repositories: []string{"github.com/acme/api", "github.com/acme/web"}, MatchCount: 4,
		Matches: []*matchRow{{Occurrences: append(occsIn("github.com/acme/api", 3), occsIn("github.com/acme/web", 1)...)}}}
	b = &findingRow{FindingID: "b", RuleName: "b", Repositories: []string{"github.com/acme/web"}, MatchCount: 2,
		Matches: []*matchRow{{Occurrences: occsIn("github.com/acme/web", 2)}}}
	return a, b
}

func TestFindingsPane_SetFilteredRowsKeepsSelectedFinding(t *testing.T) {
	a, b := selectionFixture()
	fp := newFindingsPane([]*findingRow{a, b})
	fp.sortBy = sortByMatches
	fp.sort()
	fp.cursor = slices.Index(fp.rows, a)
	if fp.cursor != 1 {
		t.Fatalf("fixture: want a at index 1 (b=2 before a=4), got %d", fp.cursor)
	}

	fp.setRepoFilter(map[string]bool{"github.com/acme/web": true})
	fp.setFilteredRows([]*findingRow{a, b})

	if fp.rows[0] != a {
		t.Errorf("re-sort dropped: want a (1) first under web, got %q", fp.rows[0].RuleName)
	}
	if got := fp.selectedFinding(); got != a {
		t.Errorf("selected after facet change = %q, want a", got.RuleName)
	}
}

func TestFindingsPane_SortKeyKeepsSelectedFinding(t *testing.T) {
	a, b := selectionFixture()
	fp := newFindingsPane([]*findingRow{a, b}) // rule name asc: a, b
	fp.focused = true
	fp.cursor = slices.Index(fp.rows, a)

	fp, _ = fp.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})

	if fp.sortBy != sortByMatches {
		t.Fatalf("fixture: s should move to the Locations sort, got %v", fp.sortBy)
	}
	if fp.rows[0] != b {
		t.Fatalf("fixture: Locations sort should put b (2) first, got %q", fp.rows[0].RuleName)
	}
	if got := fp.selectedFinding(); got != a {
		t.Errorf("selected after s = %q, want a", got.RuleName)
	}
}
