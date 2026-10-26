package explore

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// S1 fixtures: a finding whose only match failed to load its locations, so
// it has no occurrences and no repositories, beside findings with known
// locations in github.com/acme/api and github.com/acme/web.
func unknownLocationsFixture() (errored, api, web *findingRow) {
	bad := matchWith(1)
	bad.StructuralID = "errored"
	bad.LocationsErr = errors.New("database is locked")
	errored = &findingRow{FindingID: "errored", RuleName: "Errored Token", Matches: []*matchRow{bad}}
	api = &findingRow{FindingID: "api", RuleName: "Api Token", Repositories: []string{"github.com/acme/api"},
		Matches: []*matchRow{matchWith(2, occAPI1)}}
	web = &findingRow{FindingID: "web", RuleName: "Web Token", Repositories: []string{"github.com/acme/web"},
		Matches: []*matchRow{matchWith(3, occWeb)}}
	return errored, api, web
}

// locsCell reads the findings-table Locs cell of the row for ruleName as
// text, so a "?" suffix is kept.
func locsCell(t *testing.T, fp findingsPane, ruleName string) string {
	t.Helper()
	re := regexp.MustCompile(regexp.QuoteMeta(ruleName) + `\s+(\d+\??)\s`)
	sub := re.FindStringSubmatch(stripAnsi(fp.View()))
	if sub == nil {
		t.Fatalf("no Locs cell for %q in:\n%s", ruleName, stripAnsi(fp.View()))
	}
	return sub[1]
}

// S1: a finding whose locations failed to load may have locations in any
// repository, so a Repository facet selection must not hide it, and under
// the selection its match stays navigable and its warning is shown.
func TestModel_S1_ErroredFindingReachableUnderRepositoryFacet(t *testing.T) {
	for _, repo := range []string{"github.com/acme/api", "github.com/acme/web"} {
		t.Run(repo, func(t *testing.T) {
			errored, api, web := unknownLocationsFixture()
			m := newTestModel([]*findingRow{errored, api, web})
			selectFacetValue(t, &m, facetRepository, repo)
			m.applyFilters()

			if !slices.Contains(m.findings.rows, errored) {
				t.Fatalf("errored finding hidden by the %s facet; rows = %v", repo, rowNames(m.findings.rows))
			}
			m.findings.cursor = slices.Index(m.findings.rows, errored)
			m.details.setFinding(errored)
			if got := m.details.selectedMatch(); got != errored.Matches[0] {
				t.Fatalf("errored match not navigable under the %s facet (visibleMatchIdx %v)", repo, m.details.visibleMatchIdx)
			}
			plain := stripAnsi(strings.Join(m.details.contentLines(), "\n"))
			if !strings.Contains(plain, "Locations unavailable:") || !strings.Contains(plain, "database is locked") {
				t.Errorf("details pane does not show the location-load warning:\n%s", plain)
			}
		})
	}
}

// S1 benign case: findings with known locations are still narrowed by the
// facet; keeping the errored finding must not keep everything.
func TestFacetState_S1_KnownLocationsStillFiltered(t *testing.T) {
	errored, api, web := unknownLocationsFixture()
	fs := buildFacets([]*findingRow{errored, api, web})
	for _, v := range fs.Values[facetRepository] {
		v.Selected = v.Value == "github.com/acme/web"
	}
	want := map[string]bool{"errored": true, "api": false, "web": true}
	for _, f := range []*findingRow{errored, api, web} {
		if got := fs.matchesFinding(f); got != want[f.FindingID] {
			t.Errorf("matchesFinding(%s) = %v, want %v", f.FindingID, got, want[f.FindingID])
		}
	}
}

func rowNames(rows []*findingRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.RuleName
	}
	return out
}

// S1: the Locs cell of a finding with a failed location load is the count
// of the locations that did load, marked "?" as a lower bound. A finding with
// all locations known keeps a plain number.
func TestFindingsPane_S1_UnknownCountCellHasQuestionMark(t *testing.T) {
	errored, api, _ := unknownLocationsFixture()
	partial := &findingRow{RuleName: "Partial Token", Matches: []*matchRow{
		matchWith(4, occAPI1, occAPI2), errored.Matches[0],
	}}
	fp := newFindingsPane([]*findingRow{errored, api, partial})
	fp.setSize(120, 10)

	for name, want := range map[string]string{"Errored Token": "0?", "Partial Token": "2?", "Api Token": "1"} {
		if got := locsCell(t, fp, name); got != want {
			t.Errorf("Locs cell of %s = %q, want %q", name, got, want)
		}
	}
}

// S1: ascending location sort puts "N?" after a known N, and keeps the input
// order of rows with the same count and the same known/unknown state.
func TestFindingsPane_S1_LocationSortUnknownAfterKnownAndStable(t *testing.T) {
	unknown := func(name string, occs ...types.Occurrence) *findingRow {
		bad := &matchRow{LocationsErr: errors.New("boom")}
		return &findingRow{RuleName: name, Matches: []*matchRow{{Occurrences: occs}, bad}}
	}
	known := func(name string, occs ...types.Occurrence) *findingRow {
		return &findingRow{RuleName: name, Matches: []*matchRow{{Occurrences: occs}}}
	}
	// The known rows sort last by name, so the name order newFindingsPane
	// starts from puts every unknown row before its known peer: a count-only
	// sort would leave them there.
	rows := []*findingRow{
		unknown("a1a", occWeb),
		known("z1", occWeb),
		unknown("a0a"),
		unknown("a1b", occAPI1),
		known("z0"),
		unknown("a0b"),
	}
	fp := newFindingsPane(rows)
	if got := rowNames(fp.rows); !slices.Equal(got, []string{"a0a", "a0b", "a1a", "a1b", "z0", "z1"}) {
		t.Fatalf("fixture: initial order = %q, want name order", got)
	}
	fp.sortBy = sortByMatches
	fp.sortAsc = true
	fp.sort()

	want := []string{"z0", "a0a", "a0b", "z1", "a1a", "a1b"}
	if got := rowNames(fp.rows); !slices.Equal(got, want) {
		t.Errorf("ascending location sort = %q, want %q", got, want)
	}
}

// S1/N2: the Right key and the model's moveNext both step through the
// visible matches with the same rule, and an errored match is one of them
// under a facet that would hide it by its (empty) locations.
func TestDetailsPane_S1_RightAndMoveNextShareNextMatch(t *testing.T) {
	build := func() (*findingRow, *matchRow, *matchRow, *matchRow) {
		webM, apiM := matchWith(1, occWeb), matchWith(3, occAPI1)
		bad := matchWith(2)
		bad.LocationsErr = errors.New("database is locked")
		return &findingRow{RuleName: "Split", Repositories: []string{"github.com/acme/api", "github.com/acme/web"},
			Matches: []*matchRow{webM, bad, apiM}}, webM, bad, apiM
	}

	// Right key on the details pane.
	f, webM, bad, _ := build()
	dp := newTestPane()
	dp.setRepoFilter(map[string]bool{"github.com/acme/web": true})
	dp.setFinding(f)
	var viaKey []*matchRow
	for range 3 {
		viaKey = append(viaKey, dp.selectedMatch())
		dp = pressKey(dp, "l", 1)
	}

	// moveNext on the model, focus on the details pane.
	f2, webM2, bad2, _ := build()
	m := newTestModel([]*findingRow{f2})
	selectFacetValue(t, &m, facetRepository, "github.com/acme/web")
	m.applyFilters()
	m.focus = paneDetails
	var viaMove []*matchRow
	for range 3 {
		viaMove = append(viaMove, m.details.selectedMatch())
		m.moveNext()
	}

	wantKey := []*matchRow{webM, bad, bad}
	wantMove := []*matchRow{webM2, bad2, bad2}
	if !slices.Equal(viaKey, wantKey) {
		t.Errorf("Right key visited %v, want web, errored, errored (stop at the last visible match)", matchIDs(viaKey, webM, bad))
	}
	if !slices.Equal(viaMove, wantMove) {
		t.Errorf("moveNext visited %v, want web, errored, errored (stop at the last visible match)", matchIDs(viaMove, webM2, bad2))
	}
}

func matchIDs(ms []*matchRow, web, bad *matchRow) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		switch m {
		case web:
			out[i] = "web"
		case bad:
			out[i] = "errored"
		case nil:
			out[i] = "<nil>"
		default:
			out[i] = "other"
		}
	}
	return out
}
