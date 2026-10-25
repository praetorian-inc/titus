package explore

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

// --- N1: narrow panes keep every cell of wrapped text ---

// squash drops ANSI styling, whitespace and box-drawing runes, so text that
// was wrapped across pane rows (between borders and indents) compares as one
// string.
func squash(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || (r >= 0x2500 && r <= 0x257F) {
			return -1
		}
		return r
	}, stripAnsi(s))
}

// narrowOcc has a path long enough to wrap several times in a narrow pane.
var narrowOcc = types.Occurrence{Kind: "git", Repository: "github.com/acme/abcdefghij",
	Path: "abcdefghij/klmnopqrst/uvwxyz0123/END.yml", Commit: occAPI1.Commit,
	CommitDate: occAPI1.CommitDate, HostRecorded: true}

func TestDetailsPane_NarrowPaneShowsWholeLocation(t *testing.T) {
	cjk := narrowOcc
	cjk.Path = strings.Repeat("秘密", 15) + "/END.yml"
	for _, tc := range []struct {
		name  string
		occ   types.Occurrence
		width int
	}{
		{"ascii path, 28 columns", narrowOcc, 28},
		{"cjk path, 28 columns", cjk, 28},
		{"cjk path, 60 columns", cjk, 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := newDetailsPane()
			dp.setSize(tc.width, 80)
			dp.setFinding(&findingRow{RuleName: "r", RuleID: "id", Matches: []*matchRow{matchWith(10, tc.occ)}})
			view := dp.View()
			if want := types.FormatLine(tc.occ, 10, ""); !strings.Contains(squash(view), squash(want)) {
				t.Errorf("location %q not shown whole in a %d-column pane:\n%s", want, tc.width, stripAnsi(view))
			}
			for _, part := range []string{"END.yml:10", tc.occ.Commit[:7], "github.com/acme/abcdefghij"} {
				if !strings.Contains(squash(view), part) {
					t.Errorf("%q missing from a %d-column pane:\n%s", part, tc.width, stripAnsi(view))
				}
			}
		})
	}
}

func TestDetailsPane_NarrowPaneShowsWholeGroups(t *testing.T) {
	const val = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij"
	m := matchWith(1, occAPI1)
	m.NamedGroups = map[string][]byte{"token": []byte(val + "NAMED")}
	dp := newDetailsPane()
	dp.setSize(28, 80)
	dp.setFinding(&findingRow{RuleName: "r", RuleID: "id", Groups: [][]byte{[]byte(val + "GROUP")}, Matches: []*matchRow{m}})
	view := dp.View()
	for _, want := range []string{"Group1:" + val + "GROUP", "token:" + val + "NAMED"} {
		if !strings.Contains(squash(view), want) {
			t.Errorf("%q not shown whole in a 28-column pane:\n%s", want, stripAnsi(view))
		}
	}
}

// --- R2: the findings count column does not rescan every location per render ---

func TestFindingsPane_LocationCountCachedPerFilter(t *testing.T) {
	m := matchWith(1, occAPI1, occAPI2, occWeb)
	f := &findingRow{RuleName: "r", Matches: []*matchRow{m}}
	fp := newFindingsPane([]*findingRow{f})
	fp.setSize(120, 10)
	fp.setRepoFilter(map[string]bool{"github.com/acme/api": true})
	if got := fp.locationCount(f); got != 2 {
		t.Fatalf("count under the api filter = %d, want 2", got)
	}

	// Occurrences never change after load. Changing them here is only a
	// probe: a cached count ignores the change, a rescan does not.
	m.Occurrences = []types.Occurrence{occAPI1}
	_ = fp.View()
	if got := fp.locationCount(f); got != 2 {
		t.Errorf("count after a render = %d, want the cached 2: the locations were rescanned", got)
	}

	// A new filter selection starts a new cache.
	fp.setRepoFilter(map[string]bool{"github.com/acme/api": true})
	if got := fp.locationCount(f); got != 1 {
		t.Errorf("count after a new filter = %d, want 1 (recounted)", got)
	}
}

func TestFindingsPane_CopiesWithDifferentFiltersKeepOwnCounts(t *testing.T) {
	f := &findingRow{RuleName: "r", Matches: []*matchRow{matchWith(1, occAPI1, occAPI2, occWeb)}}
	base := newFindingsPane([]*findingRow{f})
	_ = base.locationCount(f)
	a, b := base, base
	a.setRepoFilter(map[string]bool{"github.com/acme/api": true})
	b.setRepoFilter(map[string]bool{"github.com/acme/web": true})
	for range 2 {
		if got := a.locationCount(f); got != 2 {
			t.Errorf("copy a (api) count = %d, want 2", got)
		}
		if got := b.locationCount(f); got != 1 {
			t.Errorf("copy b (web) count = %d, want 1", got)
		}
		if got := base.locationCount(f); got != 3 {
			t.Errorf("unfiltered original count = %d, want 3", got)
		}
	}
}

// --- R3: the exclude overlay sanitizes its input and patterns ---

func TestExcludeOverlay_HostileTextIsSanitized(t *testing.T) {
	for _, listMode := range []bool{false, true} {
		m := newTestModel([]*findingRow{{RuleName: "r", Matches: []*matchRow{matchWith(1, occAPI1)}}})
		m.width, m.height = 120, 40
		m.activeOverlay = overlayExclude
		m.excludeInput = hostile
		m.excludePatterns = []string{hostile, "plain"}
		m.excludeInListMode = listMode
		out := m.renderOverlay()
		assertNoTerminalControl(t, "exclude overlay", out)
		if n := strings.Count(out, `\x1b]0;pwn\x07`); n != 2 {
			t.Errorf("list mode %v: escaped input and pattern shown %d times, want 2:\n%s", listMode, n, out)
		}
	}
}

// --- N3: a provenance load error is shown, not dropped ---

// failingProvenanceStore fails GetAllProvenance and delegates everything else.
type failingProvenanceStore struct{ *store.MemoryStore }

func (failingProvenanceStore) GetAllProvenance(types.BlobID) ([]types.Provenance, error) {
	return nil, errors.New("provenance store down")
}

func TestBuildMatchRow_ProvenanceErrorIsShown(t *testing.T) {
	s, m := occurrenceFixture(t)

	mr := buildMatchRow(m, failingProvenanceStore{s})

	if len(mr.Occurrences) != 3 || mr.LocationsErr != nil {
		t.Fatalf("locations should load despite the provenance error: %d locations, err %v", len(mr.Occurrences), mr.LocationsErr)
	}
	got := strings.Join(plainLines(mr, nil, 120), "\n")
	if !strings.Contains(got, "provenance store down") {
		t.Errorf("provenance error not shown in the locations block:\n%s", got)
	}
	if !strings.Contains(got, "Locations 3:") {
		t.Errorf("locations hidden by the provenance error:\n%s", got)
	}
}

// N6: the provenance warning wraps instead of being clipped. Width 56 is the
// details pane of the default layout on an 80-column terminal.
func TestDetailsPane_NarrowPaneShowsWholeProvenanceWarning(t *testing.T) {
	s, m := occurrenceFixture(t)
	mr := buildMatchRow(m, failingProvenanceStore{s})
	for _, width := range []int{28, 56} {
		dp := newDetailsPane()
		dp.setSize(width, 80)
		dp.setFinding(&findingRow{RuleName: "r", RuleID: "id", Matches: []*matchRow{mr}})
		view := squash(dp.View())
		for _, want := range []string{"Provenance unavailable; locations may be incomplete:", "provenance store down"} {
			if !strings.Contains(view, squash(want)) {
				t.Errorf("%q not shown whole in a %d-column pane:\n%s", want, width, stripAnsi(dp.View()))
			}
		}
	}
}

// contentLines renders every line of the pane before scrolling and clipping.
// Only tests read it: they inspect content that View would scroll out of
// sight.
func (dp detailsPane) contentLines() []string {
	return slices.Concat(dp.content()...)
}
