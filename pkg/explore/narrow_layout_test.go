package explore

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/praetorian-inc/titus/pkg/types"
)

// ENG-9178 Phase 17 (T2-1): in a narrow details pane a location line wraps
// between fields, so the short commit hash stays on one row and copies whole.
func TestRenderLocations_NarrowPaneKeepsCommitWhole(t *testing.T) {
	occ := types.Occurrence{Kind: "git", Repository: "github.com/acme/alpha", Path: "config/app.env",
		Commit: "60121491f2e3d4c5b6a7", CommitDate: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC), HostRecorded: true}
	const (
		paneWidth = 52
		wrapWidth = paneWidth - 6 // renderLocations reserves 6 cells for indents
		commit    = "6012149"
	)
	line := types.FormatLine(occ, 1, "")

	// Precondition: at this width a hard wrap splits the hash, so the fixture
	// reproduces the reported bug.
	if hard := wrapLine(line, wrapWidth); slices.ContainsFunc(hard, func(r string) bool { return strings.Contains(r, commit) }) {
		t.Fatalf("fixture does not reproduce the split: hard-wrapped rows %q keep %q whole", hard, commit)
	}

	_, body := locationBlock(t, plainLines(matchWith(1, occ), nil, paneWidth))
	if len(body) < 2 {
		t.Fatalf("expected the location line to wrap at width %d, got %q", paneWidth, body)
	}
	if !slices.ContainsFunc(body, func(r string) bool { return strings.Contains(r, commit) }) {
		t.Errorf("commit %q split across rows: %q", commit, body)
	}
	for _, f := range []string{"github.com/acme/alpha", "config/app.env:1", "2026-10-26"} {
		if !slices.ContainsFunc(body, func(r string) bool { return slices.Contains(strings.Fields(r), f) }) {
			t.Errorf("field %q split across rows: %q", f, body)
		}
	}
	for i, r := range body {
		if w := ansi.StringWidth(r); w > paneWidth {
			t.Errorf("row %d is %d cells, wider than the pane (%d): %q", i, w, paneWidth, r)
		}
	}
}

func statusBarModel(width int) Model {
	m := newTestModel([]*findingRow{
		{FindingID: "f1", RuleName: "Rule A"},
		{FindingID: "f2", RuleName: "Rule B"},
	})
	m.width = width
	return m
}

// ENG-9178 Phase 17 (T3-1): the counts and the help text never run together.
func TestRenderStatusBar_GapBetweenSections(t *testing.T) {
	const left = " 2 findings | 2 filtered"
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(left) + ` {2,}j/k`)
	for _, width := range []int{80, 60, 40} {
		m := statusBarModel(width)
		bar := m.renderStatusBar()
		plain := stripAnsi(bar)
		if !re.MatchString(plain) {
			t.Errorf("width %d: bar %q does not read %q, at least 2 spaces, then the help text", width, plain, left)
		}
		if w := ansi.StringWidth(bar); w != width {
			t.Errorf("width %d: bar is %d cells, want %d: %q", width, w, width, plain)
		}
	}
}

// ENG-9178 Phase 17 (T3-1): on a terminal narrower than the bar's content, the
// bar is clamped to the terminal width, including widths smaller than the
// left section alone.
func TestRenderStatusBar_NeverWiderThanTerminal(t *testing.T) {
	leftWidth := ansi.StringWidth(" 2 findings | 2 filtered")
	for _, width := range []int{1, 2, 5, 10, 20, leftWidth - 1, leftWidth, leftWidth + 1, leftWidth + 2} {
		m := statusBarModel(width)
		bar := m.renderStatusBar()
		if w := ansi.StringWidth(bar); w > width {
			t.Errorf("width %d: bar is %d cells: %q", width, w, stripAnsi(bar))
		}
	}
	// Narrower than the left section: what remains is the start of the counts.
	m := statusBarModel(10)
	if got, want := stripAnsi(m.renderStatusBar()), " 2 findings | 2 filtered"[:10]; got != want {
		t.Errorf("width 10: bar = %q, want %q", got, want)
	}
}

// Width 0 means the size is not known yet (View shows "Loading..."), so the
// bar is not clamped: it still carries the counts.
func TestRenderStatusBar_ZeroWidthUnclamped(t *testing.T) {
	m := statusBarModel(0)
	if got := stripAnsi(m.renderStatusBar()); !strings.HasPrefix(got, " 2 findings | 2 filtered") {
		t.Errorf("width 0: bar = %q, want it to start with the counts", got)
	}
}

// filterRow returns the stripped Filters-pane row that contains want.
func filterRow(t *testing.T, view, want string) string {
	t.Helper()
	for _, l := range strings.Split(stripAnsi(view), "\n") {
		if strings.Contains(l, want) {
			return l
		}
	}
	t.Fatalf("no Filters row contains %q:\n%s", want, stripAnsi(view))
	return ""
}

// ENG-9178 Phase 17 (T3-2): a narrow Filters pane keeps the end of a repository
// name (owner/repo) and its count; other facets still truncate at the end.
func TestFiltersPane_RepositoryLabelTruncatedFromLeft(t *testing.T) {
	rows := []*findingRow{
		{FindingID: "f1", RuleName: "Generic API Key Detector", Repositories: []string{"github.com/acme/alpha"}},
		{FindingID: "f2", RuleName: "Generic API Key Detector", Repositories: []string{"github.com/acme/alpha", "github.com/acme/beta"}},
	}
	const width = 26
	fp := newFilterPane(buildFacets(rows))
	fp.setSize(width, 20)
	view := fp.View()

	for _, want := range []string{"acme/alpha (2)", "acme/beta (1)"} {
		row := strings.TrimRight(filterRow(t, view, want), " │")
		if !strings.HasSuffix(row, want) {
			t.Errorf("repository row %q does not end with %q", row, want)
		}
		if !strings.Contains(row, "...") {
			t.Errorf("repository row %q is not marked as truncated", row)
		}
		if strings.Contains(row, "github.com") {
			t.Errorf("repository row %q kept the host instead of owner/repo", row)
		}
	}
	for i, l := range strings.Split(view, "\n") {
		if w := ansi.StringWidth(l); w > width {
			t.Errorf("line %d is %d cells, wider than the pane (%d): %q", i, w, width, stripAnsi(l))
		}
	}

	// A rule name keeps its start and loses its end.
	rule := filterRow(t, view, "Generic")
	if !regexp.MustCompile(`Generic API[^ ]*\.\.\. \(2\)`).MatchString(rule) {
		t.Errorf("rule row %q is not truncated at the end", rule)
	}
}

// truncateStringLeft must never return more cells than maxLen, even when the
// cut lands inside a 2-cell rune.
func TestTruncateStringLeft_WideRunesFit(t *testing.T) {
	for _, s := range []string{"日本語のファイル/repo", "github.com/日本語/リポジトリ", "acme/alpha"} {
		sw := ansi.StringWidth(s)
		for maxLen := 0; maxLen <= sw+1; maxLen++ {
			got := truncateStringLeft(s, maxLen)
			if w := ansi.StringWidth(got); w > maxLen {
				t.Errorf("truncateStringLeft(%q, %d) = %q, %d cells", s, maxLen, got, w)
			}
			if sw <= maxLen && got != s {
				t.Errorf("truncateStringLeft(%q, %d) = %q, want it unchanged", s, maxLen, got)
			}
			// A result that is not empty marks the cut. (When the last rune is
			// itself wider than the room left after "...", the result is empty.)
			if sw > maxLen && maxLen > 3 && got != "" && !strings.HasPrefix(got, "...") {
				t.Errorf("truncateStringLeft(%q, %d) = %q, want a \"...\" prefix", s, maxLen, got)
			}
		}
	}
}

// A single 2-cell rune does not fit one cell; before the fix it came back whole.
func TestTruncateStringLeft_WideRuneInOneCell(t *testing.T) {
	if got := truncateStringLeft("日", 1); ansi.StringWidth(got) > 1 {
		t.Errorf("truncateStringLeft(%q, 1) = %q, %d cells", "日", got, ansi.StringWidth(got))
	}
}

// A CJK repository name in a narrow pane, focused and unfocused, stays on one
// row inside the pane and keeps its count.
func TestFiltersPane_CJKRepositoryRowFits(t *testing.T) {
	const repo = "github.com/日本語のファイル/repo"
	for _, count := range []int{1, 12345} {
		// From width 20 the label keeps room for "..." beside a 5-digit count.
		for width := 20; width <= 40; width++ {
			for _, focused := range []bool{false, true} {
				fs := newFacetState()
				fs.Values[facetRepository] = []*facetValue{{FacetID: facetRepository, Value: repo, Count: count}}
				fp := newFilterPane(fs)
				fp.setSize(width, 8)
				fp.focused = focused
				fp.cursor = slices.IndexFunc(fp.items, func(it filterItem) bool { return it.Kind == filterItemValue })
				view := fp.View()

				name := fmt.Sprintf("count %d width %d focused %v", count, width, focused)
				lines := strings.Split(view, "\n")
				if len(lines) != 8 {
					t.Errorf("%s: pane is %d lines, want 8 (a row wrapped):\n%s", name, len(lines), stripAnsi(view))
				}
				for i, l := range lines {
					if w := ansi.StringWidth(l); w > width {
						t.Errorf("%s: line %d is %d cells: %q", name, i, w, stripAnsi(l))
					}
				}
				// The pane has a spare line, so a wrapped row does not always
				// change the line count; the count leaving its label's row does.
				if row := strings.TrimRight(filterRow(t, view, fmt.Sprintf("(%d)", count)), " │"); !strings.Contains(row, "...") || !strings.HasSuffix(row, fmt.Sprintf(" (%d)", count)) {
					t.Errorf("%s: count %q is not on the repository row: %q\n%s", name, fmt.Sprintf("(%d)", count), row, stripAnsi(view))
				}
			}
		}
	}
}
