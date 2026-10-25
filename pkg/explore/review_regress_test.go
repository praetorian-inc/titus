package explore

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

// --- wrapLine by display width (ENG-9178 review) ---

func TestWrapLine_LongCJKPathRoundTripsWithinWidth(t *testing.T) {
	path := strings.Repeat("路", 60) // 120 cells
	if w := ansi.StringWidth(path); w != 120 {
		t.Fatalf("fixture width = %d, want 120", w)
	}
	const width = 41 // odd, so a wide rune never fits the last cell exactly
	got := wrapLine(path, width)
	if strings.Join(got, "") != path {
		t.Errorf("joined wrapped lines differ from the input:\n got %q\nwant %q", strings.Join(got, ""), path)
	}
	for i, l := range got {
		if w := ansi.StringWidth(l); w > width {
			t.Errorf("line %d is %d cells, want <= %d: %q", i, w, width, l)
		}
	}
}

func TestWrapLine_GraphemeClusterNeverSplit(t *testing.T) {
	for _, tc := range []struct{ name, cluster, input string }{
		{"combining mark", "é", "abécd"},
		{"emoji ZWJ sequence", "👨‍👩‍👧", "a👨‍👩‍👧b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if n := len([]rune(tc.cluster)); n < 2 {
				t.Fatalf("fixture: cluster %q is %d rune; it must be multi-rune (decomposed)", tc.cluster, n)
			}
			for width := 1; width <= 4; width++ {
				got := wrapLine(tc.input, width)
				if strings.Join(got, "") != tc.input {
					t.Errorf("width %d: joined %q, want %q", width, strings.Join(got, ""), tc.input)
				}
				if !slices.ContainsFunc(got, func(l string) bool { return strings.Contains(l, tc.cluster) }) {
					t.Errorf("width %d: cluster %q split across lines %q", width, tc.cluster, got)
				}
			}
		})
	}
}

// --- sanitization goldens ---

// hostile carries OSC (title set, BEL-terminated), CSI (clear screen) and C1
// CSI payloads.
const hostile = "x\x1b]0;pwn\x07\x1b[2J\u009b31my"

func assertNoTerminalControl(t *testing.T, where, out string) {
	t.Helper()
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\x07") || strings.ContainsRune(out, '\u009b') {
		t.Errorf("%s: rendered output carries a raw ESC/BEL/C1 byte: %q", where, out)
	}
}

func TestRender_HostileTextIsSanitized(t *testing.T) {
	// Precondition: with these payloads absent, the rendered panes carry no
	// ESC at all, so any ESC found below came from the payload.
	plainF := &findingRow{RuleName: "r", RuleID: "id", Matches: []*matchRow{matchWith(1, occAPI1)}}
	dp := newTestPane()
	dp.setFinding(plainF)
	assertNoTerminalControl(t, "benign details precondition", dp.View())
	// Precondition: the styling and truncation helpers pass raw escapes
	// through, so unsanitized text would reach the output and fail below.
	if !strings.Contains(fieldValueStyle.Render(hostile), "\x1b]0;") || !strings.Contains(truncateString(hostile, 40), "\x1b]0;") {
		t.Fatalf("precondition: render helpers strip escapes; this test could not fail")
	}

	detailsCases := []struct {
		name string
		mut  func(f *findingRow, m *matchRow)
	}{
		{"rule name", func(f *findingRow, _ *matchRow) { f.RuleName = hostile }},
		{"rule ID", func(f *findingRow, _ *matchRow) { f.RuleID = hostile }},
		{"categories", func(f *findingRow, _ *matchRow) { f.Categories = []string{"ok", hostile} }},
		{"finding comment", func(f *findingRow, _ *matchRow) { f.Comment = hostile }},
		{"validator message", func(_ *findingRow, m *matchRow) { m.ValidationStatus = "valid"; m.Message = hostile }},
		{"match comment", func(_ *findingRow, m *matchRow) { m.Comment = hostile }},
		{"named-group name", func(_ *findingRow, m *matchRow) { m.NamedGroups = map[string][]byte{hostile: []byte("v")} }},
	}
	for _, tc := range detailsCases {
		t.Run("details/"+tc.name, func(t *testing.T) {
			m := matchWith(1, occAPI1)
			f := &findingRow{RuleName: "r", RuleID: "id", Matches: []*matchRow{m}}
			tc.mut(f, m)
			dp := newTestPane()
			dp.setFinding(f)
			out := dp.View()
			assertNoTerminalControl(t, tc.name, out)
			if !strings.Contains(out, `\x1b]0;pwn\x07`) {
				t.Errorf("%s: escaped payload not shown:\n%s", tc.name, out)
			}
		})
	}

	t.Run("comment overlay", func(t *testing.T) {
		m := newTestModel([]*findingRow{plainF})
		m.width, m.height = 120, 40
		m.activeOverlay = overlayComment
		m.commentInput = hostile
		out := m.renderOverlay()
		assertNoTerminalControl(t, "comment overlay", out)
		if !strings.Contains(out, `\x1b]0;pwn\x07`) {
			t.Errorf("escaped comment not shown:\n%s", out)
		}
	})

	t.Run("findings-list rule cell", func(t *testing.T) {
		fp := newFindingsPane([]*findingRow{{RuleName: hostile, Matches: []*matchRow{matchWith(1, occAPI1)}}})
		fp.setSize(160, 10)
		out := fp.View()
		assertNoTerminalControl(t, "findings rule cell", out)
		if !strings.Contains(out, `\x1b]0;pwn\x07`) {
			t.Errorf("escaped rule name not shown:\n%s", out)
		}
	})
}

// --- locations cache ---

func TestDetailsPane_CopiesWithDifferentFiltersKeepOwnLocations(t *testing.T) {
	f := &findingRow{RuleName: "r", RuleID: "id", Matches: []*matchRow{matchWith(1, occAPI1, occWeb)}}
	base := newTestPane()
	base.setFinding(f)
	a, b := base, base // bubbletea-style copies share the cache pointer
	a.setRepoFilter(map[string]bool{"github.com/acme/api": true})
	b.setRepoFilter(map[string]bool{"github.com/acme/web": true})

	check := func(label string, dp detailsPane, want, notWant string) {
		t.Helper()
		v := paneView(dp)
		if !strings.Contains(v, want) || strings.Contains(v, notWant) {
			t.Errorf("%s: want %q and not %q in:\n%s", label, want, notWant, v)
		}
	}
	for range 2 { // alternate so each render follows the other copy's
		check("copy a (api)", a, "config/a.yml", "src/c.js")
		check("copy b (web)", b, "src/c.js", "config/a.yml")
	}
	// Same-length filters with different content must not collide either.
	a.setRepoFilter(map[string]bool{"github.com/acme/web": true})
	b.setRepoFilter(map[string]bool{"github.com/acme/api": true})
	check("copy a (web)", a, "src/c.js", "config/a.yml")
	check("copy b (api)", b, "config/a.yml", "src/c.js")
}

// freshContent renders the same state through a pane with an empty cache.
func freshContent(dp detailsPane) []string {
	fresh := dp
	fresh.cache = &locationsCache{}
	return fresh.contentLines()
}

func TestDetailsPane_CacheRerendersOnResizeAndMatchChange(t *testing.T) {
	long := occAPI1
	long.Path = strings.Repeat("deep/", 20) + "secret.yml"
	m1, m2 := matchWith(1, long), matchWith(2, occWeb)
	dp := newTestPane()
	dp.setFinding(&findingRow{RuleName: "r", RuleID: "id", Matches: []*matchRow{m1, m2}})
	wide := dp.contentLines()

	dp.setSize(50, 20)
	narrow := dp.contentLines()
	if slices.Equal(wide, narrow) {
		t.Fatalf("fixture: resizing must re-wrap the long path; otherwise the fresh-render comparison below cannot detect a stale cache")
	}
	if want := freshContent(dp); !slices.Equal(narrow, want) {
		t.Errorf("after resize, content =\n%q\nwant (fresh render)\n%q", narrow, want)
	}

	dp = pressKey(dp, "l", 1)
	got := stripAnsi(strings.Join(dp.contentLines(), "\n"))
	if !strings.Contains(got, "src/c.js") || strings.Contains(got, "secret.yml") {
		t.Errorf("after l, locations still show the first match:\n%s", got)
	}
	if want := freshContent(dp); !slices.Equal(dp.contentLines(), want) {
		t.Errorf("after match change, content differs from a fresh render")
	}
}

func TestDetailsPane_TenThousandLocationsAllReachable(t *testing.T) {
	const n = 10000
	occs := make([]types.Occurrence, n)
	for i := range occs {
		occs[i] = types.Occurrence{Kind: "git", Repository: "github.com/acme/web", Path: fmt.Sprintf("f%05d.js", i),
			Commit: occWeb.Commit, CommitDate: occWeb.CommitDate, HostRecorded: true}
	}
	m := matchWith(1, occs...)
	m.Provenance = []types.Provenance{types.GitProvenance{LocationsTruncated: true}}
	dp := newDetailsPane()
	dp.setSize(120, 40)
	dp.setFinding(&findingRow{RuleName: "r", RuleID: "id", Matches: []*matchRow{m}})

	maxOff := dp.maxOffset()
	if want := len(dp.contentLines()) - dp.visibleRows(); maxOff != want {
		t.Fatalf("maxOffset = %d, want %d", maxOff, want)
	}
	seen := make(map[string]bool, n)
	notice := false
	for off := 0; ; off = min(off+dp.visibleRows(), maxOff) {
		dp.offset = off
		v := stripAnsi(dp.View())
		for _, l := range strings.Split(v, "\n") {
			if i := strings.Index(l, " f0"); i >= 0 {
				seen[strings.Fields(l[i:])[0]] = true
			}
		}
		notice = notice || strings.Contains(v, "locations truncated")
		if off == maxOff {
			if !strings.Contains(v, fmt.Sprintf("f%05d.js:1", n-1)) {
				t.Errorf("final window at maxOffset %d lacks the last location:\n%s", maxOff, v)
			}
			break
		}
	}
	if len(seen) != n {
		t.Errorf("reached %d distinct locations by scrolling, want %d", len(seen), n)
	}
	if !notice {
		t.Errorf("truncation notice never shown while scrolling")
	}
}

// --- setRepoFilter and setFinding commute ---

func TestDetailsPane_RepoFilterAndFindingCommute(t *testing.T) {
	webMany := make([]types.Occurrence, 30)
	for i := range webMany {
		webMany[i] = occWeb
		webMany[i].Path = fmt.Sprintf("w%02d.js", i)
	}
	m1 := matchWith(1, occAPI1)
	m2 := matchWith(2, occAPI2, occWeb)
	m3 := matchWith(3, webMany...)
	f := &findingRow{RuleName: "r", RuleID: "id", Matches: []*matchRow{m1, m2, m3}}
	oldSel := map[string]bool{"github.com/acme/web": true} // shows matches {2,3}
	newSel := map[string]bool{"github.com/acme/api": true} // shows matches {1,2}

	start := func() detailsPane {
		dp := newTestPane()
		dp.setRepoFilter(oldSel)
		dp.setFinding(f)
		dp = pressKey(dp, "l", 1) // on match 3
		dp = pressKey(dp, "j", 5) // scrolled
		if dp.selectedMatch() != m3 || dp.offset == 0 {
			t.Fatalf("fixture: want match 3 scrolled, got cursor %d offset %d", dp.matchCursor, dp.offset)
		}
		return dp
	}
	type state struct {
		cursor, offset int
		match          *matchRow
	}
	end := func(dp detailsPane) state { return state{dp.matchCursor, dp.offset, dp.selectedMatch()} }

	filterOnly := start()
	filterOnly.setRepoFilter(newSel)
	filterFirst := start()
	filterFirst.setRepoFilter(newSel)
	filterFirst.setFinding(f)
	findingFirst := start()
	findingFirst.setFinding(f)
	findingFirst.setRepoFilter(newSel)

	want := state{0, 0, m1}
	for name, got := range map[string]state{
		"setRepoFilter only":        end(filterOnly),
		"setRepoFilter, setFinding": end(filterFirst),
		"setFinding, setRepoFilter": end(findingFirst),
	} {
		if got != want {
			t.Errorf("%s: cursor %d offset %d match %p, want cursor 0 offset 0 match 1 (%p)",
				name, got.cursor, got.offset, got.match, m1)
		}
	}
}

// --- findings table column alignment ---

func TestFindingsPane_WideRuleNameKeepsColumnsAligned(t *testing.T) {
	rows := []*findingRow{
		{RuleName: "日本語のルール名", Groups: [][]byte{[]byte("GRPWIDE")}},
		{RuleName: "ascii rule", Groups: [][]byte{[]byte("GRPASCII")}},
	}
	fp := newFindingsPane(rows)
	fp.setSize(140, 10)
	v := stripAnsi(fp.View())

	groupCol := func(marker string) int {
		t.Helper()
		for _, l := range strings.Split(v, "\n") {
			if i := strings.Index(l, marker); i >= 0 {
				return lipgloss.Width(l[:i])
			}
		}
		t.Fatalf("no row with %q in:\n%s", marker, v)
		return -1
	}
	if wide, ascii := groupCol("GRPWIDE"), groupCol("GRPASCII"); wide != ascii {
		t.Errorf("Groups column starts at cell %d after a wide rule name, %d after an ASCII one:\n%s", wide, ascii, v)
	}
}

// --- pager argv ---

func TestPagerCommand_EndsOptionsAndUsesAbsolutePath(t *testing.T) {
	t.Setenv("PAGER", "")
	for _, tc := range []struct {
		name, path string
		line       int
		wantLine   []string
	}{
		{"with line", "notes/secret.env", 7, []string{"+7"}},
		{"no line", "notes/secret.env", 0, nil},
		{"dash-leading path", "-o-evil.txt", 3, []string{"+3"}},
		{"plus-leading path", "+evil.txt", 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, args := pagerCommand(tc.path, tc.line)
			abs, err := filepath.Abs(tc.path)
			if err != nil {
				t.Fatalf("Abs: %v", err)
			}
			if name != "less" {
				t.Errorf("pager = %q, want less", name)
			}
			want := slices.Concat([]string{"-L"}, tc.wantLine, []string{"--", abs})
			if !slices.Equal(args, want) {
				t.Errorf("args = %q, want %q", args, want)
			}
			last := args[len(args)-1]
			if !filepath.IsAbs(last) || strings.HasPrefix(last, "-") || strings.HasPrefix(last, "+") {
				t.Errorf("path argument %q could be read as an option or command", last)
			}
		})
	}
	t.Run("less gets -L before the end of options", func(t *testing.T) {
		_, args := pagerCommand("notes/secret.env", 1)
		iL, iEnd := slices.Index(args, "-L"), slices.Index(args, "--")
		if iL < 0 || iEnd < 0 || iL > iEnd {
			t.Errorf("args = %q, want -L before --", args)
		}
	})
	t.Run("other pager gets an absolute path and no less flags", func(t *testing.T) {
		t.Setenv("PAGER", "more")
		name, args := pagerCommand("-o-evil.txt", 9)
		if name != "more" || len(args) != 1 || !filepath.IsAbs(args[0]) {
			t.Errorf("command = %q %q, want more [<absolute path>]", name, args)
		}
	})
}

// --- blob cache ---

// countingStore counts the per-blob loads and delegates to a memory store.
type countingStore struct {
	*store.MemoryStore
	occCalls, provCalls int
}

func (c *countingStore) GetOccurrences(id types.BlobID) ([]types.Occurrence, error) {
	c.occCalls++
	return c.MemoryStore.GetOccurrences(id)
}

func (c *countingStore) GetAllProvenance(id types.BlobID) ([]types.Provenance, error) {
	c.provCalls++
	return c.MemoryStore.GetAllProvenance(id)
}

func TestBuildFindingRow_MatchesOfOneBlobShareOneLoad(t *testing.T) {
	ms, m := occurrenceFixture(t)
	m2 := *m
	m2.StructuralID = "m2"
	cs := &countingStore{MemoryStore: ms}

	row := buildFindingRow(&types.Finding{ID: "f1", RuleID: m.RuleID}, []*types.Match{m, &m2}, map[string]*types.Rule{}, cs)

	if cs.occCalls != 1 || cs.provCalls != 1 {
		t.Errorf("store loads for one blob: GetOccurrences %d, GetAllProvenance %d; want 1 each", cs.occCalls, cs.provCalls)
	}
	if len(row.Matches) != 2 || len(row.Matches[0].Occurrences) != 3 {
		t.Fatalf("fixture: want 2 matches with 3 locations, got %+v", row.Matches)
	}
	if &row.Matches[0].Occurrences[0] != &row.Matches[1].Occurrences[0] {
		t.Errorf("matches of one blob hold separate copies of its locations")
	}
}
