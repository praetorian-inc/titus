package explore

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/praetorian-inc/titus/pkg/types"
)

func TestWrapLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxWidth int
		want     []string
	}{
		{
			name:     "short string no wrap",
			input:    "hello",
			maxWidth: 10,
			want:     []string{"hello"},
		},
		{
			name:     "exact width",
			input:    "12345",
			maxWidth: 5,
			want:     []string{"12345"},
		},
		{
			name:     "wraps at maxWidth",
			input:    "ABCDEFGHIJ",
			maxWidth: 4,
			want:     []string{"ABCD", "EFGH", "IJ"},
		},
		{
			name:     "preserves newlines",
			input:    "abc\ndef",
			maxWidth: 10,
			want:     []string{"abc", "def"},
		},
		{
			name:     "wraps and preserves newlines",
			input:    "ABCDEF\nGHIJKL",
			maxWidth: 4,
			want:     []string{"ABCD", "EF", "GHIJ", "KL"},
		},
		{
			name:     "empty string",
			input:    "",
			maxWidth: 10,
			want:     []string{""},
		},
		{
			name:     "zero width returns as-is",
			input:    "hello",
			maxWidth: 0,
			want:     []string{"hello"},
		},
		{
			name:     "negative width returns as-is",
			input:    "hello",
			maxWidth: -1,
			want:     []string{"hello"},
		},
		{
			name:     "width of 1",
			input:    "abc",
			maxWidth: 1,
			want:     []string{"a", "b", "c"},
		},
		{
			name:     "trailing newline",
			input:    "abc\n",
			maxWidth: 10,
			want:     []string{"abc", ""},
		},
		{
			name:     "multibyte runes stay whole",
			input:    "ab日本語cd",
			maxWidth: 3,
			want:     []string{"ab日", "本語c", "d"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapLine(tt.input, tt.maxWidth)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("wrapLine(%q, %d) = %v, want %v", tt.input, tt.maxWidth, got, tt.want)
			}
		})
	}
}

// --- Locations section (ENG-9178 T014) ---

var (
	occAPI1 = types.Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "config/a.yml",
		Commit: "7d0e8151234567890", CommitDate: time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC), HostRecorded: true}
	occAPI2 = types.Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "config/b.yml",
		Commit: "abcdef0123456789", CommitDate: time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC), HostRecorded: true}
	occWeb = types.Occurrence{Kind: "git", Repository: "github.com/acme/web", Path: "src/c.js",
		Commit: "0011223344556677", CommitDate: time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC), HostRecorded: true}
)

func matchWith(line int, occs ...types.Occurrence) *matchRow {
	m := &matchRow{Occurrences: occs}
	m.Location.Source.Start.Line = line
	return m
}

// plainLines renders a match and returns its ANSI-stripped lines.
func plainLines(m *matchRow, sel map[string]bool, width int) []string {
	raw := renderMatchDetails(m, sel, width)
	out := make([]string, len(raw))
	for i, l := range raw {
		out[i] = stripAnsi(l)
	}
	return out
}

// locationBlock returns the Locations heading and the indented lines under it.
func locationBlock(t *testing.T, lines []string) (string, []string) {
	t.Helper()
	for i, l := range lines {
		if !strings.HasPrefix(l, "  Locations ") {
			continue
		}
		var body []string
		for _, b := range lines[i+1:] {
			if !strings.HasPrefix(b, "    ") {
				break
			}
			body = append(body, b)
		}
		return l, body
	}
	t.Fatalf("no Locations heading in %q", lines)
	return "", nil
}

func expectedLines(occs []types.Occurrence, line int) []string {
	disp := types.DisambiguateDisplay(occs)
	out := make([]string, len(occs))
	for i, o := range occs {
		out[i] = "    " + types.SanitizeDisplay(types.FormatLine(o, line, disp[i]))
	}
	return out
}

// Design §7 test 1.
func TestRenderLocations_OneLinePerLocationInStoreOrder(t *testing.T) {
	m := matchWith(12, occAPI1, occAPI2, occWeb)
	heading, body := locationBlock(t, plainLines(m, nil, 500))
	if heading != "  Locations 3:" {
		t.Errorf("heading = %q, want %q", heading, "  Locations 3:")
	}
	want := expectedLines(m.Occurrences, 12)
	if !reflect.DeepEqual(body, want) {
		t.Errorf("location lines =\n%q\nwant\n%q", body, want)
	}
	if want[0] != "    github.com/acme/api  config/a.yml:12  7d0e815  2026-06-15" {
		t.Errorf("formatter text drifted: %q", want[0])
	}
}

// Design §7 test 2.
func TestRenderLocations_WorkingTreeAndHostNotRecorded(t *testing.T) {
	wt := types.Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "x.env", WorkingTree: true,
		AbsolutePath: "/home/u/api/x.env", HostRecorded: true}
	legacy := types.Occurrence{Kind: "git", Repository: "acme/api", Path: "y.env", Commit: "fedcba9876543210",
		CommitDate: time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)}
	m := matchWith(3, wt, legacy)
	_, body := locationBlock(t, plainLines(m, nil, 500))
	want := []string{
		"    github.com/acme/api  x.env:3  working tree",
		"    acme/api  y.env:3  fedcba9  2025-01-02  host not recorded",
	}
	if !reflect.DeepEqual(body, want) {
		t.Errorf("location lines =\n%q\nwant\n%q", body, want)
	}
}

// Design §7 test 3.
func TestRenderLocations_SameTextPairShowsAbsolutePaths(t *testing.T) {
	a := types.Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "k.pem", WorkingTree: true,
		AbsolutePath: "/a/api/k.pem", HostRecorded: true}
	b := a
	b.AbsolutePath = "/b/api/k.pem"
	m := matchWith(1, a, b)
	_, body := locationBlock(t, plainLines(m, nil, 500))
	want := []string{
		"    github.com/acme/api  /a/api/k.pem:1  working tree",
		"    github.com/acme/api  /b/api/k.pem:1  working tree",
	}
	if !reflect.DeepEqual(body, want) {
		t.Errorf("location lines =\n%q\nwant\n%q", body, want)
	}
}

// Design §7 test 4 (SEC-6, SEC-7).
func TestRenderLocations_SanitizesControlAndBidi(t *testing.T) {
	rawPath := "evil\x1b[2J\rname‮txt.yml"
	o := types.Occurrence{Kind: "file", Path: rawPath, HostRecorded: true}
	m := matchWith(5, o)
	raw := strings.Join(renderMatchDetails(m, nil, 500), "\n")
	if strings.Contains(raw, "\x1b[2J") || strings.ContainsRune(raw, '\r') || strings.ContainsRune(raw, '‮') {
		t.Fatalf("rendered output carries a raw control or bidi rune: %q", raw)
	}
	_, body := locationBlock(t, plainLines(m, nil, 500))
	want := []string{`    evil\x1b[2J\x0dname\u{202e}txt.yml:5`}
	if !reflect.DeepEqual(body, want) {
		t.Errorf("location lines = %q, want %q", body, want)
	}
	if m.Occurrences[0].Path != rawPath {
		t.Errorf("matchRow path mutated: %q", m.Occurrences[0].Path)
	}
}

func TestRenderLocations_ExtendedDetailKeptAndSanitized(t *testing.T) {
	prov := types.ExtendedProvenance{Payload: map[string]any{
		"source": "linear", "path": "ENG-1/description", "identifier": "ENG-1\x1b[31m",
		"entityType": "issue", "title": "Leak", "url": "https://linear.app/x/issue/ENG-1",
	}}
	o := types.Occurrence{Kind: "extended", Source: "linear", Path: "ENG-1/description", HostRecorded: true}
	m := matchWith(2, o)
	m.Provenance = []types.Provenance{prov}
	lines := plainLines(m, nil, 500)
	joined := strings.Join(lines, "\n")
	for _, want := range []string{
		"    linear  ENG-1/description:2",
		`  Issue: ENG-1\x1b[31m`,
		"  Title: Leak",
		"  URL: https://linear.app/x/issue/ENG-1",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("missing line %q in\n%s", want, joined)
		}
	}
	if slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, "  Source:") }) {
		t.Errorf("Source: line duplicates the location line:\n%s", joined)
	}
	// Narrowed to another repository, the extended detail is hidden with its location.
	other := plainLines(m, map[string]bool{"github.com/acme/web": true}, 500)
	if slices.Contains(other, "  Title: Leak") {
		t.Errorf("extended detail shown for an unselected source:\n%s", strings.Join(other, "\n"))
	}
}

func TestRenderMatchDetails_RangeLabelNoAuthorDate(t *testing.T) {
	m := matchWith(4, occAPI1)
	m.Location.Source.Start.Column = 2
	m.Location.Source.End.Line = 4
	m.Location.Source.End.Column = 9
	m.Provenance = []types.Provenance{types.GitProvenance{RepoPath: "github.com/acme/api", BlobPath: "config/a.yml",
		Commit: &types.CommitMetadata{CommitID: occAPI1.Commit, AuthorName: "Ann", AuthorEmail: "a@x",
			CommitterTimestamp: occAPI1.CommitDate}}}
	lines := plainLines(m, nil, 500)
	joined := strings.Join(lines, "\n")
	if !slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, "  Range: 4:2 - 4:9") }) {
		t.Errorf("missing Range: line:\n%s", joined)
	}
	for _, gone := range []string{"Location:", "Author:", "Date:", "Repo:", "Commit:"} {
		if strings.Contains(joined, gone) {
			t.Errorf("unexpected %q in:\n%s", gone, joined)
		}
	}
}

// Design §7 test 7.
func TestRenderLocations_LongLineWraps(t *testing.T) {
	long := types.Occurrence{Kind: "git", Repository: "github.com/acme/api",
		Path: strings.Repeat("deep/", 20) + "secret.yml", Commit: occAPI1.Commit, CommitDate: occAPI1.CommitDate, HostRecorded: true}
	m := matchWith(7, long)
	const width = 46
	_, body := locationBlock(t, plainLines(m, nil, width))
	if len(body) < 2 {
		t.Fatalf("expected wrapped lines, got %q", body)
	}
	var rebuilt strings.Builder
	for i, l := range body {
		indent := "      "
		if i == 0 {
			indent = "    "
		}
		rest, ok := strings.CutPrefix(l, indent)
		if !ok || (i > 0 && strings.HasPrefix(rest, " ")) {
			t.Errorf("line %d has wrong indent: %q", i, l)
		}
		if len(rest) > width-6 {
			t.Errorf("line %d longer than wrap width %d: %q", i, width-6, rest)
		}
		rebuilt.WriteString(rest)
	}
	if want := types.FormatLine(long, 7, ""); rebuilt.String() != want {
		t.Errorf("wrapped text = %q, want %q", rebuilt.String(), want)
	}
	if strings.Contains(strings.Join(body, ""), "...") {
		t.Errorf("location line truncated with ...: %q", body)
	}
}

func newTestPane() detailsPane {
	dp := newDetailsPane()
	dp.setSize(120, 20)
	dp.focused = true
	return dp
}

func paneView(dp detailsPane) string {
	return stripAnsi(dp.View())
}

func pressKey(dp detailsPane, k string, n int) detailsPane {
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
	for range n {
		dp, _ = dp.Update(msg)
	}
	return dp
}

// Design §7 test 5, C-EXPLORE-1: api x2 + web x1; facet web -> Locations 1,
// Match 1/1; cleared -> Locations 3.
func TestDetailsPane_RepoFilterNarrowsLocations(t *testing.T) {
	f := &findingRow{RuleName: "r", RuleID: "id", Matches: []*matchRow{matchWith(1, occAPI1, occAPI2, occWeb)}}
	dp := newTestPane()
	dp.setRepoFilter(map[string]bool{"github.com/acme/web": true})
	dp.setFinding(f)
	v := paneView(dp)
	if !strings.Contains(v, "Locations 1:") || !strings.Contains(v, "Match 1/1") {
		t.Errorf("narrowed view missing Locations 1: / Match 1/1:\n%s", v)
	}
	if strings.Contains(v, "acme/api") {
		t.Errorf("narrowed view shows an unselected repository:\n%s", v)
	}
	dp.setRepoFilter(nil)
	dp.setFinding(f)
	v = paneView(dp)
	if !strings.Contains(v, "Locations 3:") || !strings.Contains(v, "Match 1/1") {
		t.Errorf("cleared view missing Locations 3: / Match 1/1:\n%s", v)
	}
}

// Design §7 test 6.
func TestDetailsPane_NavigationSkipsMatchesWithoutVisibleLocation(t *testing.T) {
	m1, m2, m3 := matchWith(1, occWeb), matchWith(2, occAPI1), matchWith(3, occWeb)
	f := &findingRow{Matches: []*matchRow{m1, m2, m3}}
	dp := newTestPane()
	dp.setRepoFilter(map[string]bool{"github.com/acme/web": true})
	dp.setFinding(f)
	if !reflect.DeepEqual(dp.visibleMatchIdx, []int{0, 2}) {
		t.Fatalf("visibleMatchIdx = %v, want [0 2]", dp.visibleMatchIdx)
	}
	if v := paneView(dp); !strings.Contains(v, "Match 1/2") {
		t.Errorf("want Match 1/2:\n%s", v)
	}
	dp = pressKey(dp, "l", 1)
	if dp.selectedMatch() != m3 || !strings.Contains(paneView(dp), "Match 2/2") {
		t.Errorf("l should land on the third match as Match 2/2; cursor %d", dp.matchCursor)
	}
	dp = pressKey(dp, "l", 1)
	if dp.selectedMatch() != m3 {
		t.Errorf("l past the last visible match moved the cursor")
	}
	dp = pressKey(dp, "h", 1)
	if dp.selectedMatch() != m1 {
		t.Errorf("h should return to the first match")
	}
	dp.setRepoFilter(nil)
	if !reflect.DeepEqual(dp.visibleMatchIdx, []int{0, 1, 2}) {
		t.Errorf("cleared visibleMatchIdx = %v, want [0 1 2]", dp.visibleMatchIdx)
	}
}

func TestDetailsPane_StartsOnFirstMatchWithVisibleLocation(t *testing.T) {
	m1, m2 := matchWith(1, occAPI1), matchWith(2, occWeb)
	dp := newTestPane()
	dp.setRepoFilter(map[string]bool{"github.com/acme/web": true})
	dp.setFinding(&findingRow{Matches: []*matchRow{m1, m2}})
	if dp.selectedMatch() != m2 {
		t.Errorf("selectedMatch should be the first match with a visible location")
	}
}

func TestDetailsPane_NilFinding(t *testing.T) {
	dp := newTestPane()
	dp.setRepoFilter(map[string]bool{"x": true})
	dp.setFinding(nil)
	if dp.selectedMatch() != nil || len(dp.visibleMatchIdx) != 0 {
		t.Errorf("nil finding: selectedMatch %v, visibleMatchIdx %v", dp.selectedMatch(), dp.visibleMatchIdx)
	}
	dp = pressKey(dp, "l", 1)
	dp = pressKey(dp, "j", 5)
	if dp.offset != 0 {
		t.Errorf("offset = %d, want 0 on a one-line view", dp.offset)
	}
}

// Architecture §1.6: the scroll offset is clamped.
func TestDetailsPane_ScrollOffsetClamped(t *testing.T) {
	var occs []types.Occurrence
	for i := range 40 {
		o := occWeb
		o.Path = fmt.Sprintf("f%02d.js", i)
		occs = append(occs, o)
	}
	dp := newTestPane()
	dp.setFinding(&findingRow{Matches: []*matchRow{matchWith(1, occs...)}})
	dp = pressKey(dp, "j", 100)
	bottom := paneView(dp)
	maxOff := dp.offset
	if maxOff == 0 || maxOff >= 100 {
		t.Fatalf("offset after 100 j = %d, want clamped above 0", maxOff)
	}
	dp = pressKey(dp, "k", 1)
	if dp.offset != maxOff-1 {
		t.Errorf("one k after over-scrolling moved offset to %d, want %d", dp.offset, maxOff-1)
	}
	if paneView(dp) == bottom {
		t.Errorf("one k after over-scrolling did not change the view")
	}
}
