package explore

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"
	"github.com/praetorian-inc/titus/pkg/types"
)

// SEC-7 (ENG-9178): a Repository facet value comes from scanned data, so it can
// carry terminal control sequences. The Filters pane must render it through
// types.SanitizeDisplay, while the raw value still drives selection and
// filtering.
func TestFiltersPane_SEC7_SanitizesFacetLabelsKeepsRawForFiltering(t *testing.T) {
	const hostileRepo = "evil\x1b[31mred\x1b[0m\x1b]8;;http://x\x07c1\u009bbidi\u202eoper"

	hostile := &findingRow{FindingID: "f-hostile", RuleName: "Hostile Rule", Repositories: []string{hostileRepo}}
	benign := &findingRow{FindingID: "f-benign", RuleName: "Benign Rule", Repositories: []string{"github.com/acme/web"}}
	m := newTestModel([]*findingRow{hostile, benign})
	m.filters.setSize(200, 30)

	view := m.filters.View()

	// The raw control bytes and the bidi override never reach the terminal.
	for name, raw := range map[string]string{
		"ESC (CSI/OSC introducer)": "\x1b",
		"BEL (OSC terminator)":     "\x07",
		"C1 CSI U+009B":            "\u009b",
		"bidi override U+202E":     "\u202e",
	} {
		if strings.Contains(view, raw) {
			t.Errorf("Filters pane rendered raw %s:\n%q", name, view)
		}
	}

	// The value is still visible, in SanitizeDisplay's escaped form.
	for _, want := range []string{
		`evil\x1b[31mred\x1b[0m\x1b]8;;http://x\x07c1\u{009b}bidi\u{202e}oper`,
		types.SanitizeDisplay(hostileRepo),
	} {
		if !strings.Contains(view, want) {
			t.Errorf("Filters pane missing escaped label %q:\n%q", want, view)
		}
	}

	// Selecting the rendered item, through the pane's own toggle key, filters on
	// the raw repository value.
	m.setFocus(paneFilters)
	m.filters.cursor = slices.IndexFunc(m.filters.items, func(it filterItem) bool {
		return it.Kind == filterItemValue && it.FacetID == facetRepository &&
			m.filters.facets.Values[facetRepository][it.ValueIdx].Value == hostileRepo
	})
	if m.filters.cursor < 0 {
		t.Fatalf("fixture: no Repository item for the hostile value")
	}

	next, _ := m.Update(runeKey('x'))
	m = next.(Model)

	if got, want := m.filters.facets.selectedValues(facetRepository), map[string]bool{hostileRepo: true}; !maps.Equal(got, want) {
		t.Errorf("selected Repository values = %v, want %v", got, want)
	}
	if len(m.findings.rows) != 1 {
		t.Fatalf("findings under the hostile facet = %d rows, want 1", len(m.findings.rows))
	}
	if m.findings.rows[0] != hostile {
		t.Errorf("filtered finding = %q, want %q", m.findings.rows[0].FindingID, hostile.FindingID)
	}
}

// truncateString must cut by display column and never split a rune: facet
// labels can be multibyte, and a split rune renders as invalid UTF-8.
func TestTruncateString_ColumnAndRuneAware(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		maxLen int
		want   string
	}{
		{name: "zero width", in: "github.com/acme/web", maxLen: 0, want: ""},
		{name: "negative width", in: "github.com/acme/web", maxLen: -5, want: ""},
		{name: "fits unchanged", in: "acme/web", maxLen: 20, want: "acme/web"},
		{name: "exact fit unchanged", in: "acme/web", maxLen: 8, want: "acme/web"},
		{name: "short cut has no ellipsis", in: "abcdef", maxLen: 3, want: "abc"},
		{name: "short cut width 1", in: "abcdef", maxLen: 1, want: "a"},
		{name: "ascii cut with ellipsis", in: "abcdefghij", maxLen: 6, want: "abc..."},
		{name: "two-byte runes would split under byte slicing", in: strings.Repeat("é", 10), maxLen: 6, want: "ééé..."},
		{name: "wide CJK runes would split under byte slicing", in: "リポジトリ/秘密", maxLen: 8, want: "リポ..."},
		{name: "wide CJK short cut splits rune under byte slicing", in: "リポジトリ/秘密", maxLen: 2, want: "リ"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := truncateString(tt.in, tt.maxLen)
			if out != tt.want {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.in, tt.maxLen, out, tt.want)
			}
			if !utf8.ValidString(out) {
				t.Errorf("truncateString(%q, %d) = %q: invalid UTF-8", tt.in, tt.maxLen, out)
			}
			if w := ansi.StringWidth(out); w > max(tt.maxLen, 0) {
				t.Errorf("truncateString(%q, %d) = %q: width %d exceeds %d", tt.in, tt.maxLen, out, w, tt.maxLen)
			}
			if tt.maxLen > 0 && tt.maxLen <= 3 && strings.Contains(out, "...") {
				t.Errorf("truncateString(%q, %d) = %q: short cut must have no ellipsis tail", tt.in, tt.maxLen, out)
			}
		})
	}
}
