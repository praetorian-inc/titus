package explore

import (
	"reflect"
	"strings"
	"testing"
	"time"

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
