package explore

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"
)

// ENG-9178: pressing y copies the selected finding's secret. The clipboard
// payload must stay byte-exact, but the "Copied: ..." flash message is drawn in
// the status bar, so it must never carry terminal control sequences and its
// preview must be truncated by display column without splitting a rune.
func TestModel_CopySecretFlashIsSanitizedAndColumnTruncated(t *testing.T) {
	tests := []struct {
		name          string
		secret        string
		wantPreview   string // exact preview after "Copied: "; empty means not pinned
		wantTruncated bool   // preview ends with "..."
	}{
		{name: "hostile control sequences", secret: "AKIA\x1b[31mX\x1b]0;pwn\x07\u009b2J\u202eZ", wantPreview: "AKIA.[31mX.]0;pwn...2J...Z"},
		// Secret bytes render through the ASCII-only sanitizeForDisplay: every
		// non-printable-ASCII byte becomes '.', then the line is cut to 40
		// columns including the ellipsis.
		{name: "long CJK secret", secret: strings.Repeat("秘", 30), wantPreview: strings.Repeat(".", 37) + "...", wantTruncated: true},
		{name: "long two-byte secret", secret: strings.Repeat("é", 50), wantPreview: strings.Repeat(".", 37) + "...", wantTruncated: true},
		{name: "short ascii secret", secret: "AKIAEXAMPLE123", wantPreview: "AKIAEXAMPLE123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &findingRow{FindingID: "f-copy", RuleName: "Copy Rule", Groups: [][]byte{[]byte(tt.secret)}}
			m := newTestModel([]*findingRow{f})
			if got := m.findings.selectedFinding(); got != f {
				t.Fatalf("fixture: expected the finding selected, got %+v", got)
			}

			next, _ := m.Update(runeKey('y'))
			m = next.(Model)

			if m.pendingClipboard != tt.secret {
				t.Errorf("pendingClipboard = %q, want the raw secret %q", m.pendingClipboard, tt.secret)
			}

			preview, ok := strings.CutPrefix(m.flashMsg, "Copied: ")
			if !ok {
				t.Fatalf("flashMsg = %q, want a %q prefix", m.flashMsg, "Copied: ")
			}
			if !utf8.ValidString(m.flashMsg) {
				t.Errorf("flashMsg is not valid UTF-8: %q", m.flashMsg)
			}
			for _, r := range m.flashMsg {
				if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == '\u202e' {
					t.Errorf("flashMsg contains control/bidi rune %U: %q", r, m.flashMsg)
				}
			}
			if w := ansi.StringWidth(preview); w > 40 {
				t.Errorf("preview display width = %d, want <= 40: %q", w, preview)
			}
			if tt.wantPreview != "" && preview != tt.wantPreview {
				t.Errorf("preview = %q, want %q", preview, tt.wantPreview)
			}
			if tt.wantTruncated && !strings.HasSuffix(preview, "...") {
				t.Errorf("long secret preview %q does not end with \"...\"", preview)
			}
		})
	}
}
