package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractContext(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		start    int
		end      int
		lines    int
		wantBefore string
		wantAfter  string
	}{
		{
			name: "normal case - 2 lines before and after",
			content: `line1
line2
line3
MATCH
line5
line6
line7`,
			start:      18, // Start of "MATCH"
			end:        23, // End of "MATCH"
			lines:      2,
			wantBefore: "line2\nline3\n",
			wantAfter:  "line5\nline6\n",
		},
		{
			name: "start of file - no lines before",
			content: `MATCH
line2
line3
line4
`,
			start:      0,
			end:        5,
			lines:      3,
			wantBefore: "",
			wantAfter:  "line2\nline3\nline4\n",
		},
		{
			name: "end of file - no lines after",
			content: `line1
line2
line3
MATCH`,
			start:      18,
			end:        23,
			lines:      3,
			wantBefore: "line1\nline2\nline3\n",
			wantAfter:  "",
		},
		{
			name: "fewer lines available than requested - before",
			content: `line1
MATCH
line3
line4
`,
			start:      6,
			end:        11,
			lines:      3,
			wantBefore: "line1\n",
			wantAfter:  "line3\nline4\n",
		},
		{
			name: "fewer lines available than requested - after",
			content: `line1
line2
line3
MATCH
line5
`,
			start:      18,
			end:        23,
			lines:      3,
			wantBefore: "line1\nline2\nline3\n",
			wantAfter:  "line5\n",
		},
		{
			name: "no context requested (lines=0)",
			content: `line1
line2
MATCH
line4
line5`,
			start:      12,
			end:        17,
			lines:      0,
			wantBefore: "",
			wantAfter:  "",
		},
		{
			name: "match spans multiple lines",
			content: `line1
line2
MATCH
CONTINUES
HERE
line6
line7
`,
			start:      12, // Start of "MATCH"
			end:        33, // End of "HERE"
			lines:      2,
			wantBefore: "line1\nline2\n",
			wantAfter:  "line6\nline7\n",
		},
		{
			name: "single line file with match",
			content: "MATCH",
			start:   0,
			end:     5,
			lines:   3,
			wantBefore: "",
			wantAfter:  "",
		},
		{
			name: "match at exact line boundary",
			content: `line1
MATCH
line3
`,
			start:      6,
			end:        11,
			lines:      1,
			wantBefore: "line1\n",
			wantAfter:  "line3\n",
		},
		{
			name: "empty content",
			content:    "",
			start:      0,
			end:        0,
			lines:      3,
			wantBefore: "",
			wantAfter:  "",
		},
		{
			name: "match includes trailing newline",
			content: `line1
line2
MATCH
line4
line5`,
			start:      12,
			end:        18, // Includes newline after MATCH
			lines:      1,
			wantBefore: "line2\n",
			wantAfter:  "line4\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before, after := ExtractContext([]byte(tt.content), tt.start, tt.end, tt.lines)

			assert.Equal(t, tt.wantBefore, string(before), "before context mismatch")
			assert.Equal(t, tt.wantAfter, string(after), "after context mismatch")
		})
	}
}

func TestExtractContext_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		start      int
		end        int
		lines      int
		wantBefore string
		wantAfter  string
	}{
		{
			name: "start exceeds content length",
			content: "short",
			start:   100,
			end:     100,
			lines:   3,
			wantBefore: "",
			wantAfter:  "",
		},
		{
			name: "end exceeds content length",
			content: "short",
			start:   0,
			end:     100,
			lines:   3,
			wantBefore: "",
			wantAfter:  "",
		},
		{
			name: "negative lines (should return empty)",
			content: `line1
MATCH
line3`,
			start:      6,
			end:        11,
			lines:      -1,
			wantBefore: "",
			wantAfter:  "",
		},
		{
			name: "zero-length match (start == end)",
			content: `line1
line2
line3
line4
line5`,
			start:      12, // Point between line2 and line3
			end:        12, // Same position
			lines:      2,
			wantBefore: "line1\nline2\n",
			wantAfter:  "line3\nline4\n",
		},
		{
			name: "invalid range (start > end)",
			content: `line1
line2
line3`,
			start:      10,
			end:        5,
			lines:      2,
			wantBefore: "",
			wantAfter:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before, after := ExtractContext([]byte(tt.content), tt.start, tt.end, tt.lines)

			assert.Equal(t, tt.wantBefore, string(before), "before context mismatch")
			assert.Equal(t, tt.wantAfter, string(after), "after context mismatch")
		})
	}
}
