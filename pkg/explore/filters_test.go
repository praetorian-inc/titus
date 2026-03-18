package explore

import "testing"

func TestSanitizeForDisplay(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "printable ascii",
			input: []byte("hello world"),
			want:  "hello world",
		},
		{
			name:  "preserves newlines but replaces tabs and carriage returns",
			input: []byte("line1\n\tline2\r\n"),
			want:  "line1\n.line2.\n",
		},
		{
			name:  "replaces null bytes",
			input: []byte("abc\x00def"),
			want:  "abc.def",
		},
		{
			name:  "replaces control characters",
			input: []byte("\x01\x02\x03\x1b\x7f"),
			want:  ".....",
		},
		{
			name:  "replaces high bytes",
			input: []byte{0x80, 0xFF, 0xFE},
			want:  "...",
		},
		{
			name:  "mixed binary and text",
			input: []byte("password=\x00s3cret\x01\x02"),
			want:  "password=.s3cret..",
		},
		{
			name:  "empty input",
			input: []byte{},
			want:  "",
		},
		{
			name:  "nil input",
			input: nil,
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeForDisplay(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeForDisplay(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
