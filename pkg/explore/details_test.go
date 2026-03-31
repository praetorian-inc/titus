package explore

import (
	"reflect"
	"testing"
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
