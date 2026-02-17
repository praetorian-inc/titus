package types

import "testing"

func TestComputeLineColumn(t *testing.T) {
	tests := []struct {
		name       string
		content    []byte
		byteOffset int
		wantLine   int
		wantColumn int
	}{
		{
			name:       "empty content at offset 0",
			content:    []byte{},
			byteOffset: 0,
			wantLine:   1,
			wantColumn: 1,
		},
		{
			name:       "single line at offset 2",
			content:    []byte("hello"),
			byteOffset: 2,
			wantLine:   1,
			wantColumn: 3,
		},
		{
			name:       "multi-line at offset 7",
			content:    []byte("hello\nworld"),
			byteOffset: 7,
			wantLine:   2,
			wantColumn: 2,
		},
		{
			name:       "offset at newline",
			content:    []byte("hello\nworld"),
			byteOffset: 5,
			wantLine:   1,
			wantColumn: 6,
		},
		{
			name:       "offset beyond content length",
			content:    []byte("hello"),
			byteOffset: 100,
			wantLine:   1,
			wantColumn: 6,
		},
		{
			name:       "offset at start of second line",
			content:    []byte("hello\nworld"),
			byteOffset: 6,
			wantLine:   2,
			wantColumn: 1,
		},
		{
			name:       "multiple newlines",
			content:    []byte("line1\nline2\nline3"),
			byteOffset: 12,
			wantLine:   3,
			wantColumn: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLine, gotColumn := ComputeLineColumn(tt.content, tt.byteOffset)
			if gotLine != tt.wantLine {
				t.Errorf("ComputeLineColumn() line = %v, want %v", gotLine, tt.wantLine)
			}
			if gotColumn != tt.wantColumn {
				t.Errorf("ComputeLineColumn() column = %v, want %v", gotColumn, tt.wantColumn)
			}
		})
	}
}
