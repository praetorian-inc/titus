package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBoundBefore(t *testing.T) {
	content := []byte("line1\nline2\nline3\nMATCH")
	at := 18 // start of MATCH

	tests := []struct {
		name     string
		maxLines int
		maxBytes int
		want     int
	}{
		{name: "two complete lines", maxLines: 2, maxBytes: 100, want: 6},
		{name: "one complete line", maxLines: 1, maxBytes: 100, want: 12},
		{name: "byte cap mid-line", maxLines: 10, maxBytes: 3, want: 15},
		{name: "zero lines", maxLines: 0, maxBytes: 100, want: 18},
		{name: "zero bytes", maxLines: 10, maxBytes: 0, want: 18},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, boundBefore(content, at, tt.maxLines, tt.maxBytes))
		})
	}
}

func TestBoundAfter(t *testing.T) {
	content := []byte("MATCH\nline2\nline3\nline4")
	from := 6 // start of line2

	tests := []struct {
		name     string
		maxLines int
		maxBytes int
		want     int
	}{
		{name: "two complete lines", maxLines: 2, maxBytes: 100, want: 18},
		{name: "one complete line", maxLines: 1, maxBytes: 100, want: 12},
		{name: "byte cap mid-line", maxLines: 10, maxBytes: 3, want: 9},
		{name: "zero lines", maxLines: 0, maxBytes: 100, want: 6},
		{name: "zero bytes", maxLines: 10, maxBytes: 0, want: 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, boundAfter(content, from, tt.maxLines, tt.maxBytes))
		})
	}
}
