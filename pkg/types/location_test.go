package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOffsetSpan(t *testing.T) {
	span := OffsetSpan{Start: 10, End: 20}
	assert.Equal(t, int64(10), span.Start)
	assert.Equal(t, int64(20), span.End)
}

func TestSourcePoint(t *testing.T) {
	point := SourcePoint{Line: 5, Column: 12}
	assert.Equal(t, 5, point.Line)
	assert.Equal(t, 12, point.Column)
}

func TestSourceSpan(t *testing.T) {
	span := SourceSpan{
		Start: SourcePoint{Line: 1, Column: 5},
		End:   SourcePoint{Line: 3, Column: 10},
	}
	assert.Equal(t, 1, span.Start.Line)
	assert.Equal(t, 5, span.Start.Column)
	assert.Equal(t, 3, span.End.Line)
	assert.Equal(t, 10, span.End.Column)
}

func TestLocation(t *testing.T) {
	loc := Location{
		Offset: OffsetSpan{Start: 100, End: 200},
		Source: SourceSpan{
			Start: SourcePoint{Line: 10, Column: 1},
			End:   SourcePoint{Line: 12, Column: 15},
		},
	}

	assert.Equal(t, int64(100), loc.Offset.Start)
	assert.Equal(t, int64(200), loc.Offset.End)
	assert.Equal(t, 10, loc.Source.Start.Line)
	assert.Equal(t, 1, loc.Source.Start.Column)
	assert.Equal(t, 12, loc.Source.End.Line)
	assert.Equal(t, 15, loc.Source.End.Column)
}

func TestOffsetSpan_HalfOpen(t *testing.T) {
	// OffsetSpan is [Start, End) - half-open interval
	// This test documents the semantic meaning
	span := OffsetSpan{Start: 0, End: 5}

	// A 5-byte span [0, 5) includes bytes at indices 0, 1, 2, 3, 4
	// but NOT byte at index 5
	assert.Equal(t, int64(0), span.Start)
	assert.Equal(t, int64(5), span.End)

	// Length is End - Start
	length := span.End - span.Start
	assert.Equal(t, int64(5), length)
}

func TestSourcePoint_OneBased(t *testing.T) {
	// SourcePoint is 1-based (line 1 is first line, column 1 is first column)
	// This test documents the semantic meaning
	point := SourcePoint{Line: 1, Column: 1}
	assert.Equal(t, 1, point.Line)
	assert.Equal(t, 1, point.Column)

	// Line 0 or Column 0 would be invalid in practice
	// (but we don't enforce validation in the type itself)
}
