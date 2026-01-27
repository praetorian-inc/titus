package types

// OffsetSpan is byte range [Start, End) - half-open interval.
type OffsetSpan struct {
	Start int64
	End   int64
}

// SourcePoint is line:column position (1-based).
type SourcePoint struct {
	Line   int
	Column int
}

// SourceSpan is start-end line:column range.
type SourceSpan struct {
	Start SourcePoint
	End   SourcePoint
}

// Location combines byte offsets and source positions.
type Location struct {
	Offset OffsetSpan
	Source SourceSpan
}
