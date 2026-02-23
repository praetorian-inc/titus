package matcher

// ExtractContext extracts N lines before and after a match.
// Returns before, after byte slices that are independent copies (not sub-slices
// of content), so storing them will not pin the original content in memory.
// Handles file boundaries gracefully (returns empty if at start/end).
// Context starts immediately before the start offset and ends immediately after the end offset.
// The matched content itself (between start and end) is not duplicated in the context.
func ExtractContext(content []byte, start, end int, lines int) (before, after []byte) {
	if lines <= 0 {
		return nil, nil
	}
	if start < 0 || start > len(content) {
		return nil, nil
	}
	if end < 0 || end > len(content) {
		return nil, nil
	}
	if start > end {
		return nil, nil
	}

	// Copy sub-slices to decouple from the original content backing array.
	// Without this, storing a small context snippet keeps the entire
	// file content pinned in memory via the shared underlying array.
	if b := extractBefore(content, start, lines); len(b) > 0 {
		before = append([]byte{}, b...)
	}
	if a := extractAfter(content, end, lines); len(a) > 0 {
		after = append([]byte{}, a...)
	}

	return before, after
}

// extractBefore finds N lines before the start offset.
// Walks backward from start, counting newlines.
func extractBefore(content []byte, start, lines int) []byte {
	if start == 0 {
		return nil
	}

	// Start at position before the match
	pos := start - 1
	linesFound := 0

	// Walk backward counting newlines
	// We need to find N newlines to get N lines
	for pos >= 0 {
		if content[pos] == '\n' {
			linesFound++
			if linesFound == lines {
				// Found N newlines, now find where the Nth line starts
				// Continue backward to find the start of the Nth line
				for pos > 0 {
					pos--
					if content[pos] == '\n' {
						// Found the newline before the Nth line
						return content[pos+1 : start]
					}
				}
				// Reached start of file - Nth line starts at position 0
				return content[0:start]
			}
		}
		pos--
	}

	// Reached start of file before finding N lines
	// Return from start of file to match start
	return content[0:start]
}

// extractAfter finds N lines after the end offset.
// Walks forward from end, counting newlines.
func extractAfter(content []byte, end, lines int) []byte {
	if end >= len(content) {
		return nil
	}

	// If end points to a newline, skip it (it's part of the match line)
	start := end
	if content[end] == '\n' {
		start = end + 1
		if start >= len(content) {
			return nil
		}
	}

	// Walk forward counting newlines to find N complete lines
	pos := start
	linesFound := 0

	for pos < len(content) {
		if content[pos] == '\n' {
			linesFound++
			if linesFound == lines {
				// Found N lines, include up to and including this newline
				return content[start : pos+1]
			}
		}
		pos++
	}

	// Reached end of file before finding N lines
	// Return from start position to end of file
	return content[start:]
}
