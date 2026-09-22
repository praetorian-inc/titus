package matcher

import "bytes"

// boundBefore returns the start of a region ending at "at".
// The region contains at most maxLines complete lines and at most maxBytes.
// If the byte budget runs out mid-line, the returned start is mid-line.
func boundBefore(content []byte, at, maxLines, maxBytes int) int {
	if at <= 0 || maxLines <= 0 || maxBytes <= 0 {
		return at
	}
	limit := at - maxBytes
	if limit < 0 {
		limit = 0
	}

	window := content[limit:at]
	pos := len(window)
	for range maxLines {
		i := bytes.LastIndexByte(window[:pos], '\n')
		if i < 0 {
			return limit
		}
		pos = i
	}
	i := bytes.LastIndexByte(window[:pos], '\n')
	if i < 0 {
		return limit
	}
	return limit + i + 1
}

// boundAfter returns the exclusive end of a region starting at from.
// The region contains at most maxLines complete lines and at most maxBytes.
// If the byte budget runs out mid-line, the returned end is mid-line.
func boundAfter(content []byte, from, maxLines, maxBytes int) int {
	n := len(content)
	if from >= n || maxLines <= 0 || maxBytes <= 0 {
		return from
	}
	limit := from + maxBytes
	if limit > n {
		limit = n
	}

	window := content[from:limit]
	pos := 0
	for range maxLines {
		i := bytes.IndexByte(window[pos:], '\n')
		if i < 0 {
			return limit
		}
		pos += i + 1
	}
	return from + pos
}
