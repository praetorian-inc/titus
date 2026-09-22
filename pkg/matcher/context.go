package matcher

const defaultContextBytes = 4 * 1024

// ExtractContext extracts up to N lines before and after a match, capped at
// defaultContextBytes on each side. Returns independent copies so storing them
// will not pin the original content in memory.
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

	beforeStart := boundBefore(content, start, lines, defaultContextBytes)
	if beforeStart < start {
		before = append([]byte{}, content[beforeStart:start]...)
	}

	afterFrom := end
	if end < len(content) && content[end] == '\n' {
		afterFrom = end + 1
	}
	afterEnd := boundAfter(content, afterFrom, lines, defaultContextBytes)
	if afterEnd > afterFrom {
		after = append([]byte{}, content[afterFrom:afterEnd]...)
	}

	return before, after
}
