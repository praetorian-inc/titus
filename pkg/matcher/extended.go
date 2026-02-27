//go:build !wasm

package matcher

import (
	"regexp"
	"strings"
)

// stripExtendedMode preprocesses a regex pattern to remove extended mode syntax.
// If the pattern starts with a flag group containing 'x' (e.g., (?x), (?xi), (?xis)), this function:
// 1. Removes only the 'x' flag from the group (other flags like i, s, m are preserved)
// 2. Removes all whitespace (except escaped whitespace like \s or \ )
// 3. Removes all comments in the form (?# ... )
// 4. Removes all # line-end comments (from unescaped # outside character classes to end of line)
//
// This is necessary because the Hyperscan library (gohs) doesn't support the Extended flag,
// which allows free-spacing mode with comments in regex patterns.
func stripExtendedMode(pattern string) string {
	// Check if pattern uses extended mode by looking for (?...) with x flag
	pattern = strings.TrimSpace(pattern)
	if len(pattern) < 4 || pattern[0:2] != "(?" {
		return pattern
	}

	// Find the closing ) of the flag group
	closeIdx := strings.Index(pattern[2:], ")")
	if closeIdx == -1 {
		return pattern
	}

	flags := pattern[2 : 2+closeIdx]
	if !strings.Contains(flags, "x") {
		return pattern
	}

	// Remove only the 'x' flag, preserve other flags
	remainingFlags := strings.ReplaceAll(flags, "x", "")
	rest := pattern[2+closeIdx+1:]

	// Rebuild pattern with remaining flags (if any)
	if remainingFlags != "" {
		pattern = "(?" + remainingFlags + ")" + rest
	} else {
		pattern = rest
	}

	// Remove comments (?# ... )
	// This regex matches (?# followed by any characters until the closing )
	commentRegex := regexp.MustCompile(`\(\?#[^)]*\)`)
	pattern = commentRegex.ReplaceAllString(pattern, "")

	// Remove inline flag modifiers that Hyperscan doesn't support
	// (?s) - DotAll - already set via hyperscan.DotAll flag
	// (?m) - MultiLine - already set via hyperscan.MultiLine flag
	pattern = strings.ReplaceAll(pattern, "(?s)", "")
	pattern = strings.ReplaceAll(pattern, "(?m)", "")

	// Remove unescaped whitespace and # line-end comments.
	// We need to be careful to preserve:
	// - Escaped spaces: \ (backslash followed by space)
	// - Whitespace escape sequences: \s, \t, \n, \r, etc.
	// - # inside character classes [...] (not a comment there)
	//
	// Strategy: Process byte by byte (pattern is ASCII-safe after flag removal),
	// tracking escape and character-class state.
	var result strings.Builder
	bytes := []byte(pattern)
	escaped := false
	inCharClass := false
	i := 0

	for i < len(bytes) {
		char := bytes[i]

		if escaped {
			// Previous character was backslash, keep this character regardless
			result.WriteByte(char)
			escaped = false
			i++
			continue
		}

		if char == '\\' {
			if i+1 < len(bytes) {
				// Write the backslash and mark as escaped
				result.WriteByte(char)
				escaped = true
			} else {
				// Trailing backslash, keep it
				result.WriteByte(char)
			}
			i++
			continue
		}

		// Track character class boundaries
		if char == '[' && !inCharClass {
			inCharClass = true
			result.WriteByte(char)
			i++
			continue
		}
		if char == ']' && inCharClass {
			inCharClass = false
			result.WriteByte(char)
			i++
			continue
		}

		// In extended mode, unescaped # outside a character class starts a line-end comment.
		// Skip from # to the end of the line (the newline itself is stripped as whitespace).
		if char == '#' && !inCharClass {
			// Skip everything until we hit a newline or end of string
			for i < len(bytes) && bytes[i] != '\n' {
				i++
			}
			// The newline (if present) will be handled on the next iteration and stripped
			// as unescaped whitespace.
			continue
		}

		// Skip unescaped whitespace (space, tab, newline, carriage return)
		if char == ' ' || char == '\t' || char == '\n' || char == '\r' {
			i++
			continue
		}

		// Keep all other characters
		result.WriteByte(char)
		i++
	}

	return result.String()
}
