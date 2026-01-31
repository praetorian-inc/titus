//go:build !wasm

package matcher

import (
	"regexp"
	"strings"
)

// stripExtendedMode preprocesses a regex pattern to remove extended mode syntax.
// If the pattern starts with (?x), this function:
// 1. Removes the (?x) flag
// 2. Removes all whitespace (except escaped whitespace like \s or \ )
// 3. Removes all comments in the form (?# ... )
//
// This is necessary because the Hyperscan library (gohs) doesn't support the Extended flag,
// which allows free-spacing mode with comments in regex patterns.
func stripExtendedMode(pattern string) string {
	// Check if pattern uses extended mode
	if !strings.HasPrefix(strings.TrimSpace(pattern), "(?x)") {
		return pattern
	}

	// Remove the (?x) flag
	pattern = strings.TrimSpace(pattern)
	pattern = strings.TrimPrefix(pattern, "(?x)")

	// Remove comments (?# ... )
	// This regex matches (?# followed by any characters until the closing )
	commentRegex := regexp.MustCompile(`\(\?#[^)]*\)`)
	pattern = commentRegex.ReplaceAllString(pattern, "")

	// Remove inline flag modifiers that Hyperscan doesn't support
	// (?s) - DotAll - already set via hyperscan.DotAll flag
	// (?m) - MultiLine - already set via hyperscan.MultiLine flag
	pattern = strings.ReplaceAll(pattern, "(?s)", "")
	pattern = strings.ReplaceAll(pattern, "(?m)", "")

	// Remove unescaped whitespace
	// We need to be careful to preserve:
	// - Escaped spaces: \ (backslash followed by space)
	// - Whitespace escape sequences: \s, \t, \n, \r, etc.
	//
	// Strategy: Process character by character, skipping whitespace unless preceded by backslash
	var result strings.Builder
	escaped := false

	for i, char := range pattern {
		if escaped {
			// Previous character was backslash, keep this character regardless
			result.WriteRune(char)
			escaped = false
			continue
		}

		if char == '\\' {
			// Check if this is escaping whitespace or is part of a sequence
			if i+1 < len(pattern) {
				// Always write the backslash and mark as escaped
				result.WriteRune(char)
				escaped = true
			} else {
				// Trailing backslash, keep it
				result.WriteRune(char)
			}
			continue
		}

		// Skip unescaped whitespace (space, tab, newline, carriage return)
		if char == ' ' || char == '\t' || char == '\n' || char == '\r' {
			continue
		}

		// Keep all other characters
		result.WriteRune(char)
	}

	return result.String()
}
