//go:build !wasm

package matcher

import (
	"regexp"
	"strings"
)

// stripExtendedMode preprocesses a regex pattern to remove extended mode syntax.
// If the pattern starts with inline flags containing 'x' (e.g., (?x), (?xi), (?xis)),
// this function:
// 1. Removes the 'x' flag from the flag group (or removes the entire group if only 'x')
// 2. Removes all whitespace (except escaped whitespace like \s or \ )
// 3. Removes all comments in the form (?# ... )
//
// This is necessary because the Hyperscan library (gohs) doesn't support the Extended flag,
// which allows free-spacing mode with comments in regex patterns.
func stripExtendedMode(pattern string) string {
	pattern = strings.TrimSpace(pattern)

	// Match inline flag groups at the start: (?x), (?xi), (?xis), (?ix), (?ism), etc.
	// We need to check if 'x' is present in the flags
	flagGroupRegex := regexp.MustCompile(`^\(\?([imsx]+)\)`)
	matches := flagGroupRegex.FindStringSubmatch(pattern)

	if len(matches) == 0 {
		// No flag group at start, pattern doesn't use extended mode
		return pattern
	}

	flags := matches[1]
	if !strings.Contains(flags, "x") {
		// No extended mode flag, return as-is
		return pattern
	}

	// Remove the 'x' flag from the flag group
	remainingFlags := strings.ReplaceAll(flags, "x", "")

	// Remove the original flag group
	pattern = flagGroupRegex.ReplaceAllString(pattern, "")

	// If there are remaining flags (like 'i', 's', 'm'), add them back
	if len(remainingFlags) > 0 {
		pattern = "(?" + remainingFlags + ")" + pattern
	}

	// Save the flag group we added at the start (if any)
	var startFlagGroup string
	if len(remainingFlags) > 0 {
		startFlagGroup = "(?" + remainingFlags + ")"
		// Remove it temporarily so we don't accidentally remove it when cleaning inline flags
		pattern = strings.TrimPrefix(pattern, startFlagGroup)
	}

	// Remove comments (?# ... )
	commentRegex := regexp.MustCompile(`\(\?#[^)]*\)`)
	pattern = commentRegex.ReplaceAllString(pattern, "")

	// Remove inline (?s) and (?m) flags that appear in the pattern body
	// These are handled via Hyperscan flags instead
	// (but we don't touch the flag group we added at the start)
	pattern = strings.ReplaceAll(pattern, "(?s)", "")
	pattern = strings.ReplaceAll(pattern, "(?m)", "")

	// Remove unescaped whitespace
	var result strings.Builder
	escaped := false

	for i, char := range pattern {
		if escaped {
			result.WriteRune(char)
			escaped = false
			continue
		}

		if char == '\\' {
			if i+1 < len(pattern) {
				result.WriteRune(char)
				escaped = true
			} else {
				result.WriteRune(char)
			}
			continue
		}

		// Skip unescaped whitespace
		if char == ' ' || char == '\t' || char == '\n' || char == '\r' {
			continue
		}

		result.WriteRune(char)
	}

	// Add back the flag group at the start if we had one
	if startFlagGroup != "" {
		return startFlagGroup + result.String()
	}

	return result.String()
}
