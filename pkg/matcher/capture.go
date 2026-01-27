package matcher

import (
	"fmt"
	"regexp"
)

// ExtractCaptures extracts named capture groups from a match location using Go regexp.
// This is Stage 2 of the two-stage matching pipeline (Hyperscan finds offsets, then this extracts captures).
//
// Parameters:
//   - content: full content being scanned
//   - pattern: regex pattern (may contain named groups like (?P<name>...))
//   - start: byte offset where Hyperscan match started
//   - end: byte offset where Hyperscan match ended
//
// Returns:
//   - map of named capture groups to their matched values
//   - error if pattern invalid, bounds invalid, or no match found
func ExtractCaptures(content []byte, pattern string, start, end int) (map[string][]byte, error) {
	// Validate bounds
	if start < 0 || end > len(content) || start > end {
		return nil, fmt.Errorf("invalid bounds: start=%d, end=%d, content_len=%d (out of bounds)", start, end, len(content))
	}

	// Compile the pattern
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile pattern: %w", err)
	}

	// Extract the region that Hyperscan matched
	region := content[start:end]

	// Apply the regex to extract capture groups
	match := re.FindSubmatch(region)
	if match == nil {
		return nil, fmt.Errorf("pattern did not match at specified location")
	}

	// Build map of named capture groups
	captures := make(map[string][]byte)
	names := re.SubexpNames()

	// Skip index 0 (full match), iterate over named groups
	for i, name := range names {
		if i == 0 || name == "" {
			continue // skip full match and unnamed groups
		}
		if i < len(match) {
			captures[name] = match[i]
		}
	}

	return captures, nil
}
