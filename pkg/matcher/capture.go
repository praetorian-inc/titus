package matcher

import (
	"fmt"
	"regexp"
)

// findMatchNearEnd finds the match that ends closest to the target end offset.
// This is used when Hyperscan provides an accurate end offset but inaccurate start offset
// (which happens when SomLeftMost is disabled for memory efficiency).
//
// Parameters:
//   - content: full content being scanned
//   - re: compiled regexp pattern
//   - targetEnd: the end offset reported by Hyperscan
//
// Returns:
//   - actualStart: the actual start offset of the match
//   - actualEnd: the actual end offset of the match (should be close to targetEnd)
//   - captures: the matched substrings (including full match at index 0)
//   - error if no match found near targetEnd
func findMatchNearEnd(content []byte, re *regexp.Regexp, targetEnd int) (actualStart, actualEnd int, captures [][]byte, err error) {
	// Search for all matches in the content up to slightly past the target end
	// (allowing some margin in case of rounding or boundary issues)
	searchLimit := targetEnd + 100
	if searchLimit > len(content) {
		searchLimit = len(content)
	}

	// Find all matches with their indices
	matches := re.FindAllSubmatchIndex(content[:searchLimit], -1)
	if len(matches) == 0 {
		return 0, 0, nil, fmt.Errorf("pattern did not match at specified location")
	}

	// Find the match that ends closest to targetEnd
	bestMatchIdx := -1
	bestDistance := int(^uint(0) >> 1) // max int

	for i, matchIndices := range matches {
		if len(matchIndices) < 2 {
			continue
		}
		matchEnd := matchIndices[1]
		distance := abs(matchEnd - targetEnd)
		if distance < bestDistance {
			bestDistance = distance
			bestMatchIdx = i
		}
	}

	if bestMatchIdx == -1 {
		return 0, 0, nil, fmt.Errorf("pattern did not match at specified location")
	}

	// Extract the best match
	matchIndices := matches[bestMatchIdx]
	actualStart = matchIndices[0]
	actualEnd = matchIndices[1]

	// Extract all capture groups (including full match at index 0)
	captures = make([][]byte, 0, len(matchIndices)/2)
	for i := 0; i < len(matchIndices); i += 2 {
		start := matchIndices[i]
		end := matchIndices[i+1]
		if start >= 0 && end >= 0 {
			captures = append(captures, content[start:end])
		} else {
			captures = append(captures, nil)
		}
	}

	return actualStart, actualEnd, captures, nil
}

// abs returns the absolute value of an integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ExtractCaptures extracts named capture groups from a match location using Go regexp.
// This is Stage 2 of the two-stage matching pipeline (Hyperscan finds offsets, then this extracts captures).
//
// Parameters:
//   - content: full content being scanned
//   - pattern: regex pattern (may contain named groups like (?P<name>...))
//   - start: byte offset where Hyperscan match started (may be 0 if SomLeftMost disabled)
//   - end: byte offset where Hyperscan match ended (accurate)
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

	// If start is 0, it might be inaccurate (SomLeftMost disabled)
	// Use Go regexp to find the actual match near the end offset
	var match [][]byte
	if start == 0 {
		_, _, match, err = findMatchNearEnd(content, re, end)
		if err != nil {
			return nil, err
		}
	} else {
		// Extract the region that Hyperscan matched
		region := content[start:end]

		// Apply the regex to extract capture groups
		match = re.FindSubmatch(region)
		if match == nil {
			return nil, fmt.Errorf("pattern did not match at specified location")
		}
	}

	return BuildNamedGroups(re, match), nil
}

// BuildNamedGroups extracts named capture groups from a compiled regexp and its match result.
// Returns a map of group name -> captured value. Unnamed groups are skipped.
func BuildNamedGroups(re *regexp.Regexp, match [][]byte) map[string][]byte {
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

	return captures
}
