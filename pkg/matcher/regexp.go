//go:build wasm

package matcher

import (
	"fmt"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/praetorian-inc/titus/pkg/types"
)

// RegexpMatcher implements Matcher using regexp2 for Perl-style regex support.
// Used for WASM builds where Hyperscan (CGO) is unavailable.
// Unlike HyperscanMatcher which uses a two-stage pipeline, RegexpMatcher
// performs pattern matching and capture extraction in a single pass.
type RegexpMatcher struct {
	rules        []*types.Rule
	regexCache   map[string]*regexp2.Regexp
	contextLines int
}

// NewRegexp creates a new regexp-based matcher.
func NewRegexp(rules []*types.Rule, contextLines int) (*RegexpMatcher, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules provided")
	}

	m := &RegexpMatcher{
		rules:        rules,
		regexCache:   make(map[string]*regexp2.Regexp),
		contextLines: contextLines,
	}

	// Pre-compile all patterns to catch errors early
	for _, rule := range rules {
		// Try RE2 mode first (safer, no backtracking)
		re, err := regexp2.Compile(rule.Pattern, regexp2.RE2|regexp2.Multiline)
		if err != nil {
			// Fallback to default Perl-compatible mode if RE2 fails (for advanced features like (?x))
			re, err = regexp2.Compile(rule.Pattern, regexp2.None)
			if err != nil {
				return nil, fmt.Errorf("failed to compile pattern %q for rule %s: %w", rule.Pattern, rule.ID, err)
			}
		}
		// Set timeout to prevent catastrophic backtracking
		re.MatchTimeout = 5 * time.Second
		m.regexCache[rule.Pattern] = re
	}

	return m, nil
}

// Match scans content against all loaded rules.
func (m *RegexpMatcher) Match(content []byte) ([]*types.Match, error) {
	blobID := types.ComputeBlobID(content)
	return m.MatchWithBlobID(content, blobID)
}

// MatchWithBlobID scans content with a known BlobID.
func (m *RegexpMatcher) MatchWithBlobID(content []byte, blobID types.BlobID) ([]*types.Match, error) {
	var matches []*types.Match
	dedup := NewDeduplicator()
	contentStr := string(content)

	for _, rule := range m.rules {
		re := m.regexCache[rule.Pattern]
		if re == nil {
			continue
		}

		// Find first match
		match, err := re.FindStringMatch(contentStr)
		if err != nil {
			return nil, fmt.Errorf("regex match error for rule %s: %w", rule.ID, err)
		}

		// Loop through all matches
		for match != nil {
			start := match.Index
			end := start + match.Length

			// Extract capture groups
			var groups [][]byte
			matchGroups := match.Groups()
			for i := 1; i < len(matchGroups); i++ {
				group := matchGroups[i]
				if len(group.Captures) > 0 {
					capture := group.Captures[0]
					groups = append(groups, []byte(capture.String()))
				}
			}

			// Extract context
			var before, after []byte
			if m.contextLines > 0 {
				before, after = ExtractContext(content, start, end, m.contextLines)
			}

			result := &types.Match{
				BlobID:   blobID,
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Location: types.Location{
					Offset: types.OffsetSpan{
						Start: int64(start),
						End:   int64(end),
					},
				},
				Groups: groups,
				Snippet: types.Snippet{
					Before:   before,
					Matching: content[start:end],
					After:    after,
				},
			}

			// Compute structural ID for deduplication
			result.StructuralID = result.ComputeStructuralID(rule.StructuralID)

			// Deduplicate
			if !dedup.IsDuplicate(result) {
				dedup.Add(result)
				matches = append(matches, result)
			}

			// Find next match
			match, err = re.FindNextMatch(match)
			if err != nil {
				return nil, fmt.Errorf("regex match error for rule %s: %w", rule.ID, err)
			}
		}
	}

	return matches, nil
}

// Close releases resources (no-op for regexp).
func (m *RegexpMatcher) Close() error {
	return nil
}
