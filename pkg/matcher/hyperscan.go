//go:build !wasm

package matcher

import (
	"fmt"
	"regexp"

	"github.com/flier/gohs/hyperscan"
	"github.com/praetorian-inc/titus/pkg/types"
)

// HyperscanMatcher implements Matcher using Hyperscan.
// Two-stage pipeline:
//  1. Hyperscan finds pattern offsets (fast, no capture groups)
//  2. Go regexp extracts capture groups for each match
type HyperscanMatcher struct {
	db           hyperscan.BlockDatabase       // Compiled patterns
	scratch      *hyperscan.Scratch            // Per-scan scratch space
	rules        []*types.Rule                 // Rule metadata indexed by pattern ID
	regexCache   map[string]*regexp.Regexp     // Cache for capture group extraction
	contextLines int                           // Lines of context to extract before/after matches
}

// NewHyperscan creates a Hyperscan-based matcher.
func NewHyperscan(rules []*types.Rule, contextLines int) (*HyperscanMatcher, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules provided")
	}

	// Prepare patterns for Hyperscan compilation
	patterns := make([]*hyperscan.Pattern, len(rules))

	for i, rule := range rules {
		// Create pattern with flags:
		// - DotAll: . matches newlines
		// - MultiLine: ^/$ match line boundaries
		// Note: SomLeftMost (start-of-match tracking) is disabled to avoid memory issues
		// with complex patterns, following NoseyParker's approach. We use Go regexp in
		// stage 2 to find actual match boundaries.
		p := hyperscan.NewPattern(rule.Pattern, hyperscan.DotAll|hyperscan.MultiLine)
		p.Id = i // Pattern ID = index into rules array
		patterns[i] = p
	}

	// Compile database
	db, err := hyperscan.NewBlockDatabase(patterns...)
	if err != nil {
		return nil, fmt.Errorf("failed to compile Hyperscan database: %w", err)
	}

	// Allocate scratch space
	scratch, err := hyperscan.NewScratch(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to allocate Hyperscan scratch: %w", err)
	}

	return &HyperscanMatcher{
		db:           db,
		scratch:      scratch,
		rules:        rules,
		regexCache:   make(map[string]*regexp.Regexp),
		contextLines: contextLines,
	}, nil
}

// Match scans content against all loaded rules.
func (m *HyperscanMatcher) Match(content []byte) ([]*types.Match, error) {
	// Compute BlobID for the content
	blobID := types.ComputeBlobID(content)
	return m.MatchWithBlobID(content, blobID)
}

// rawMatch holds a Hyperscan match before processing
type rawMatch struct {
	ruleIdx int
	start   int
	end     int
}

// MatchWithBlobID scans content with a known BlobID.
func (m *HyperscanMatcher) MatchWithBlobID(content []byte, blobID types.BlobID) ([]*types.Match, error) {
	// Collect raw matches from Hyperscan
	// Note: Without SomLeftMost, Hyperscan reports from=0 (inaccurate start offset)
	// Key: "ruleIdx:end" -> smallest start offset seen (longest match)
	bestMatches := make(map[string]rawMatch)

	// Define callback for Hyperscan matches
	onMatch := func(id uint, from, to uint64, flags uint, context interface{}) error {
		if int(id) >= len(m.rules) {
			return fmt.Errorf("invalid pattern ID from Hyperscan: %d", id)
		}

		start := int(from)
		end := int(to)

		// For each (rule, end) pair, keep the longest match (smallest start offset)
		// This deduplication strategy works even when start=0 (SomLeftMost disabled)
		key := fmt.Sprintf("%d:%d", id, end)
		if existing, ok := bestMatches[key]; ok {
			if start < existing.start {
				bestMatches[key] = rawMatch{ruleIdx: int(id), start: start, end: end}
			}
		} else {
			bestMatches[key] = rawMatch{ruleIdx: int(id), start: start, end: end}
		}

		return nil
	}

	// Scan with Hyperscan
	if err := m.db.Scan(content, m.scratch, onMatch, nil); err != nil {
		return nil, fmt.Errorf("Hyperscan scan failed: %w", err)
	}

	// Process best matches into final Match objects
	var matches []*types.Match
	dedup := NewDeduplicator()

	for _, raw := range bestMatches {
		rule := m.rules[raw.ruleIdx]
		hyperscanStart := raw.start
		hyperscanEnd := raw.end

		// Stage 2: Extract capture groups using Go regexp
		// This also finds the actual start offset when start=0 (SomLeftMost disabled)
		actualStart, actualEnd, captures, err := m.extractCapturesAndBounds(content, rule.Pattern, hyperscanStart, hyperscanEnd)
		if err != nil {
			// If capture extraction fails, skip this match
			continue
		}

		// Convert captures map[string][]byte to Groups [][]byte
		var groups [][]byte
		if len(captures) > 0 {
			re := m.getCachedRegexp(rule.Pattern)
			if re != nil {
				names := re.SubexpNames()
				for _, name := range names {
					if name != "" {
						if val, ok := captures[name]; ok {
							groups = append(groups, val)
						}
					}
				}
			}
		}

		// Extract context lines before and after the match
		var before, after []byte
		if m.contextLines > 0 {
			before, after = ExtractContext(content, actualStart, actualEnd, m.contextLines)
		}

		// Build Match object using actual bounds from Go regexp
		match := &types.Match{
			BlobID:   blobID,
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Location: types.Location{
				Offset: types.OffsetSpan{
					Start: int64(actualStart),
					End:   int64(actualEnd),
				},
				Source: types.SourceSpan{},
			},
			Groups: groups,
			Snippet: types.Snippet{
				Before:   before,
				Matching: content[actualStart:actualEnd],
				After:    after,
			},
		}

		// Compute structural ID for deduplication
		match.StructuralID = match.ComputeStructuralID(rule.StructuralID)

		// Deduplicate by structural ID
		if !dedup.IsDuplicate(match) {
			dedup.Add(match)
			matches = append(matches, match)
		}
	}

	return matches, nil
}

// Close releases resources.
func (m *HyperscanMatcher) Close() error {
	if m.scratch != nil {
		if err := m.scratch.Free(); err != nil {
			return fmt.Errorf("failed to free scratch: %w", err)
		}
		m.scratch = nil
	}
	if m.db != nil {
		if err := m.db.Close(); err != nil {
			return fmt.Errorf("failed to close database: %w", err)
		}
		m.db = nil
	}
	return nil
}

// extractCapturesAndBounds extracts capture groups and finds actual match boundaries.
// When start=0 (SomLeftMost disabled), it uses Go regexp to find the match near the end offset.
// Returns actualStart, actualEnd, captures map, and error.
func (m *HyperscanMatcher) extractCapturesAndBounds(content []byte, pattern string, start, end int) (int, int, map[string][]byte, error) {
	// Get or compile regexp
	re := m.getCachedRegexp(pattern)
	if re == nil {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return 0, 0, nil, err
		}
		m.regexCache[pattern] = compiled
		re = compiled
	}

	var actualStart, actualEnd int
	var rawCaptures [][]byte

	// If start is 0, use Go regexp to find actual match near end
	if start == 0 {
		var err error
		actualStart, actualEnd, rawCaptures, err = findMatchNearEnd(content, re, end)
		if err != nil {
			return 0, 0, nil, err
		}
	} else {
		// Use the provided start/end bounds
		actualStart = start
		actualEnd = end

		// Extract capture groups from the region
		region := content[start:end]
		rawCaptures = re.FindSubmatch(region)
		if rawCaptures == nil {
			return 0, 0, nil, fmt.Errorf("pattern did not match at specified location")
		}
	}

	// Build map of named capture groups
	captures := make(map[string][]byte)
	names := re.SubexpNames()

	// Skip index 0 (full match), iterate over named groups
	for i, name := range names {
		if i == 0 || name == "" {
			continue
		}
		if i < len(rawCaptures) {
			captures[name] = rawCaptures[i]
		}
	}

	return actualStart, actualEnd, captures, nil
}

// getCachedRegexp retrieves compiled regexp from cache.
func (m *HyperscanMatcher) getCachedRegexp(pattern string) *regexp.Regexp {
	return m.regexCache[pattern]
}
