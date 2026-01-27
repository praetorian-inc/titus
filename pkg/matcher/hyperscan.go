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
	db         hyperscan.BlockDatabase // Compiled patterns
	scratch    *hyperscan.Scratch      // Per-scan scratch space
	rules      []*types.Rule           // Rule metadata indexed by pattern ID
	regexCache map[string]*regexp.Regexp // Cache for capture group extraction
}

// NewHyperscan creates a Hyperscan-based matcher.
func NewHyperscan(rules []*types.Rule) (*HyperscanMatcher, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules provided")
	}

	// Prepare patterns for Hyperscan compilation
	patterns := make([]*hyperscan.Pattern, len(rules))

	for i, rule := range rules {
		// Create pattern with flags:
		// - SomLeftMost: Report start-of-match (SOM) offset in callback
		// - DotAll: . matches newlines
		// - MultiLine: ^/$ match line boundaries
		// Note: SingleMatch is incompatible with SomLeftMost, so we use deduplication instead
		p := hyperscan.NewPattern(rule.Pattern, hyperscan.SomLeftMost|hyperscan.DotAll|hyperscan.MultiLine)
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
		db:         db,
		scratch:    scratch,
		rules:      rules,
		regexCache: make(map[string]*regexp.Regexp),
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
	// Key: "ruleIdx:start" -> longest end offset seen
	bestMatches := make(map[string]rawMatch)

	// Define callback for Hyperscan matches
	onMatch := func(id uint, from, to uint64, flags uint, context interface{}) error {
		if int(id) >= len(m.rules) {
			return fmt.Errorf("invalid pattern ID from Hyperscan: %d", id)
		}

		start := int(from)
		end := int(to)

		// For each (rule, start) pair, keep the longest match (greatest end offset)
		key := fmt.Sprintf("%d:%d", id, start)
		if existing, ok := bestMatches[key]; ok {
			if end > existing.end {
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
		start := raw.start
		end := raw.end

		// Stage 2: Extract capture groups using Go regexp
		captures, err := m.extractCapturesWithCache(content, rule.Pattern, start, end)
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

		// Build Match object
		match := &types.Match{
			BlobID:   blobID,
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Location: types.Location{
				Offset: types.OffsetSpan{
					Start: int64(start),
					End:   int64(end),
				},
				Source: types.SourceSpan{},
			},
			Groups: groups,
			Snippet: types.Snippet{
				Matching: content[start:end],
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

// extractCapturesWithCache uses cached regexp for capture extraction.
func (m *HyperscanMatcher) extractCapturesWithCache(content []byte, pattern string, start, end int) (map[string][]byte, error) {
	re := m.getCachedRegexp(pattern)
	if re == nil {
		// Cache miss - compile and cache
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		m.regexCache[pattern] = compiled
		re = compiled
	}

	// Use the existing ExtractCaptures function (already handles compilation internally, but we optimize with cache)
	return ExtractCaptures(content, pattern, start, end)
}

// getCachedRegexp retrieves compiled regexp from cache.
func (m *HyperscanMatcher) getCachedRegexp(pattern string) *regexp.Regexp {
	return m.regexCache[pattern]
}
