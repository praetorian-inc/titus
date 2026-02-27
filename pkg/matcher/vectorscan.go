//go:build !wasm && cgo && vectorscan

package matcher

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/flier/gohs/hyperscan"
	"github.com/praetorian-inc/titus/pkg/prefilter"
	"github.com/praetorian-inc/titus/pkg/types"
)

// VectorscanMatcher implements Matcher using Intel Hyperscan/Vectorscan for
// high-performance multi-pattern regex matching with SIMD acceleration.
//
// Performance Characteristics:
// - Uses hardware SIMD instructions (AVX2/AVX-512) for parallel pattern matching
// - Compiles all patterns into a single database for efficient multi-pattern matching
// - 10-100x faster than pure Go regex implementations for large content
// - Requires CGO and the Hyperscan/Vectorscan C library
//
// Thread Safety:
// - The compiled database is immutable and safe for concurrent use
// - Each goroutine needs its own scratch space (handled via sync.Pool)
// - Match() is safe for concurrent calls from multiple goroutines
type VectorscanMatcher struct {
	rules        []*types.Rule
	db           hyperscan.BlockDatabase
	scratch      *hyperscan.Scratch
	scratchPool  sync.Pool
	prefilter    *prefilter.Prefilter
	contextLines int

	// Pattern ID to rule mapping (Hyperscan uses integer IDs)
	patternToRule map[uint]*types.Rule

	// Fallback regex cache for capture group extraction
	// (Hyperscan doesn't support capture groups natively)
	regexCache     map[string]*regexp2.Regexp
	groupNameCache map[string][]string

	// Hybrid approach: track which rules use Hyperscan vs regexp2 fallback
	hsRules       []*types.Rule // Rules compiled into Hyperscan
	fallbackRules []*types.Rule // Rules that require regexp2 fallback
}

// knownIncompatiblePatterns contains rule IDs that are known to be
// incompatible with Hyperscan compilation. These patterns are automatically
// routed to the regexp2 fallback without attempting Hyperscan compilation.
// This optimization allows the fast path (single batch compilation) to succeed
// immediately, reducing initialization time from ~24 seconds to ~100-200ms.
//
// Note: np.azure.5, np.redis.1, np.redis.2 were previously incompatible due to
// lookbehind/lookahead assertions. They have been rewritten to be Hyperscan-
// compatible by moving the filtering logic to ignore_if_contains.
var knownIncompatiblePatterns = map[string]bool{
	// Currently empty - all rules are Hyperscan-compatible
}

// NewVectorscan creates a new Hyperscan/Vectorscan-based matcher.
// This is the high-performance option requiring CGO and the Hyperscan library.
//
// Use this when:
// - Maximum performance is required (10-100x faster than regexp2)
// - CGO is available and acceptable
// - Scanning large files or many files
func NewVectorscan(rules []*types.Rule, contextLines int) (*VectorscanMatcher, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules provided")
	}

	m := &VectorscanMatcher{
		rules:          rules,
		contextLines:   contextLines,
		patternToRule:  make(map[uint]*types.Rule),
		regexCache:     make(map[string]*regexp2.Regexp),
		groupNameCache: make(map[string][]string),
		prefilter:      prefilter.New(rules),
	}

	// Compile patterns into Hyperscan database
	if err := m.compilePatterns(); err != nil {
		return nil, fmt.Errorf("compile patterns: %w", err)
	}

	// Only initialize scratch space if we have a Hyperscan database
	if m.db != nil {
		scratch, err := hyperscan.NewScratch(m.db)
		if err != nil {
			m.db.Close()
			return nil, fmt.Errorf("allocate scratch: %w", err)
		}
		m.scratch = scratch

		// Initialize scratch pool for concurrent matching
		m.scratchPool = sync.Pool{
			New: func() interface{} {
				s, err := m.scratch.Clone()
				if err != nil {
					panic(fmt.Sprintf("failed to clone scratch space: %v", err))
				}
				return s
			},
		}
	}

	return m, nil
}

// compilePatterns compiles rule patterns using an optimized hybrid approach:
// 1. Check each rule against knownIncompatiblePatterns and route to fallback immediately
// 2. Attempt to compile remaining patterns at once (fast path)
// 3. If that fails, use binary search to identify newly incompatible patterns
// 4. Incompatible patterns use regexp2 fallback
//
// This optimization reduces compilation time from O(n) to O(1) in the common
// case where all patterns are compatible, or O(log n) when a few are not.
func (m *VectorscanMatcher) compilePatterns() error {
	// Build pattern list with preprocessing
	type patternInfo struct {
		rule    *types.Rule
		pattern *hyperscan.Pattern
		index   int
	}
	allPatterns := make([]patternInfo, 0, len(m.rules))

	// Track known incompatible rules separately
	var knownFallbackRules []*types.Rule

	for i, rule := range m.rules {
		// Check if this is a known incompatible pattern
		if knownIncompatiblePatterns[rule.ID] {
			knownFallbackRules = append(knownFallbackRules, rule)
			continue
		}

		// Preprocess pattern for Hyperscan compatibility
		pattern := preprocessPatternForHyperscan(rule.Pattern)

		// Determine Hyperscan flags based on pattern content
		var flags hyperscan.CompileFlag = 0
		if hasCaseInsensitive(rule.Pattern) {
			flags |= hyperscan.Caseless
		}
		if hasDotAll(rule.Pattern) {
			flags |= hyperscan.DotAll
		}
		if hasMultiline(rule.Pattern) {
			flags |= hyperscan.MultiLine
		}

		p := hyperscan.NewPattern(pattern, flags)
		p.Id = i
		allPatterns = append(allPatterns, patternInfo{rule: rule, pattern: p, index: i})
	}

	// Try to compile all patterns at once (fast path)
	hsPatternList := make([]*hyperscan.Pattern, len(allPatterns))
	for i, pi := range allPatterns {
		hsPatternList[i] = pi.pattern
	}

	var hsPatterns []*hyperscan.Pattern
	var hsRules []*types.Rule
	var fallbackRules []*types.Rule
	var discoveredFallbackRules []*types.Rule // Track which fallback rules were discovered (not known)
	hsPatternToRule := make(map[uint]*types.Rule)

	// Start with known incompatible patterns in fallback
	fallbackRules = append(fallbackRules, knownFallbackRules...)

	// Try to compile all patterns at once (fast path)
	// If successful, we'll reuse this database instead of compiling again
	var firstCompileDB hyperscan.BlockDatabase
	firstCompileDB, err := hyperscan.NewBlockDatabase(hsPatternList...)
	if err == nil {
		// All patterns are compatible! Fast path - reuse this compilation
		for i, pi := range allPatterns {
			pi.pattern.Id = i
			hsPatterns = append(hsPatterns, pi.pattern)
			hsRules = append(hsRules, pi.rule)
			hsPatternToRule[uint(i)] = pi.rule
		}
	} else {
		// Some patterns are incompatible - use binary search to find them
		incompatibleIndices := findIncompatiblePatterns(hsPatternList)
		incompatibleSet := make(map[int]bool)
		for _, idx := range incompatibleIndices {
			incompatibleSet[idx] = true
		}

		// Separate compatible from incompatible
		for _, pi := range allPatterns {
			if incompatibleSet[pi.index] {
				fallbackRules = append(fallbackRules, pi.rule)
				discoveredFallbackRules = append(discoveredFallbackRules, pi.rule)
			} else {
				pi.pattern.Id = len(hsPatterns)
				hsPatterns = append(hsPatterns, pi.pattern)
				hsRules = append(hsRules, pi.rule)
				hsPatternToRule[uint(len(hsPatterns)-1)] = pi.rule
			}
		}
	}

	// Build regex cache for ALL rules (needed for capture extraction and fallback)
	for _, rule := range m.rules {
		re, err := regexp2.Compile(rule.Pattern, regexp2.RE2|regexp2.Multiline)
		if err != nil {
			// Fallback to Perl-compatible mode
			re, err = regexp2.Compile(rule.Pattern, regexp2.None)
			if err != nil {
				return fmt.Errorf("failed to compile pattern %q for rule %s: %w", rule.Pattern, rule.ID, err)
			}
		}
		re.MatchTimeout = 5 * time.Second
		m.regexCache[rule.Pattern] = re
		m.groupNameCache[rule.Pattern] = re.GetGroupNames()
	}

	// Store which rules use which engine
	m.hsRules = hsRules
	m.fallbackRules = fallbackRules
	m.patternToRule = hsPatternToRule

	// Set the database - either reuse from fast path or compile incompatible subset
	if len(hsPatterns) > 0 {
		if firstCompileDB != nil {
			// Fast path: reuse the first successful compilation
			m.db = firstCompileDB
		} else {
			// Slow path: compile only the compatible patterns after binary search
			db, err := hyperscan.NewBlockDatabase(hsPatterns...)
			if err != nil {
				return fmt.Errorf("compile database: %w", err)
			}
			m.db = db
		}
	}

	// Print diagnostic info about pattern compilation
	fmt.Fprintf(os.Stderr, "[vectorscan] %d/%d rules compiled for Hyperscan, %d rules use regexp2 fallback\n",
		len(hsRules), len(m.rules), len(fallbackRules))

	// Print which rules are using fallback (for debugging)
	if len(knownFallbackRules) > 0 {
		fmt.Fprintf(os.Stderr, "[vectorscan] Known incompatible patterns (skipped Hyperscan compilation):\n")
		for _, rule := range knownFallbackRules {
			fmt.Fprintf(os.Stderr, "[vectorscan]   - %s\n", rule.ID)
		}
	}
	if len(discoveredFallbackRules) > 0 {
		fmt.Fprintf(os.Stderr, "[vectorscan] Discovered incompatible patterns (found via binary search):\n")
		for _, rule := range discoveredFallbackRules {
			fmt.Fprintf(os.Stderr, "[vectorscan]   - %s (consider adding to knownIncompatiblePatterns)\n", rule.ID)
		}
	}

	return nil
}

// findIncompatiblePatterns uses binary search to identify patterns that
// cannot be compiled by Hyperscan. Returns the indices of incompatible patterns.
func findIncompatiblePatterns(patterns []*hyperscan.Pattern) []int {
	if len(patterns) == 0 {
		return nil
	}

	// Try to compile all patterns
	_, err := hyperscan.NewBlockDatabase(patterns...)
	if err == nil {
		return nil // All patterns are compatible
	}

	// If only one pattern, it's the incompatible one
	if len(patterns) == 1 {
		return []int{patterns[0].Id}
	}

	// Split and recurse (binary search)
	mid := len(patterns) / 2
	left := patterns[:mid]
	right := patterns[mid:]

	incompatible := findIncompatiblePatterns(left)
	incompatible = append(incompatible, findIncompatiblePatterns(right)...)

	return incompatible
}

// preprocessPatternForHyperscan modifies a pattern for Hyperscan compatibility.
// Hyperscan doesn't support extended mode ((?x)) so we strip it.
func preprocessPatternForHyperscan(pattern string) string {
	// Strip extended mode if present
	if hasExtendedMode(pattern) {
		pattern = stripExtendedMode(pattern)
	}

	// Remove inline flag modifiers (we set them via Hyperscan flags instead)
	pattern = strings.ReplaceAll(pattern, "(?i)", "")
	pattern = strings.ReplaceAll(pattern, "(?s)", "")
	pattern = strings.ReplaceAll(pattern, "(?m)", "")

	return pattern
}

// hasExtendedMode checks if pattern uses extended mode.
func hasExtendedMode(pattern string) bool {
	// Check for (?x), (?xi), (?xis), etc. at the start
	pattern = strings.TrimSpace(pattern)
	if len(pattern) < 4 {
		return false
	}
	if pattern[0:2] != "(?" {
		return false
	}
	// Find the closing )
	closeIdx := strings.Index(pattern[2:], ")")
	if closeIdx == -1 {
		return false
	}
	flags := pattern[2 : 2+closeIdx]
	return strings.Contains(flags, "x")
}

// hasCaseInsensitive checks if pattern uses case-insensitive mode.
// Detects both (?i) and combined forms like (?xi), (?is), etc.
func hasCaseInsensitive(pattern string) bool {
	return hasFlag(pattern, 'i')
}

// hasDotAll checks if pattern uses dot-all mode.
// Detects both (?s) and combined forms like (?xs), (?is), etc.
func hasDotAll(pattern string) bool {
	return hasFlag(pattern, 's')
}

// hasMultiline checks if pattern uses multiline mode.
// Detects both (?m) and combined forms like (?xm), (?im), etc.
func hasMultiline(pattern string) bool {
	return hasFlag(pattern, 'm')
}

// hasFlag checks if a pattern contains the given flag character in any flag group.
// It searches for (?...) groups anywhere in the pattern and checks if the flag is present.
func hasFlag(pattern string, flag byte) bool {
	for i := 0; i < len(pattern)-2; i++ {
		if pattern[i] == '(' && pattern[i+1] == '?' {
			// Found a flag group, extract flags until ')'
			for j := i + 2; j < len(pattern); j++ {
				c := pattern[j]
				if c == ')' || c == ':' || c == '!' || c == '=' || c == '<' {
					// End of flags (or start of non-capturing/lookahead/lookbehind group)
					break
				}
				if c == flag {
					return true
				}
			}
		}
	}
	return false
}

// Match scans content against all loaded rules.
func (m *VectorscanMatcher) Match(content []byte) ([]*types.Match, error) {
	blobID := types.ComputeBlobID(content)
	return m.MatchWithBlobID(content, blobID)
}

// MatchWithBlobID scans content with a known BlobID.
func (m *VectorscanMatcher) MatchWithBlobID(content []byte, blobID types.BlobID) ([]*types.Match, error) {
	result, err := m.MatchWithBlobIDAndOptions(content, blobID, DefaultOptions())
	if err != nil {
		return nil, err
	}
	return result.Matches, nil
}

// MatchWithBlobIDAndOptions scans content with options.
func (m *VectorscanMatcher) MatchWithBlobIDAndOptions(content []byte, blobID types.BlobID, opts Options) (*MatchResult, error) {
	// Check if chunking is needed for large files
	chunkConfig := DefaultChunkConfig()
	chunks := ChunkContent(content, chunkConfig)

	// Single chunk: direct matching
	if len(chunks) == 1 {
		return m.matchChunk(content, blobID, opts)
	}

	// Large file: process chunks and merge results
	return m.matchChunked(content, chunks, blobID, opts)
}

// matchChunk performs matching on a single chunk of content.
//
// Hyperscan is used as a prefilter: its callback fires for every end position of a
// match (since we do not use HS_FLAG_SOM_LEFTMOST, which would make 183/196 rules
// incompatible). Rather than using the inaccurate (from=0, to=end) locations,
// we collect only the *set* of matched rule IDs from Hyperscan and then use
// regexp2 (already compiled in m.regexCache) to find the precise match locations.
func (m *VectorscanMatcher) matchChunk(content []byte, blobID types.BlobID, opts Options) (*MatchResult, error) {
	var scratch *hyperscan.Scratch

	// Only get scratch from pool if we have a Hyperscan database
	if m.db != nil {
		scratchI := m.scratchPool.Get()
		if scratchI == nil {
			return nil, fmt.Errorf("failed to get scratch space from pool")
		}
		scratch = scratchI.(*hyperscan.Scratch)
		defer m.scratchPool.Put(scratch)
	}

	// Use Hyperscan only as a prefilter: collect the set of rule IDs that had any match.
	// We deliberately ignore from/to because without SOM_LEFTMOST, from=0 for all matches
	// and Hyperscan fires a callback for every valid end position (not just one per match).
	matchedRuleIDs := make(map[uint]bool)
	var mu sync.Mutex

	handler := hyperscan.MatchHandler(func(id uint, from, to uint64, flags uint, context interface{}) error {
		mu.Lock()
		matchedRuleIDs[id] = true
		mu.Unlock()
		return nil
	})

	// Perform Hyperscan scan (only if we have Hyperscan-compiled patterns)
	if m.db != nil {
		if err := m.db.Scan(content, scratch, handler, nil); err != nil {
			return nil, fmt.Errorf("hyperscan scan: %w", err)
		}
	}

	// Process matches and extract captures
	matches := make([]*types.Match, 0)
	ruleStats := make(map[string]RuleStat)
	dedup := NewDeduplicator()
	contentStr := string(content)

	// For each Hyperscan-identified rule, use regexp2 to find precise match locations.
	for ruleIdx := range matchedRuleIDs {
		rule := m.patternToRule[ruleIdx]
		if rule == nil {
			continue
		}

		re := m.regexCache[rule.Pattern]
		if re == nil {
			continue
		}

		startTime := time.Now()
		stat := RuleStat{
			RuleID:   rule.ID,
			Status:   RuleCompleted,
			Matches:  0,
			Duration: 0,
			Error:    nil,
		}

		// Find all precise matches using regexp2
		match, err := re.FindStringMatch(contentStr)
		if err != nil {
			if strings.Contains(err.Error(), "match timeout") {
				fmt.Fprintf(os.Stderr, "[warn] rule %s regex timeout on content (skipping rule for this blob)\n", rule.ID)
			} else {
				fmt.Fprintf(os.Stderr, "[warn] rule %s regex error (skipping rule for this blob): %v\n", rule.ID, err)
			}
			stat.Duration = time.Since(startTime)
			ruleStats[rule.ID] = stat
			continue
		}
		lastEnd := -1
		for match != nil {
			start := match.Index
			end := start + match.Length

			// Prevent infinite loops on zero-length matches
			if start <= lastEnd {
				break
			}

			// Bounds check
			if start < 0 || end > len(content) || start > end {
				match, err = re.FindNextMatch(match)
				if err != nil {
					if strings.Contains(err.Error(), "match timeout") {
						fmt.Fprintf(os.Stderr, "[warn] rule %s regex timeout on content (skipping rule for this blob)\n", rule.ID)
					} else {
						fmt.Fprintf(os.Stderr, "[warn] rule %s regex error (skipping rule for this blob): %v\n", rule.ID, err)
					}
					break
				}
				continue
			}

			lastEnd = end

			newMatch := m.buildMatchFromRegexp2(content, blobID, rule, match)

			// Deduplicate
			if !dedup.IsDuplicate(newMatch) {
				dedup.Add(newMatch)
				matches = append(matches, newMatch)
				stat.Matches++
			}

			match, err = re.FindNextMatch(match)
			if err != nil {
				if strings.Contains(err.Error(), "match timeout") {
					fmt.Fprintf(os.Stderr, "[warn] rule %s regex timeout on content (skipping rule for this blob)\n", rule.ID)
				} else {
					fmt.Fprintf(os.Stderr, "[warn] rule %s regex error (skipping rule for this blob): %v\n", rule.ID, err)
				}
				break
			}
		}

		stat.Duration = time.Since(startTime)
		ruleStats[rule.ID] = stat
	}

	// Match fallback rules using regexp2
	if len(m.fallbackRules) > 0 {
		fallbackMatches := m.matchFallbackRules(content, blobID)
		for _, match := range fallbackMatches {
			if !dedup.IsDuplicate(match) {
				dedup.Add(match)
				matches = append(matches, match)
			}
		}
	}

	// Build summary
	summary := ResultSummary{
		TotalRules:     len(m.rules),
		CompletedRules: len(ruleStats),
		TimedOutRules:  0,
		ErrorRules:     0,
	}

	return &MatchResult{
		Matches:   matches,
		RuleStats: ruleStats,
		Summary:   summary,
	}, nil
}

// matchChunked handles large files by processing chunks with overlap.
func (m *VectorscanMatcher) matchChunked(content []byte, chunks []Chunk, blobID types.BlobID, opts Options) (*MatchResult, error) {
	var allMatches []*types.Match
	aggregatedStats := make(map[string]RuleStat)
	crossChunkDedup := NewDeduplicator()

	// Process chunks (could be parallelized in future)
	for _, chunk := range chunks {
		result, err := m.matchChunk(chunk.Content, blobID, opts)
		if err != nil && !opts.Tolerant {
			return nil, err
		}

		// Adjust match offsets to be relative to original file
		for _, match := range result.Matches {
			AdjustMatchOffset(match, chunk)

			// Deduplicate across chunks
			if !crossChunkDedup.IsDuplicate(match) {
				crossChunkDedup.Add(match)
				allMatches = append(allMatches, match)
			}
		}

		// Merge stats
		for ruleID, stat := range result.RuleStats {
			existing, ok := aggregatedStats[ruleID]
			if !ok || stat.Status > existing.Status {
				aggregatedStats[ruleID] = stat
			} else if stat.Status == existing.Status {
				existing.Matches += stat.Matches
				existing.Duration += stat.Duration
				aggregatedStats[ruleID] = existing
			}
		}
	}

	// Build summary
	summary := ResultSummary{
		TotalRules:     len(m.rules),
		CompletedRules: 0,
		TimedOutRules:  0,
		ErrorRules:     0,
	}

	for _, stat := range aggregatedStats {
		switch stat.Status {
		case RuleCompleted:
			summary.CompletedRules++
		case RuleTimedOut:
			summary.TimedOutRules++
		case RuleError:
			summary.ErrorRules++
		}
	}

	return &MatchResult{
		Matches:   allMatches,
		RuleStats: aggregatedStats,
		Summary:   summary,
	}, nil
}

// buildMatchFromRegexp2 constructs a types.Match from a regexp2 match result.
// It extracts positional and named capture groups, context lines, and computes
// the structural and finding IDs. This is the shared match-building logic used
// by both matchChunk and matchFallbackRules.
func (m *VectorscanMatcher) buildMatchFromRegexp2(
	content []byte,
	blobID types.BlobID,
	rule *types.Rule,
	re2match *regexp2.Match,
) *types.Match {
	start := re2match.Index
	end := start + re2match.Length

	// Extract positional and named capture groups
	groups, namedGroups := m.extractGroupsFromMatch(re2match, rule)

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
		Groups:      groups,
		NamedGroups: namedGroups,
		Snippet: types.Snippet{
			Before:   before,
			Matching: append([]byte{}, content[start:end]...),
			After:    after,
		},
	}
	result.StructuralID = result.ComputeStructuralID(rule.StructuralID)
	result.FindingID = types.ComputeFindingID(rule.StructuralID, groups)

	return result
}

// extractGroupsFromMatch extracts positional and named capture groups from a regexp2 match.
func (m *VectorscanMatcher) extractGroupsFromMatch(match *regexp2.Match, rule *types.Rule) ([][]byte, map[string][]byte) {
	// Extract positional capture groups
	var groups [][]byte
	matchGroups := match.Groups()
	for i := 1; i < len(matchGroups); i++ {
		group := matchGroups[i]
		if len(group.Captures) > 0 {
			capture := group.Captures[0]
			groups = append(groups, []byte(capture.String()))
		}
	}

	// Extract named capture groups
	namedGroups := make(map[string][]byte)
	groupNames := m.groupNameCache[rule.Pattern]
	for _, name := range groupNames {
		if name == "" || (len(name) > 0 && name[0] >= '0' && name[0] <= '9') {
			continue
		}
		group := match.GroupByName(name)
		if group != nil && len(group.Captures) > 0 {
			namedGroups[name] = []byte(group.Captures[0].String())
		}
	}

	return groups, namedGroups
}

// matchFallbackRules uses regexp2 to match patterns that are incompatible with Hyperscan.
// It applies prefiltering to only check patterns whose keywords are found in content.
func (m *VectorscanMatcher) matchFallbackRules(content []byte, blobID types.BlobID) []*types.Match {
	var matches []*types.Match
	contentStr := string(content)

	// Use prefilter to determine which fallback rules might match
	// This dramatically reduces the number of regex executions
	candidateRules := m.prefilter.Filter(content)

	// Build a set of candidate rule IDs for O(1) lookup
	candidateSet := make(map[string]bool, len(candidateRules))
	for _, r := range candidateRules {
		candidateSet[r.ID] = true
	}

	for _, rule := range m.fallbackRules {
		// Skip rules not in candidate set (keyword prefilter rejected them)
		if !candidateSet[rule.ID] {
			continue
		}

		re := m.regexCache[rule.Pattern]
		if re == nil {
			continue
		}

		// Find all matches for this rule
		match, err := re.FindStringMatch(contentStr)
		if err != nil {
			if strings.Contains(err.Error(), "match timeout") {
				fmt.Fprintf(os.Stderr, "[warn] rule %s regex timeout on content (skipping rule for this blob)\n", rule.ID)
			} else {
				fmt.Fprintf(os.Stderr, "[warn] rule %s regex error (skipping rule for this blob): %v\n", rule.ID, err)
			}
			continue
		}
		lastEnd := -1 // Track last match end to prevent infinite loops on zero-length matches
		for match != nil {
			start := match.Index
			end := start + match.Length

			// Prevent infinite loops on zero-length matches or matches at same position
			if start <= lastEnd {
				break
			}

			// Bounds check
			if start < 0 || end > len(content) || start > end {
				match, err = re.FindNextMatch(match)
				if err != nil {
					if strings.Contains(err.Error(), "match timeout") {
						fmt.Fprintf(os.Stderr, "[warn] rule %s regex timeout on content (skipping rule for this blob)\n", rule.ID)
					} else {
						fmt.Fprintf(os.Stderr, "[warn] rule %s regex error (skipping rule for this blob): %v\n", rule.ID, err)
					}
					break
				}
				continue
			}

			lastEnd = end

			newMatch := m.buildMatchFromRegexp2(content, blobID, rule, match)
			matches = append(matches, newMatch)

			match, err = re.FindNextMatch(match)
			if err != nil {
				if strings.Contains(err.Error(), "match timeout") {
					fmt.Fprintf(os.Stderr, "[warn] rule %s regex timeout on content (skipping rule for this blob)\n", rule.ID)
				} else {
					fmt.Fprintf(os.Stderr, "[warn] rule %s regex error (skipping rule for this blob): %v\n", rule.ID, err)
				}
				break
			}
		}
	}

	return matches
}

// Close releases all resources associated with the matcher.
func (m *VectorscanMatcher) Close() error {
	// Note: We don't drain scratchPool - sync.Pool automatically GCs unused items
	// Attempting to drain would cause infinite loop since Pool.New() clones scratches

	// Free template scratch
	if m.scratch != nil {
		if err := m.scratch.Free(); err != nil {
			return fmt.Errorf("free scratch: %w", err)
		}
	}

	// Close database
	if m.db != nil {
		if err := m.db.Close(); err != nil {
			return fmt.Errorf("close database: %w", err)
		}
	}

	return nil
}

// VectorscanAvailable returns true if vectorscan is available.
// This is always true when this file is compiled (build tag satisfied).
func VectorscanAvailable() bool {
	return true
}

// VectorscanInfo returns information about the Hyperscan build.
func VectorscanInfo() string {
	version := hyperscan.Version()
	return fmt.Sprintf("hyperscan %s (GOMAXPROCS=%d)", version, runtime.GOMAXPROCS(0))
}
