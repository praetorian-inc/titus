//go:build !wasm

package matcher

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/praetorian-inc/titus/pkg/types"
)

const parallelThreshold = 10000 // bytes

// PortableRegexpMatcher implements Matcher using regexp2 for native (non-WASM) builds.
// This is the non-CGO alternative to HyperscanMatcher, offering portability at the cost of performance.
//
// Performance Trade-offs:
// - Does NOT require CGO (can compile with CGO_ENABLED=0)
// - Slower than HyperscanMatcher (typically 5-15x depending on pattern complexity)
// - Uses pure Go regexp2 library (github.com/dlclark/regexp2)
// - Suitable for library mode where CGO dependencies are undesirable
//
// Unlike HyperscanMatcher which uses a two-stage pipeline (Hyperscan for location + Go regexp for captures),
// PortableRegexpMatcher performs pattern matching and capture extraction in a single pass using regexp2.
//
// Thread Safety: PortableRegexpMatcher is NOT safe for concurrent use.
// If you need to scan multiple files concurrently, create separate matcher instances per goroutine.
// The regexCache and groupNameCache are read-only after initialization (safe for concurrent reads).
// Calling Match() serially on the same instance is safe, but concurrent Match() calls on the same
// instance may race due to the shared dedup state.
type PortableRegexpMatcher struct {
	rules          []*types.Rule
	regexCache     map[string]*regexp2.Regexp   // read-only after init, safe for concurrent reads
	groupNameCache map[string][]string          // read-only after init, safe for concurrent reads
	dedup          *Deduplicator
	contextLines   int
}

// NewPortableRegexp creates a new portable regexp-based matcher (non-CGO).
// This matcher is functionally equivalent to RegexpMatcher (used in WASM builds)
// but is available for native builds as an alternative to HyperscanMatcher.
//
// Use this when:
// - CGO is disabled or unavailable (library mode)
// - Cross-compilation without CGO dependencies
// - Benchmarking CGO vs non-CGO performance
func NewPortableRegexp(rules []*types.Rule, contextLines int) (*PortableRegexpMatcher, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules provided")
	}

	m := &PortableRegexpMatcher{
		rules:          rules,
		regexCache:     make(map[string]*regexp2.Regexp),
		groupNameCache: make(map[string][]string),
		dedup:          NewContentDeduplicator(),
		contextLines:   contextLines,
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
		// Cache group names for this pattern
		m.groupNameCache[rule.Pattern] = re.GetGroupNames()
	}

	return m, nil
}

// Match scans content against all loaded rules.
func (m *PortableRegexpMatcher) Match(content []byte) ([]*types.Match, error) {
	blobID := types.ComputeBlobID(content)
	return m.MatchWithBlobID(content, blobID)
}

// MatchWithBlobID scans content with a known BlobID.
func (m *PortableRegexpMatcher) MatchWithBlobID(content []byte, blobID types.BlobID) ([]*types.Match, error) {
	if len(content) >= parallelThreshold {
		return m.matchParallel(content, blobID)
	}
	return m.matchSequential(content, blobID)
}

// matchSequential performs sequential matching (existing logic).
func (m *PortableRegexpMatcher) matchSequential(content []byte, blobID types.BlobID) ([]*types.Match, error) {
	// Estimate capacity: ~2% of rules typically match
	estimatedMatches := len(m.rules) / 50
	if estimatedMatches < 10 {
		estimatedMatches = 10
	}
	matches := make([]*types.Match, 0, estimatedMatches)
	m.dedup.Reset()
	contentStr := string(content)

	for _, rule := range m.rules {
		re := m.regexCache[rule.Pattern]
		if re == nil {
			continue
		}

		// Find first match
		match, err := re.FindStringMatch(contentStr)
		if err != nil {
			if strings.Contains(err.Error(), "match timeout") {
				fmt.Fprintf(os.Stderr, "[warn] rule %s regex timeout on content (skipping rule for this blob)\n", rule.ID)
			} else {
				fmt.Fprintf(os.Stderr, "[warn] rule %s regex error (skipping rule for this blob): %v\n", rule.ID, err)
			}
			continue
		}

		// Loop through all matches
		for match != nil {
			start := match.Index
			end := start + match.Length

			// Extract capture groups
			groups := extractCaptureGroups(match)
			namedGroups := extractNamedGroups(match, m.groupNameCache[rule.Pattern])

			// Build match result
			result := buildMatchResult(blobID, rule, start, end, groups, namedGroups, content, m.contextLines)

			// Deduplicate
			if !m.dedup.IsDuplicate(result) {
				m.dedup.Add(result)
				matches = append(matches, result)
			}

			// Find next match
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

	return matches, nil
}

// matchParallel performs parallel matching with worker pool.
func (m *PortableRegexpMatcher) matchParallel(content []byte, blobID types.BlobID) ([]*types.Match, error) {
	numWorkers := runtime.GOMAXPROCS(0)
	contentStr := string(content)

	// Job channel for distributing rules to workers
	type job struct {
		rule *types.Rule
		re   *regexp2.Regexp
	}
	jobs := make(chan job, len(m.rules))

	// Result channel for collecting matches
	type result struct {
		matches []*types.Match
		err     error
	}
	results := make(chan result, numWorkers)

	// Create cancellable context for worker coordination
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Pre-allocate worker match slice
			estimatedPerWorker := len(m.rules) / (50 * numWorkers)
			if estimatedPerWorker < 5 {
				estimatedPerWorker = 5
			}
			workerMatches := make([]*types.Match, 0, estimatedPerWorker)

			for j := range jobs {
				// Check if context cancelled (another worker errored)
				select {
				case <-ctx.Done():
					return
				default:
				}

				rule := j.rule
				re := j.re

				// Find first match
				match, err := re.FindStringMatch(contentStr)
				if err != nil {
					if strings.Contains(err.Error(), "match timeout") {
						fmt.Fprintf(os.Stderr, "[warn] rule %s regex timeout on content (skipping rule for this blob)\n", rule.ID)
					} else {
						fmt.Fprintf(os.Stderr, "[warn] rule %s regex error (skipping rule for this blob): %v\n", rule.ID, err)
					}
					continue
				}

				// Loop through all matches
				for match != nil {
					start := match.Index
					end := start + match.Length

					// Extract capture groups and build result
					groups := extractCaptureGroups(match)
					namedGroups := extractNamedGroups(match, m.groupNameCache[rule.Pattern])
					matchResult := buildMatchResult(blobID, rule, start, end, groups, namedGroups, content, m.contextLines)
					workerMatches = append(workerMatches, matchResult)

					// Find next match
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

			results <- result{matches: workerMatches}
		}()
	}

	// Distribute jobs
	for _, rule := range m.rules {
		re := m.regexCache[rule.Pattern]
		if re != nil {
			jobs <- job{rule: rule, re: re}
		}
	}
	close(jobs)

	// Wait for workers and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and deduplicate results
	estimatedMatches := len(m.rules) / 50
	if estimatedMatches < 10 {
		estimatedMatches = 10
	}
	allMatches := make([]*types.Match, 0, estimatedMatches)
	m.dedup.Reset()

	for r := range results {
		if r.err != nil {
			return nil, r.err
		}
		for _, match := range r.matches {
			if !m.dedup.IsDuplicate(match) {
				m.dedup.Add(match)
				allMatches = append(allMatches, match)
			}
		}
	}

	return allMatches, nil
}

// Close releases resources (no-op for regexp).
func (m *PortableRegexpMatcher) Close() error {
	return nil
}
