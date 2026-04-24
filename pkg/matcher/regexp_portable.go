//go:build !wasm

package matcher

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/praetorian-inc/titus/pkg/types"
)

const parallelThreshold = 10000 // bytes

// retryJob holds a timed-out (content, blobID, rule) triple that will be
// replayed single-threaded by DrainTimedOut after the main parallel pass.
type retryJob struct {
	content []byte
	blobID  types.BlobID
	rule    *types.Rule
}

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
	warnf          func(string, ...any)
	matchTimeout   time.Duration // initial per-match timeout; 5s by default

	// retryMu protects retryJobs which is written by parallel workers and
	// drained single-threaded by DrainTimedOut after the main pass completes.
	retryMu   sync.Mutex
	retryJobs []retryJob
}

// NewPortableRegexp creates a new portable regexp-based matcher (non-CGO).
// This matcher is functionally equivalent to RegexpMatcher (used in WASM builds)
// but is available for native builds as an alternative to HyperscanMatcher.
//
// Use this when:
// - CGO is disabled or unavailable (library mode)
// - Cross-compilation without CGO dependencies
// - Benchmarking CGO vs non-CGO performance
func NewPortableRegexp(rules []*types.Rule, contextLines int, warnf func(string, ...any)) (*PortableRegexpMatcher, error) {
	return NewPortableRegexpWithTimeout(rules, contextLines, warnf, 5*time.Second)
}

// NewPortableRegexpWithTimeout creates a portable regexp-based matcher with a configurable
// initial match timeout. Exposed primarily for testing: pass a very short timeout (e.g. 1ms)
// to reliably trigger the retry queue without requiring catastrophic backtracking patterns.
// Production callers should use NewPortableRegexp, which applies the standard 5-second timeout.
func NewPortableRegexpWithTimeout(rules []*types.Rule, contextLines int, warnf func(string, ...any), matchTimeout time.Duration) (*PortableRegexpMatcher, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules provided")
	}

	m := &PortableRegexpMatcher{
		rules:          rules,
		regexCache:     make(map[string]*regexp2.Regexp),
		groupNameCache: make(map[string][]string),
		dedup:          NewContentDeduplicator(),
		contextLines:   contextLines,
		warnf:          warnf,
		matchTimeout:   matchTimeout,
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
		re.MatchTimeout = matchTimeout
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
	contentRunes := []rune(string(content))

	for _, rule := range m.rules {
		re := m.regexCache[rule.Pattern]
		if re == nil {
			continue
		}

		// Find first match
		match, err := re.FindRunesMatch(contentRunes)
		if err != nil {
			if strings.Contains(err.Error(), "match timeout") {
				// Warn immediately so operators can observe timeout rate, then queue for
				// single-threaded retry to recover findings lost to CPU-starvation timeouts.
				if m.warnf != nil {
					m.warnf("[warn] rule %s regex timeout on blob %s (skipping rule for this blob)\n", rule.ID, blobID.Hex())
				}
				m.retryMu.Lock()
				m.retryJobs = append(m.retryJobs, retryJob{content: content, blobID: blobID, rule: rule})
				m.retryMu.Unlock()
			} else if m.warnf != nil {
				m.warnf("[warn] rule %s regex error on blob %s (skipping rule for this blob): %v\n", rule.ID, blobID.Hex(), err)
			}
			continue
		}

		// Loop through all matches
		for match != nil {
			// Extract capture groups
			groups := extractCaptureGroups(match)
			namedGroups := extractNamedGroups(match, m.groupNameCache[rule.Pattern])

			// Build match result (convert rune-based Index/Length to byte offsets)
			result := buildMatchResult(blobID, rule, match.Index, match.Length, []byte(match.String()), groups, namedGroups, content, m.contextLines)

			// Deduplicate
			if !m.dedup.IsDuplicate(result) {
				m.dedup.Add(result)
				matches = append(matches, result)
			}

			// Find next match
			match, err = re.FindNextMatch(match)
			if err != nil {
				if strings.Contains(err.Error(), "match timeout") {
					if m.warnf != nil {
						m.warnf("[warn] rule %s regex timeout on blob %s (skipping rule for this blob)\n", rule.ID, blobID.Hex())
					}
					m.retryMu.Lock()
					m.retryJobs = append(m.retryJobs, retryJob{content: content, blobID: blobID, rule: rule})
					m.retryMu.Unlock()
				} else if m.warnf != nil {
					m.warnf("[warn] rule %s regex error on blob %s (skipping rule for this blob): %v\n", rule.ID, blobID.Hex(), err)
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
	contentRunes := []rune(string(content))

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
				match, err := re.FindRunesMatch(contentRunes)
				if err != nil {
					if strings.Contains(err.Error(), "match timeout") {
						if m.warnf != nil {
							m.warnf("[warn] rule %s regex timeout on blob %s (skipping rule for this blob)\n", rule.ID, blobID.Hex())
						}
						m.retryMu.Lock()
						m.retryJobs = append(m.retryJobs, retryJob{content: content, blobID: blobID, rule: rule})
						m.retryMu.Unlock()
					} else if m.warnf != nil {
						m.warnf("[warn] rule %s regex error on blob %s (skipping rule for this blob): %v\n", rule.ID, blobID.Hex(), err)
					}
					continue
				}

				// Loop through all matches
				for match != nil {
					// Extract capture groups and build result (convert rune-based Index/Length to byte offsets)
					groups := extractCaptureGroups(match)
					namedGroups := extractNamedGroups(match, m.groupNameCache[rule.Pattern])
					matchResult := buildMatchResult(blobID, rule, match.Index, match.Length, []byte(match.String()), groups, namedGroups, content, m.contextLines)
					workerMatches = append(workerMatches, matchResult)

					// Find next match
					match, err = re.FindNextMatch(match)
					if err != nil {
						if strings.Contains(err.Error(), "match timeout") {
							if m.warnf != nil {
								m.warnf("[warn] rule %s regex timeout on blob %s (skipping rule for this blob)\n", rule.ID, blobID.Hex())
							}
							m.retryMu.Lock()
							m.retryJobs = append(m.retryJobs, retryJob{content: content, blobID: blobID, rule: rule})
							m.retryMu.Unlock()
						} else if m.warnf != nil {
							m.warnf("[warn] rule %s regex error on blob %s (skipping rule for this blob): %v\n", rule.ID, blobID.Hex(), err)
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

// DrainTimedOut replays any blobs that timed out during the main parallel scan,
// this time single-threaded and with a longer timeout (30s) to avoid false drops
// caused by CPU contention between workers. Only if a blob times out again is it
// truly abandoned (catastrophic backtracking) and the warning emitted.
//
// Call this once after the main parallel scan (after all workers have joined) and
// feed the returned matches through the same store pipeline as normal matches.
// Near-zero cost when no timeouts occurred; overhead is proportional to actual
// timeout count.
func (m *PortableRegexpMatcher) DrainTimedOut() ([]*types.Match, error) {
	m.retryMu.Lock()
	jobs := m.retryJobs
	m.retryJobs = nil
	m.retryMu.Unlock()

	if len(jobs) == 0 {
		return nil, nil
	}

	// Deduplicate: keep only one retry job per (blobID, rule.ID) pair.
	seen := make(map[string]struct{})
	deduped := jobs[:0]
	for _, j := range jobs {
		key := j.blobID.Hex() + "\x00" + j.rule.ID
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			deduped = append(deduped, j)
		}
	}
	jobs = deduped

	const retryTimeout = 30 * time.Second

	var all []*types.Match
	for _, j := range jobs {
		re := m.regexCache[j.rule.Pattern]
		if re == nil {
			continue
		}

		// Temporarily raise timeout for the retry pass; restore afterward.
		orig := re.MatchTimeout
		re.MatchTimeout = retryTimeout

		contentRunes := []rune(string(j.content))

		match, err := re.FindRunesMatch(contentRunes)
		if err != nil {
			re.MatchTimeout = orig
			if strings.Contains(err.Error(), "match timeout") {
				// Still times out with 30s: genuine catastrophic backtracking.
				if m.warnf != nil {
					m.warnf("[warn] rule %s regex timeout on blob %s (skipping rule for this blob)\n", j.rule.ID, j.blobID.Hex())
				}
			} else if m.warnf != nil {
				m.warnf("[warn] rule %s regex error on blob %s (skipping rule for this blob): %v\n", j.rule.ID, j.blobID.Hex(), err)
			}
			continue
		}

		lastEnd := -1
		for match != nil {
			if match.Index <= lastEnd {
				break
			}
			lastEnd = match.Index + match.Length
			groups := extractCaptureGroups(match)
			namedGroups := extractNamedGroups(match, m.groupNameCache[j.rule.Pattern])
			result := buildMatchResult(j.blobID, j.rule, match.Index, match.Length, []byte(match.String()), groups, namedGroups, j.content, m.contextLines)
			// Compute line/col here since we have access to the original content.
			startLine, startCol := types.ComputeLineColumn(j.content, int(result.Location.Offset.Start))
			endLine, endCol := types.ComputeLineColumn(j.content, int(result.Location.Offset.End))
			result.Location.Source.Start.Line = startLine
			result.Location.Source.Start.Column = startCol
			result.Location.Source.End.Line = endLine
			result.Location.Source.End.Column = endCol
			all = append(all, result)

			match, err = re.FindNextMatch(match)
			if err != nil {
				if strings.Contains(err.Error(), "match timeout") {
					if m.warnf != nil {
						m.warnf("[warn] rule %s regex timeout on blob %s (skipping rule for this blob)\n", j.rule.ID, j.blobID.Hex())
					}
				} else if m.warnf != nil {
					m.warnf("[warn] rule %s regex error on blob %s (skipping rule for this blob): %v\n", j.rule.ID, j.blobID.Hex(), err)
				}
				break
			}
		}

		re.MatchTimeout = orig
	}

	return all, nil
}

// Close releases resources (no-op for regexp).
func (m *PortableRegexpMatcher) Close() error {
	return nil
}
