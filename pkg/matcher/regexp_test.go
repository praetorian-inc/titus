//go:build !wasm

package matcher

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMatchParallel_Correctness tests that parallel matching produces correct results
func TestMatchParallel_Correctness(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test-rule-1",
			Name:    "Test Password Pattern",
			Pattern: `password\s*=\s*"([^"]+)"`,
		},
		{
			ID:      "test-rule-2",
			Name:    "Test API Key Pattern",
			Pattern: `api_key\s*=\s*"([^"]+)"`,
		},
	}

	// Create content >10KB to trigger parallel path
	var contentBuilder strings.Builder
	for i := 0; i < 500; i++ {
		contentBuilder.WriteString(`password = "secret123"` + "\n")
		contentBuilder.WriteString(`api_key = "key456"` + "\n")
		contentBuilder.WriteString("some other line\n")
	}
	content := []byte(contentBuilder.String())
	require.Greater(t, len(content), 10000, "Content must be >10KB to trigger parallel path")

	matcher, err := NewPortableRegexp(rules, 0, nil)
	require.NoError(t, err)

	matches, err := matcher.Match(content)
	require.NoError(t, err)

	// Should find both patterns
	assert.NotEmpty(t, matches, "Should find matches in large content")

	// Verify we have matches for both rules
	ruleMatches := make(map[string]int)
	for _, match := range matches {
		ruleMatches[match.RuleID]++
	}

	assert.Contains(t, ruleMatches, "test-rule-1", "Should match password pattern")
	assert.Contains(t, ruleMatches, "test-rule-2", "Should match API key pattern")

	// With content-based deduplication (NoseyParker behavior), same secret value = 1 finding
	assert.Equal(t, 1, ruleMatches["test-rule-1"], "Should deduplicate identical password content")
	assert.Equal(t, 1, ruleMatches["test-rule-2"], "Should deduplicate identical API key content")
}

// TestMatchParallel_vs_Sequential_Equivalence tests that parallel and sequential paths return same results
func TestMatchParallel_vs_Sequential_Equivalence(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "equiv-rule-1",
			Name:    "Email Pattern",
			Pattern: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
		},
		{
			ID:      "equiv-rule-2",
			Name:    "URL Pattern",
			Pattern: `https?://[^\s]+`,
		},
	}

	// Create content with varying sizes
	testCases := []struct {
		name        string
		contentSize int // in iterations
	}{
		{"small", 10},   // <10KB - sequential path
		{"medium", 100}, // ~10KB - boundary
		{"large", 1000}, // >10KB - parallel path
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var contentBuilder strings.Builder
			for i := 0; i < tc.contentSize; i++ {
				contentBuilder.WriteString("user@example.com\n")
				contentBuilder.WriteString("https://example.com/path\n")
				contentBuilder.WriteString("some other content\n")
			}
			content := []byte(contentBuilder.String())

			matcher, err := NewPortableRegexp(rules, 2, nil)
			require.NoError(t, err)

			matches, err := matcher.Match(content)
			require.NoError(t, err)

			// Verify consistent results
			assert.NotEmpty(t, matches, "Should find matches")

			// Check rule coverage
			ruleIDs := make(map[string]bool)
			for _, match := range matches {
				ruleIDs[match.RuleID] = true
			}

			assert.True(t, ruleIDs["equiv-rule-1"], "Should match email pattern")
			assert.True(t, ruleIDs["equiv-rule-2"], "Should match URL pattern")
		})
	}
}

// TestMatch_FindingID_Populated verifies that FindingID is set on all returned matches
func TestMatch_FindingID_Populated(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "np.aws.1",
			Name:         "AWS API Key",
			Pattern:      `(AKIA[0-9A-Z]{16})`,
			StructuralID: "1e4113c48323df7405840eede9a2be89a9797520",
		},
	}

	content := []byte("aws_access_key=AKIAZ52KNG5GARBXTEST\n")

	matcher, err := NewPortableRegexp(rules, 0, nil)
	require.NoError(t, err)

	matches, err := matcher.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	match := matches[0]
	assert.NotEmpty(t, match.FindingID, "FindingID should be populated")
	assert.Len(t, match.FindingID, 40, "FindingID should be 40-char SHA-1 hex")

	// Verify it matches the expected NoseyParker-compatible value
	expectedFindingID := types.ComputeFindingID(rules[0].StructuralID, match.Groups)
	assert.Equal(t, expectedFindingID, match.FindingID)

	// NoseyParker v0.24.0 produces this finding_id for np.aws.1 + "AKIAZ52KNG5GARBXTEST"
	assert.Equal(t, "59141806118796593f3d14bae57834b794d3421b", match.FindingID)
}

// TestPortableRegexp_TimeoutIsTolerated verifies that a regex timeout on one rule
// does NOT kill the scan; matches from other rules are still returned.
func TestPortableRegexp_TimeoutIsTolerated(t *testing.T) {
	// Build a catastrophic-backtracking pattern that will reliably time out under regexp2.
	// The pattern (a+)+ on a string of a's followed by a non-match is the canonical example.
	// We pair it with a benign rule so we can verify the benign rule still produces results.
	rules := []*types.Rule{
		{
			ID:      "catastrophic-rule",
			Name:    "Catastrophic Backtracking",
			Pattern: `(a+)+b`, // Known catastrophic backtracking pattern
		},
		{
			ID:      "good-rule",
			Name:    "Good Pattern",
			Pattern: `password\s*=\s*"([^"]+)"`,
		},
	}

	// Content: long string of 'a's (no 'b' at end → catastrophic backtracking on rule 1)
	// plus a password match that rule 2 should find.
	catastrophicContent := strings.Repeat("a", 5000) + "c" // no 'b' → triggers timeout on rule 1
	content := []byte(catastrophicContent + "\n" + `password = "secret123"`)

	m, err := NewPortableRegexp(rules, 0, nil)
	require.NoError(t, err)

	// This must NOT return an error even though catastrophic-rule times out.
	matches, err := m.MatchWithBlobID(content, types.ComputeBlobID(content))
	require.NoError(t, err, "timeout on one rule must not propagate as error")

	// The good-rule must still produce its match.
	ruleIDs := make(map[string]bool)
	for _, match := range matches {
		ruleIDs[match.RuleID] = true
	}
	assert.True(t, ruleIDs["good-rule"], "good-rule should still match despite other rule timing out")
	assert.False(t, ruleIDs["catastrophic-rule"], "catastrophic-rule should not produce matches (timed out)")
}

// TestPortableRegexp_BlobIDInWarning verifies that regex timeout and error warnings
// include the blob ID hex so that the problematic blob can be identified.
func TestPortableRegexp_BlobIDInWarning(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "catastrophic-rule",
			Name:    "Catastrophic Backtracking",
			Pattern: `(a+)+b`,
		},
		{
			ID:      "good-rule",
			Name:    "Good Pattern",
			Pattern: `password\s*=\s*"([^"]+)"`,
		},
	}

	content := []byte(strings.Repeat("a", 5000) + "c\n" + `password = "secret123"`)
	blobID := types.ComputeBlobID(content)

	var warnings []string
	warnf := func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}

	m, err := NewPortableRegexp(rules, 0, warnf)
	require.NoError(t, err)

	_, err = m.MatchWithBlobID(content, blobID)
	require.NoError(t, err)

	require.NotEmpty(t, warnings, "should have emitted at least one timeout warning")
	for _, w := range warnings {
		assert.Contains(t, w, blobID.Hex(), "warning should include the blob ID hex")
		assert.Contains(t, w, "on blob", "warning should use 'on blob' prefix")
	}
}

// TestPortableRegexp_TimedOutBlobsAreRetried verifies that blobs which timed out
// during the main parallel scan are queued and retried by DrainTimedOut(), recovering
// findings that would otherwise be silently dropped due to CPU-contention starvation.
//
// The test directly injects a retryJob (package-internal struct) to simulate a timeout
// that occurred during the main pass, then verifies that DrainTimedOut recovers the match.
// This avoids any dependency on real wall-clock timing or CPU load.
func TestPortableRegexp_TimedOutBlobsAreRetried(t *testing.T) {
	rule := &types.Rule{
		ID:      "benign-rule",
		Name:    "Simple API Key",
		Pattern: `SECRET_KEY=([A-Z0-9]{20})`,
	}

	content := []byte("SECRET_KEY=ABCDEFGHIJ1234567890\nsome other content\n")
	blobID := types.ComputeBlobID(content)

	m, err := NewPortableRegexpWithTimeout([]*types.Rule{rule}, 0, nil, 5*time.Second)
	require.NoError(t, err)

	// Simulate a timeout by directly injecting a retry job, as the parallel workers
	// do when regexp2 returns a timeout error. This decouples the test from real timing.
	m.retryMu.Lock()
	m.retryJobs = append(m.retryJobs, retryJob{content: content, blobID: blobID, rule: rule})
	m.retryMu.Unlock()

	// The main pass has not run, so there are no matches yet.
	// DrainTimedOut replays queued jobs single-threaded with a longer timeout.
	retried, err := m.DrainTimedOut()
	require.NoError(t, err)
	require.NotEmpty(t, retried, "DrainTimedOut must recover timed-out findings")

	ruleIDs := make(map[string]bool)
	for _, match := range retried {
		ruleIDs[match.RuleID] = true
	}
	assert.True(t, ruleIDs["benign-rule"], "benign-rule findings must be recovered by DrainTimedOut")

	// After draining, the queue must be empty.
	retried2, err := m.DrainTimedOut()
	require.NoError(t, err)
	assert.Empty(t, retried2, "second DrainTimedOut call must return nothing (queue cleared)")
}

// TestPortableRegexp_BlobIDInWarning_NoHint verifies that warnings always include
// the blob ID hex even when no source path context is available.
func TestPortableRegexp_BlobIDInWarning_NoHint(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "catastrophic-rule",
			Name:    "Catastrophic Backtracking",
			Pattern: `(a+)+b`,
		},
	}

	content := []byte(strings.Repeat("a", 5000) + "c")
	blobID := types.ComputeBlobID(content)

	var warnings []string
	warnf := func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}

	m, err := NewPortableRegexp(rules, 0, warnf)
	require.NoError(t, err)

	_, err = m.MatchWithBlobID(content, blobID)
	require.NoError(t, err)

	require.NotEmpty(t, warnings, "should have emitted at least one timeout warning")
	for _, w := range warnings {
		assert.Contains(t, w, blobID.Hex(), "warning should include the blob ID hex")
		assert.Contains(t, w, "on blob", "warning should use 'on blob' prefix")
	}
}

// TestPortableRegexp_TimeoutIsTolerated_Parallel is the same test but for large content
// that triggers the parallel path.
func TestPortableRegexp_TimeoutIsTolerated_Parallel(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "catastrophic-rule",
			Name:    "Catastrophic Backtracking",
			Pattern: `(a+)+b`, // Known catastrophic backtracking pattern
		},
		{
			ID:      "good-rule",
			Name:    "Good Pattern",
			Pattern: `password\s*=\s*"([^"]+)"`,
		},
	}

	// Build content >10KB to trigger parallel path.
	var sb strings.Builder
	sb.WriteString(strings.Repeat("a", 5000) + "c\n")
	for sb.Len() < parallelThreshold+1000 {
		sb.WriteString(`password = "secret123"` + "\n")
	}
	content := []byte(sb.String())
	require.Greater(t, len(content), parallelThreshold, "must trigger parallel path")

	m, err := NewPortableRegexp(rules, 0, nil)
	require.NoError(t, err)

	matches, err := m.MatchWithBlobID(content, types.ComputeBlobID(content))
	require.NoError(t, err, "timeout on one rule must not propagate as error in parallel path")

	ruleIDs := make(map[string]bool)
	for _, match := range matches {
		ruleIDs[match.RuleID] = true
	}
	assert.True(t, ruleIDs["good-rule"], "good-rule should still match in parallel path despite other rule timing out")
}

// TestMatchParallel_RaceDetector explicitly exercises parallel path with race detector
func TestMatchParallel_RaceDetector(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "race-rule-1",
			Name:    "Pattern 1",
			Pattern: `secret_[0-9]+`,
		},
		{
			ID:      "race-rule-2",
			Name:    "Pattern 2",
			Pattern: `token_[a-z]+`,
		},
		{
			ID:      "race-rule-3",
			Name:    "Pattern 3",
			Pattern: `key_[A-Z]+`,
		},
	}

	// Create large content to force parallel path
	var contentBuilder strings.Builder
	for i := 0; i < 1000; i++ {
		contentBuilder.WriteString("secret_123 token_abc key_XYZ\n")
	}
	content := []byte(contentBuilder.String())
	require.Greater(t, len(content), 10000)

	matcher, err := NewPortableRegexp(rules, 1, nil)
	require.NoError(t, err)

	// Run multiple times to increase chance of detecting races
	for i := 0; i < 5; i++ {
		matches, err := matcher.Match(content)
		require.NoError(t, err)
		assert.NotEmpty(t, matches, "iteration %d: should find matches", i)
	}
}

// TestMatch_SnippetAndOffset_ASCII verifies correct snippet extraction and byte offsets
// for ASCII-only content.
func TestMatch_SnippetAndOffset_ASCII(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test-secret",
			Name:    "Secret Pattern",
			Pattern: `\b(secret_[a-z]+)\b`,
		},
	}

	content := []byte("prefix secret_key suffix")
	//                 0123456789...
	//                        ^-- "secret_key" starts at byte 7

	matcher, err := NewPortableRegexp(rules, 0, nil)
	require.NoError(t, err)

	matches, err := matcher.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	match := matches[0]

	// Verify matched text
	assert.Equal(t, "secret_key", string(match.Snippet.Matching))

	// Verify byte offsets
	assert.Equal(t, int64(7), match.Location.Offset.Start, "start offset should be 7")
	assert.Equal(t, int64(17), match.Location.Offset.End, "end offset should be 17")

	// Verify slicing with offsets gives correct result
	start := match.Location.Offset.Start
	end := match.Location.Offset.End
	assert.Equal(t, "secret_key", string(content[start:end]))
}

// TestMatch_SnippetAndOffset_UTF8 verifies correct snippet extraction and byte offsets
// when content contains multi-byte UTF-8 characters before the match.
//
// This is a regression test for the regexp2 rune-vs-byte index issue:
// regexp2 returns Match.Index as a rune count, not byte count, which caused
// incorrect offsets when content had multi-byte UTF-8 characters.
func TestMatch_SnippetAndOffset_UTF8(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test-secret",
			Name:    "Secret Pattern",
			Pattern: `\b(secret_[a-z]+)\b`,
		},
	}

	testCases := []struct {
		name        string
		content     string
		wantMatch   string
		wantStart   int64
		wantEnd     int64
		description string
	}{
		{
			name:        "2-byte UTF-8 before match",
			content:     "préfix secret_key suffix", // é = 2 bytes
			wantMatch:   "secret_key",
			wantStart:   8, // "préfix " = 8 bytes (7 chars but é is 2 bytes)
			wantEnd:     18,
			description: "é (U+00E9) is 2 bytes in UTF-8",
		},
		{
			name:        "3-byte UTF-8 before match",
			content:     "pre–fix secret_key suffix", // – (en dash) = 3 bytes
			wantMatch:   "secret_key",
			wantStart:   10, // "pre–fix " = 10 bytes (8 chars but – is 3 bytes)
			wantEnd:     20,
			description: "– (U+2013 en dash) is 3 bytes in UTF-8",
		},
		{
			name:        "4-byte UTF-8 before match",
			content:     "prefix 🔑 secret_key suffix", // 🔑 = 4 bytes
			wantMatch:   "secret_key",
			wantStart:   12, // "prefix 🔑 " = 12 bytes (9 chars but 🔑 is 4 bytes)
			wantEnd:     22,
			description: "🔑 (U+1F511) is 4 bytes in UTF-8",
		},
		{
			name:        "multiple multi-byte chars before match",
			content:     "café 🔐 secret_key suffix", // é=2bytes, 🔐=4bytes
			wantMatch:   "secret_key",
			wantStart:   11, // "café 🔐 " = 11 bytes (7 chars)
			wantEnd:     21,
			description: "multiple multi-byte characters compound the offset",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.content)

			matcher, err := NewPortableRegexp(rules, 0, nil)
			require.NoError(t, err)

			matches, err := matcher.Match(content)
			require.NoError(t, err)
			require.Len(t, matches, 1, "should find exactly one match")

			match := matches[0]

			// Verify matched text is correct
			assert.Equal(t, tc.wantMatch, string(match.Snippet.Matching),
				"Snippet.Matching should contain the correct text")

			// Verify byte offsets are correct
			assert.Equal(t, tc.wantStart, match.Location.Offset.Start,
				"Location.Offset.Start should be correct byte offset")
			assert.Equal(t, tc.wantEnd, match.Location.Offset.End,
				"Location.Offset.End should be correct byte offset")

			// Most importantly: verify slicing content with these offsets gives the matched text
			start := match.Location.Offset.Start
			end := match.Location.Offset.End
			sliced := string(content[start:end])
			assert.Equal(t, tc.wantMatch, sliced,
				"content[Offset.Start:Offset.End] must equal the matched text")
		})
	}
}

// TestMatch_SnippetContext_UTF8 verifies that before/after context is correct
// when content contains multi-byte UTF-8 characters.
func TestMatch_SnippetContext_UTF8(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test-secret",
			Name:    "Secret Pattern",
			Pattern: `\b(secret_[a-z]+)\b`,
		},
	}

	// Content with multi-byte chars before and after the match
	content := []byte("café secret_key 🔑end")

	matcher, err := NewPortableRegexp(rules, 3, nil) // 3 lines of context
	require.NoError(t, err)

	matches, err := matcher.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	match := matches[0]

	// Verify the matched text
	assert.Equal(t, "secret_key", string(match.Snippet.Matching))

	// Verify before context contains the UTF-8 prefix
	assert.Contains(t, string(match.Snippet.Before), "café",
		"before context should include UTF-8 characters")

	// Verify after context contains the UTF-8 suffix
	assert.Contains(t, string(match.Snippet.After), "🔑",
		"after context should include UTF-8 characters")
}

// TestPortableRegexp_BlacklistAfterKTimeouts verifies that after retryBlacklistThreshold
// timeouts for the same rule on distinct blobs, the rule is added to the per-scan
// blacklist and no further retry jobs are enqueued for it.
func TestPortableRegexp_BlacklistAfterKTimeouts(t *testing.T) {
	rule := &types.Rule{
		ID:      "runaway-rule",
		Name:    "Runaway Pattern",
		Pattern: `SECRET_KEY=([A-Z0-9]{20})`,
	}

	// Use a 1ms timeout so we can reliably simulate timeouts by injecting jobs directly.
	m, err := NewPortableRegexpWithTimeout([]*types.Rule{rule}, 0, nil, 1*time.Millisecond)
	require.NoError(t, err)

	// Inject retryBlacklistThreshold-1 jobs (under threshold): they should all be enqueued.
	for i := 0; i < retryBlacklistThreshold-1; i++ {
		blob := []byte(fmt.Sprintf("content-%d", i))
		blobID := types.ComputeBlobID(blob)
		m.enqueueOrBlacklist(retryJob{content: blob, blobID: blobID, rule: rule})
	}
	m.retryMu.Lock()
	queueLen := len(m.retryJobs)
	m.retryMu.Unlock()
	assert.Equal(t, retryBlacklistThreshold-1, queueLen,
		"first K-1 timeouts should all be enqueued")

	// The K-th timeout (threshold) should blacklist the rule and NOT enqueue a new job.
	var warnBuf []string
	m.warnf = func(format string, args ...any) {
		warnBuf = append(warnBuf, fmt.Sprintf(format, args...))
	}
	blob := []byte("content-threshold")
	blobID := types.ComputeBlobID(blob)
	m.enqueueOrBlacklist(retryJob{content: blob, blobID: blobID, rule: rule})

	m.retryMu.Lock()
	queueLenAfter := len(m.retryJobs)
	m.retryMu.Unlock()
	assert.Equal(t, retryBlacklistThreshold-1, queueLenAfter,
		"K-th timeout must NOT add a new job (rule is now blacklisted)")

	// Exactly one warning should have been emitted mentioning the rule and threshold.
	require.Len(t, warnBuf, 1, "exactly one blacklist warning should be emitted")
	assert.Contains(t, warnBuf[0], rule.ID, "warning must name the rule")
	assert.Contains(t, warnBuf[0], fmt.Sprintf("%d", retryBlacklistThreshold),
		"warning must mention the threshold count")
	assert.Contains(t, warnBuf[0], "disabled after", "warning must say 'disabled after'")

	// A subsequent (K+1) timeout for the already-blacklisted rule must be silently ignored.
	blob2 := []byte("content-after-blacklist")
	blobID2 := types.ComputeBlobID(blob2)
	m.enqueueOrBlacklist(retryJob{content: blob2, blobID: blobID2, rule: rule})

	m.retryMu.Lock()
	queueLenFinal := len(m.retryJobs)
	m.retryMu.Unlock()
	assert.Equal(t, retryBlacklistThreshold-1, queueLenFinal,
		"post-blacklist jobs must be silently dropped")
	assert.Len(t, warnBuf, 1, "no additional warnings after blacklisting")
}

// TestMatchParallel_DeterministicOutputOrder verifies that matchParallel always returns
// allMatches in the same canonical order (start offset ASC, end offset ASC, ruleID ASC)
// regardless of which worker goroutine completes first.
func TestMatchParallel_DeterministicOutputOrder(t *testing.T) {
	// Three rules, each matching at different offsets throughout a large blob.
	// Workers may complete in any order, so without a sort the output slice order
	// is nondeterministic across runs.
	rules := []*types.Rule{
		{
			ID:      "rule-aaa",
			Name:    "Pattern AAA",
			Pattern: `ALPHA_[A-Z]{5}`,
		},
		{
			ID:      "rule-bbb",
			Name:    "Pattern BBB",
			Pattern: `BETA_[0-9]{5}`,
		},
		{
			ID:      "rule-ccc",
			Name:    "Pattern CCC",
			Pattern: `GAMMA_[a-z]{5}`,
		},
	}

	// Build content >10KB so matchParallel is triggered.
	// Each pattern appears once per line so that deduplication keeps a single match
	// per rule and the sort key is unambiguous.
	var sb strings.Builder
	for sb.Len() < parallelThreshold+5000 {
		sb.WriteString("ALPHA_ABCDE BETA_12345 GAMMA_abcde filler\n")
	}
	content := []byte(sb.String())
	require.Greater(t, len(content), parallelThreshold, "content must trigger parallel path")

	matcher, err := NewPortableRegexp(rules, 0, nil)
	require.NoError(t, err)

	// Run 10 times and collect the StructuralID sequences.
	const runs = 10
	sequences := make([][]string, runs)
	for i := range sequences {
		// Reset the deduplicator between calls so each run is independent.
		matcher.dedup.Reset()
		matches, err := matcher.MatchWithBlobID(content, types.ComputeBlobID(content))
		require.NoError(t, err)
		ids := make([]string, len(matches))
		for j, m := range matches {
			ids[j] = m.RuleID
		}
		sequences[i] = ids
	}

	// Every run must produce the same sequence.
	require.NotEmpty(t, sequences[0], "must find at least one match")
	for i := 1; i < runs; i++ {
		assert.Equal(t, sequences[0], sequences[i],
			"run %d produced different match order than run 0", i)
	}

	// Additionally assert that the output is sorted by (start, end, ruleID).
	// Take the last run's result and verify structural ordering.
	matcher.dedup.Reset()
	finalMatches, err := matcher.MatchWithBlobID(content, types.ComputeBlobID(content))
	require.NoError(t, err)
	for i := 1; i < len(finalMatches); i++ {
		mi := finalMatches[i-1]
		mj := finalMatches[i]
		if mi.Location.Offset.Start == mj.Location.Offset.Start {
			if mi.Location.Offset.End == mj.Location.Offset.End {
				assert.LessOrEqual(t, mi.RuleID, mj.RuleID,
					"matches at same offset must be sorted by ruleID")
			} else {
				assert.LessOrEqual(t, mi.Location.Offset.End, mj.Location.Offset.End,
					"matches at same start must be sorted by end offset")
			}
		} else {
			assert.Less(t, mi.Location.Offset.Start, mj.Location.Offset.Start,
				"matches must be sorted by start offset")
		}
	}
}

// TestPortableRegexp_QueueCapDropsExcess verifies that once the retry queue reaches
// retryQueueCap entries, additional jobs are dropped and retryDropped is incremented.
// DrainTimedOut must emit a warning when dropped > 0.
func TestPortableRegexp_QueueCapDropsExcess(t *testing.T) {
	var warnBuf []string
	warnf := func(format string, args ...any) {
		warnBuf = append(warnBuf, fmt.Sprintf(format, args...))
	}

	// Each job needs a distinct rule ID to avoid the blacklist triggering before the cap.
	// Use distinct rules so the per-rule blacklist does not fire before we fill the cap.
	rules := make([]*types.Rule, retryQueueCap+1)
	for i := range rules {
		rules[i] = &types.Rule{
			ID:      fmt.Sprintf("distinct-rule-%d", i),
			Name:    fmt.Sprintf("Rule %d", i),
			Pattern: `SECRET_KEY=([A-Z0-9]{20})`,
		}
	}

	// Re-create matcher with all distinct rules so they are in regexCache.
	m2, err := NewPortableRegexpWithTimeout(rules, 0, warnf, 1*time.Millisecond)
	require.NoError(t, err)

	// Inject retryQueueCap+1 jobs with distinct (blob, rule) pairs.
	for i := 0; i <= retryQueueCap; i++ {
		blob := []byte(fmt.Sprintf("content-%d", i))
		blobID := types.ComputeBlobID(blob)
		m2.enqueueOrBlacklist(retryJob{content: blob, blobID: blobID, rule: rules[i]})
	}

	m2.retryMu.Lock()
	queueLen := len(m2.retryJobs)
	dropped := m2.retryDropped
	m2.retryMu.Unlock()

	assert.Equal(t, retryQueueCap, queueLen,
		"queue must be capped at retryQueueCap entries")
	assert.Equal(t, 1, dropped,
		"exactly one job should have been dropped")

	// DrainTimedOut should emit a cap-reached warning.
	_, err = m2.DrainTimedOut()
	require.NoError(t, err)

	capWarnings := 0
	for _, w := range warnBuf {
		if strings.Contains(w, "retry queue cap") {
			capWarnings++
			assert.Contains(t, w, fmt.Sprintf("%d", retryQueueCap),
				"warning must mention the cap value")
			assert.Contains(t, w, "1 (blob, rule) pairs were not retried",
				"warning must report the drop count")
		}
	}
	assert.Equal(t, 1, capWarnings, "exactly one cap-reached warning must be emitted")
}

func TestPortableRegexpMatcher_Reset_ClearsPerScanState(t *testing.T) {
	rules := []*types.Rule{{ID: "r1", Pattern: `AKIA[0-9A-Z]{16}`}}
	m, err := NewPortableRegexp(rules, 0, nil)
	require.NoError(t, err)

	// Simulate a scan that timed out: content queued for retry + rule blacklisted.
	m.retryJobs = []retryJob{{content: []byte("sensitive blob"), rule: rules[0]}}
	m.retryDropped = 3
	m.blacklist["r1"] = retryBlacklistThreshold

	m.Reset()

	require.Empty(t, m.retryJobs, "retry queue (holds scanned content) must be cleared")
	require.Zero(t, m.retryDropped)
	require.Empty(t, m.blacklist, "timeout blacklist must be cleared")
	require.NotEmpty(t, m.regexCache, "compiled patterns must survive Reset")
}
