package main

import (
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pendingRetryMatcher is a matcher that reports a queued rule retry for the
// blobs in pending. Its other methods are never called by incrementalJob.
type pendingRetryMatcher struct {
	matcher.Matcher
	pending map[types.BlobID]bool
}

func (p pendingRetryMatcher) HasPendingRetry(id types.BlobID) bool { return p.pending[id] }

// ENG-9178: --incremental scans a blob the store has never seen, skips a
// stored blob that has no matches, and sends a stored blob with matches as
// known, so its new location is recorded without matching it again. A stored
// blob without matches yet whose timed-out rules this scan queued for retry
// is sent as known too: its matches arrive from the retry pass, and skipping
// it would drop this location (C2, review r3). Every stored case counts as
// skipped.
func TestIncrementalJob_SendSkipMatrix(t *testing.T) {
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	matched := types.ComputeBlobID([]byte("matched"))
	clean := types.ComputeBlobID([]byte("clean"))
	retrying := types.ComputeBlobID([]byte("retrying"))
	require.NoError(t, s.AddBlob(matched, 7))
	require.NoError(t, s.AddBlob(clean, 5))
	require.NoError(t, s.AddBlob(retrying, 8))
	m := pendingRetryMatcher{pending: map[types.BlobID]bool{retrying: true}}
	require.NoError(t, s.AddRule(&types.Rule{ID: "np.test.1", Name: "Test Rule", Pattern: "x", StructuralID: "r1"}))
	require.NoError(t, s.AddMatch(&types.Match{BlobID: matched, StructuralID: "m1", RuleID: "np.test.1", RuleName: "Test Rule"}))

	for _, tc := range []struct {
		name                         string
		id                           types.BlobID
		wantSend, wantSkip, wantKnow bool
	}{
		{"unknown blob is scanned", types.ComputeBlobID([]byte("new")), true, false, false},
		{"stored blob with matches is sent as known", matched, true, true, true},
		{"stored blob without matches is skipped", clean, false, true, false},
		{"stored blob without matches but a pending retry is sent as known", retrying, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job := blobJob{blobID: tc.id}
			send, skipped, err := incrementalJob(s, m, &job)
			require.NoError(t, err)
			assert.Equal(t, tc.wantSend, send, "send")
			assert.Equal(t, tc.wantSkip, skipped, "skipped")
			assert.Equal(t, tc.wantKnow, job.known, "known")
		})
	}

	// A matcher that queues no retries (nil here) leaves every stored blob
	// without matches skipped, the pending-retry one included.
	job := blobJob{blobID: retrying}
	send, skipped, err := incrementalJob(s, nil, &job)
	require.NoError(t, err)
	assert.False(t, send, "send without a retrying matcher")
	assert.True(t, skipped, "skipped without a retrying matcher")
	assert.False(t, job.known, "known without a retrying matcher")
}

// ENG-9178: a known blob is not matched again; matchJob returns no matches
// for it without touching the matcher (a nil matcher would panic).
func TestMatchJob_KnownBlobNotMatched(t *testing.T) {
	matches, err := matchJob(nil, blobJob{content: []byte("anything"), known: true})
	require.NoError(t, err)
	assert.Empty(t, matches)
}

// ENG-9178: the statistics line counts this scan's matches as new and
// reports blobs an incremental scan did not match again separately, only
// when there are any.
func TestScanStatsLine(t *testing.T) {
	assert.Equal(t,
		"Scanned 2048 B from 3 blobs in 2 second (1024 B/s); 1 new matches\n",
		scanStatsLine(2048, 3, 1, 0, 2*time.Second))
	assert.Equal(t,
		"Scanned 2048 B from 3 blobs in 2 second (1024 B/s); 1 new matches; 2 blobs already scanned, not matched again\n",
		scanStatsLine(2048, 3, 1, 2, 2*time.Second))
}
