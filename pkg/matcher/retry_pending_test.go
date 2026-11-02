//go:build !wasm

package matcher

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var retryPendingRule = &types.Rule{
	ID:      "retry-pending-rule",
	Name:    "Retry Pending Rule",
	Pattern: `SECRET_KEY=([A-Z0-9]{20})`,
}

// TestPortableRegexp_HasPendingRetryTracksQueue: a blob is pending from the
// moment its job is queued until DrainTimedOut takes the queue.
func TestPortableRegexp_HasPendingRetryTracksQueue(t *testing.T) {
	m, err := NewPortableRegexp([]*types.Rule{retryPendingRule}, 0, nil)
	require.NoError(t, err)

	queued := []byte("SECRET_KEY=ABCDEFGHIJ1234567890\n")
	other := []byte("nothing here\n")
	queuedID, otherID := types.ComputeBlobID(queued), types.ComputeBlobID(other)

	assert.False(t, m.HasPendingRetry(queuedID), "no job queued yet")
	m.enqueueOrBlacklist(retryJob{content: queued, blobID: queuedID, rule: retryPendingRule})
	assert.True(t, m.HasPendingRetry(queuedID))
	assert.False(t, m.HasPendingRetry(otherID))

	retried, err := m.DrainTimedOut()
	require.NoError(t, err)
	require.Len(t, retried, 1)
	assert.Equal(t, queuedID, retried[0].BlobID)
	assert.False(t, m.HasPendingRetry(queuedID), "DrainTimedOut must clear the pending set")
}

// TestPortableRegexp_DroppedJobIsNotPending: a job dropped at the queue cap is
// never retried, so its blob is not pending. This also bounds the pending set
// by retryQueueCap.
func TestPortableRegexp_DroppedJobIsNotPending(t *testing.T) {
	m, err := NewPortableRegexp([]*types.Rule{retryPendingRule}, 0, nil)
	require.NoError(t, err)
	m.retryJobs = make([]retryJob, retryQueueCap)

	content := []byte("SECRET_KEY=ABCDEFGHIJ1234567890\n")
	id := types.ComputeBlobID(content)
	m.enqueueOrBlacklist(retryJob{content: content, blobID: id, rule: retryPendingRule})

	assert.Equal(t, 1, m.retryDropped)
	assert.False(t, m.HasPendingRetry(id))
	assert.Empty(t, m.retryBlobs)
}

// noRetryMatcher is a Matcher that does not implement RetryReporter.
type noRetryMatcher struct{ Matcher }

// TestHasPendingRetry_ForwardsThroughWrappers: the filtering and dedup
// wrappers that New puts around the engine forward HasPendingRetry, and a
// matcher without retry support reports false.
func TestHasPendingRetry_ForwardsThroughWrappers(t *testing.T) {
	rules := []*types.Rule{retryPendingRule}
	inner, err := NewPortableRegexp(rules, 0, nil)
	require.NoError(t, err)
	wrapped := newDedupMatcher(newFilteringMatcher(inner, rules), rules)

	content := []byte("SECRET_KEY=ABCDEFGHIJ1234567890\n")
	id := types.ComputeBlobID(content)
	assert.False(t, HasPendingRetry(wrapped, id))
	inner.enqueueOrBlacklist(retryJob{content: content, blobID: id, rule: retryPendingRule})
	assert.True(t, HasPendingRetry(wrapped, id))

	assert.False(t, HasPendingRetry(noRetryMatcher{inner}, id))
}
