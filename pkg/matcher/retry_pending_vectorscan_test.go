//go:build !wasm && cgo && vectorscan

package matcher

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVectorscan_HasPendingRetryTracksQueue: a blob is pending from the
// moment its job is queued until DrainTimedOut takes the queue.
func TestVectorscan_HasPendingRetryTracksQueue(t *testing.T) {
	m, err := NewVectorscan([]*types.Rule{retryPendingRule}, 0, nil)
	require.NoError(t, err)
	defer func() { _ = m.Close() }()

	content := []byte("SECRET_KEY=ABCDEFGHIJ1234567890\n")
	id := types.ComputeBlobID(content)
	assert.False(t, m.HasPendingRetry(id))
	m.enqueueOrBlacklist(retryJob{content: content, blobID: id, rule: retryPendingRule})
	assert.True(t, m.HasPendingRetry(id))

	_, err = m.DrainTimedOut()
	require.NoError(t, err)
	assert.False(t, m.HasPendingRetry(id))
}
