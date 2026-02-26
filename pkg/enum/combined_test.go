package enum

import (
	"context"
	"errors"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockEnumerator is a simple Enumerator that yields a fixed set of blobs.
type mockEnumerator struct {
	blobs []mockBlob
}

type mockBlob struct {
	content []byte
	blobID  types.BlobID
	prov    types.Provenance
}

func (m *mockEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	for _, b := range m.blobs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := callback(b.content, b.blobID, b.prov); err != nil {
			return err
		}
	}
	return nil
}

// blobID creates a fixed BlobID from a byte value for test convenience.
func blobIDFrom(b byte) types.BlobID {
	var id types.BlobID
	id[0] = b
	return id
}

func TestCombinedEnumerator_Empty(t *testing.T) {
	combined := NewCombinedEnumerator()

	var yielded int
	err := combined.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		yielded++
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 0, yielded, "empty CombinedEnumerator should yield no blobs")
}

func TestCombinedEnumerator_SingleEnumerator(t *testing.T) {
	id1 := blobIDFrom(1)
	id2 := blobIDFrom(2)
	prov1 := types.FileProvenance{FilePath: "a.txt"}
	prov2 := types.FileProvenance{FilePath: "b.txt"}

	e1 := &mockEnumerator{blobs: []mockBlob{
		{content: []byte("hello"), blobID: id1, prov: prov1},
		{content: []byte("world"), blobID: id2, prov: prov2},
	}}
	combined := NewCombinedEnumerator(e1)

	type yielded struct {
		blobID types.BlobID
		prov   types.Provenance
	}
	var results []yielded
	err := combined.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		results = append(results, yielded{blobID: blobID, prov: prov})
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, id1, results[0].blobID)
	assert.Equal(t, id2, results[1].blobID)
}

func TestCombinedEnumerator_DeduplicatesByBlobID(t *testing.T) {
	sharedID := blobIDFrom(42)
	uniqueID := blobIDFrom(99)

	// Both enumerators yield the same blobID; only one should reach the callback.
	e1 := &mockEnumerator{blobs: []mockBlob{
		{content: []byte("dup"), blobID: sharedID, prov: types.FileProvenance{FilePath: "first.txt"}},
	}}
	e2 := &mockEnumerator{blobs: []mockBlob{
		{content: []byte("dup"), blobID: sharedID, prov: types.FileProvenance{FilePath: "second.txt"}},
		{content: []byte("unique"), blobID: uniqueID, prov: types.FileProvenance{FilePath: "unique.txt"}},
	}}
	combined := NewCombinedEnumerator(e1, e2)

	var blobIDs []types.BlobID
	err := combined.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobIDs = append(blobIDs, blobID)
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, blobIDs, 2, "shared blob should be deduplicated, only 2 unique blobs expected")
	assert.Contains(t, blobIDs, sharedID)
	assert.Contains(t, blobIDs, uniqueID)
}

func TestCombinedEnumerator_AllUniqueBlobs(t *testing.T) {
	e1 := &mockEnumerator{blobs: []mockBlob{
		{content: []byte("a"), blobID: blobIDFrom(1), prov: types.FileProvenance{FilePath: "a.txt"}},
		{content: []byte("b"), blobID: blobIDFrom(2), prov: types.FileProvenance{FilePath: "b.txt"}},
	}}
	e2 := &mockEnumerator{blobs: []mockBlob{
		{content: []byte("c"), blobID: blobIDFrom(3), prov: types.FileProvenance{FilePath: "c.txt"}},
	}}
	combined := NewCombinedEnumerator(e1, e2)

	var count int
	err := combined.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 3, count, "all unique blobs from both enumerators should be yielded")
}

func TestCombinedEnumerator_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var callCount int
	e1 := &mockEnumerator{blobs: []mockBlob{
		{content: []byte("a"), blobID: blobIDFrom(1), prov: types.FileProvenance{FilePath: "a.txt"}},
		{content: []byte("b"), blobID: blobIDFrom(2), prov: types.FileProvenance{FilePath: "b.txt"}},
	}}
	combined := NewCombinedEnumerator(e1)

	err := combined.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		callCount++
		cancel() // Cancel after first blob
		return nil
	})

	// The context cancellation should propagate as an error.
	assert.True(t, errors.Is(err, context.Canceled), "expected context.Canceled, got: %v", err)
	assert.Equal(t, 1, callCount, "should stop after cancellation")
}
