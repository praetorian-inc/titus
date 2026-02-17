package datastore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlobStore_Store(t *testing.T) {
	tmpDir := t.TempDir()
	bs := &BlobStore{Root: tmpDir}

	content := []byte("hello world")
	id, err := bs.Store(content)
	require.NoError(t, err)

	// Verify blob ID matches git-style hash
	expectedID := types.ComputeBlobID(content)
	assert.Equal(t, expectedID, id)

	// Verify blob file was created with correct prefix
	blobPath := bs.blobPath(id)
	assert.FileExists(t, blobPath)

	// Verify content matches
	storedContent, err := os.ReadFile(blobPath)
	require.NoError(t, err)
	assert.Equal(t, content, storedContent)
}

func TestBlobStore_StoreIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	bs := &BlobStore{Root: tmpDir}

	content := []byte("test content")

	// Store same content twice
	id1, err := bs.Store(content)
	require.NoError(t, err)

	id2, err := bs.Store(content)
	require.NoError(t, err)

	// Should return same ID
	assert.Equal(t, id1, id2)

	// Should only have one file
	blobPath := bs.blobPath(id1)
	assert.FileExists(t, blobPath)
}

func TestBlobStore_Get(t *testing.T) {
	tmpDir := t.TempDir()
	bs := &BlobStore{Root: tmpDir}

	content := []byte("test content\n")
	id, err := bs.Store(content)
	require.NoError(t, err)

	// Retrieve content
	retrievedContent, err := bs.Get(id)
	require.NoError(t, err)
	assert.Equal(t, content, retrievedContent)
}

func TestBlobStore_GetNonexistent(t *testing.T) {
	tmpDir := t.TempDir()
	bs := &BlobStore{Root: tmpDir}

	// Try to get blob that doesn't exist
	nonexistentID := types.ComputeBlobID([]byte("does not exist"))
	_, err := bs.Get(nonexistentID)
	assert.Error(t, err)
}

func TestBlobStore_Exists(t *testing.T) {
	tmpDir := t.TempDir()
	bs := &BlobStore{Root: tmpDir}

	content := []byte("exists test")
	id, err := bs.Store(content)
	require.NoError(t, err)

	// Should exist
	assert.True(t, bs.Exists(id))

	// Nonexistent blob should not exist
	nonexistentID := types.ComputeBlobID([]byte("does not exist"))
	assert.False(t, bs.Exists(nonexistentID))
}

func TestBlobStore_blobPath(t *testing.T) {
	tmpDir := t.TempDir()
	bs := &BlobStore{Root: tmpDir}

	// Test with known ID
	content := []byte("hello world")
	id := types.ComputeBlobID(content)
	hexID := id.Hex()

	path := bs.blobPath(id)

	// Should have 2-char prefix directory
	expectedPrefix := hexID[:2]
	expectedRest := hexID[2:]
	expectedPath := filepath.Join(tmpDir, expectedPrefix, expectedRest)

	assert.Equal(t, expectedPath, path)
}

func TestBlobStore_EmptyContent(t *testing.T) {
	tmpDir := t.TempDir()
	bs := &BlobStore{Root: tmpDir}

	// Store empty content
	content := []byte("")
	id, err := bs.Store(content)
	require.NoError(t, err)

	// Verify it can be retrieved
	retrievedContent, err := bs.Get(id)
	require.NoError(t, err)
	assert.Equal(t, content, retrievedContent)
}

func TestBlobStore_MultipleBlobs(t *testing.T) {
	tmpDir := t.TempDir()
	bs := &BlobStore{Root: tmpDir}

	contents := [][]byte{
		[]byte("first"),
		[]byte("second"),
		[]byte("third"),
	}

	ids := make([]types.BlobID, len(contents))

	// Store all blobs
	for i, content := range contents {
		id, err := bs.Store(content)
		require.NoError(t, err)
		ids[i] = id
	}

	// Verify all can be retrieved
	for i, id := range ids {
		retrievedContent, err := bs.Get(id)
		require.NoError(t, err)
		assert.Equal(t, contents[i], retrievedContent)
	}
}
