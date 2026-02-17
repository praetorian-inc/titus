package datastore

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Store writes content to blob storage and returns the blob ID.
// Blob ID is SHA-1 hash of content (same as git blob hashing).
func (b *BlobStore) Store(content []byte) (types.BlobID, error) {
	// Compute blob ID using git-style hash
	id := types.ComputeBlobID(content)

	// Check if blob already exists (content-addressable = idempotent)
	path := b.blobPath(id)
	if _, err := os.Stat(path); err == nil {
		// Blob already exists, return existing ID
		return id, nil
	}

	// Create prefix directory if needed
	prefixDir := filepath.Dir(path)
	if err := os.MkdirAll(prefixDir, 0755); err != nil {
		return types.BlobID{}, fmt.Errorf("creating blob directory: %w", err)
	}

	// Write blob content atomically using temp file + rename
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, content, 0644); err != nil {
		return types.BlobID{}, fmt.Errorf("writing blob: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath) // Clean up temp file on failure
		return types.BlobID{}, fmt.Errorf("renaming blob: %w", err)
	}

	return id, nil
}

// Get retrieves content by blob ID.
func (b *BlobStore) Get(id types.BlobID) ([]byte, error) {
	path := b.blobPath(id)

	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("blob not found: %s", id.Hex())
		}
		return nil, fmt.Errorf("reading blob: %w", err)
	}

	return content, nil
}

// Exists checks if a blob exists in storage.
func (b *BlobStore) Exists(id types.BlobID) bool {
	path := b.blobPath(id)
	_, err := os.Stat(path)
	return err == nil
}

// blobPath returns the file path for a blob ID.
// Uses git-style 2-char prefix: blobs/ab/cdef1234...
func (b *BlobStore) blobPath(id types.BlobID) string {
	hexID := id.Hex()
	// First 2 chars are directory prefix
	prefix := hexID[:2]
	// Rest is filename
	rest := hexID[2:]
	return filepath.Join(b.Root, prefix, rest)
}
