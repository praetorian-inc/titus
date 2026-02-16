package datastore

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/titus/pkg/store"
)

// Datastore manages a directory-based datastore (NoseyParker-style).
type Datastore struct {
	Path       string       // Directory path (e.g., "titus.ds")
	Store      store.Store  // SQLite store for metadata
	BlobStore  *BlobStore   // Optional blob storage (nil if StoreBlobs not set)
	CloneCache *CloneCache  // Git clone cache manager
}

// Options configures datastore behavior.
type Options struct {
	StoreBlobs bool // Enable blob storage (--store-blobs flag)
}

// BlobStore manages content-addressable blob storage.
// Stub type - implementation in blobs.go.
type BlobStore struct {
	Root string
}

// CloneCache manages cached bare git clones.
// Stub type - implementation in clones.go.
type CloneCache struct {
	Root string
}

// Open opens or creates a datastore directory.
func Open(path string, opts Options) (*Datastore, error) {
	if path == "" {
		return nil, fmt.Errorf("datastore path is required")
	}

	// Create main directory
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, fmt.Errorf("creating datastore directory: %w", err)
	}

	// Create subdirectories
	subdirs := []string{"clones", "scratch"}
	if opts.StoreBlobs {
		subdirs = append(subdirs, "blobs")
	}
	for _, subdir := range subdirs {
		if err := os.MkdirAll(filepath.Join(path, subdir), 0755); err != nil {
			return nil, fmt.Errorf("creating %s directory: %w", subdir, err)
		}
	}

	// Write .gitignore
	gitignorePath := filepath.Join(path, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte("*\n"), 0644); err != nil {
		return nil, fmt.Errorf("writing .gitignore: %w", err)
	}

	// Create SQLite store
	dbPath := filepath.Join(path, "datastore.db")
	s, err := store.New(store.Config{Path: dbPath})
	if err != nil {
		return nil, fmt.Errorf("creating store: %w", err)
	}

	ds := &Datastore{
		Path:       path,
		Store:      s,
		CloneCache: &CloneCache{Root: filepath.Join(path, "clones")},
	}

	if opts.StoreBlobs {
		ds.BlobStore = &BlobStore{Root: filepath.Join(path, "blobs")}
	}

	return ds, nil
}

// Close closes the datastore and releases resources.
func (d *Datastore) Close() error {
	if d.Store != nil {
		return d.Store.Close()
	}
	return nil
}
