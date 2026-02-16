# Datastore Directory Design

**Date:** 2026-02-12
**Status:** Approved

## Overview

Replace single `titus.db` file with NoseyParker-style datastore directory for git clone caching, optional blob storage, and future triage workflows.

## Directory Structure

```
titus.ds/
├── datastore.db      # SQLite database (metadata, matches, findings)
├── blobs/            # Content-addressable blob storage (optional)
│   ├── ab/
│   │   └── cdef1234...  # Blob files stored by SHA prefix
│   └── ...
├── clones/           # Cached bare git repositories
│   └── github.com/
│       └── org/
│           └── repo.git/  # Bare clone
├── scratch/          # Temporary workspace for operations
└── .gitignore        # Ignore this directory in version control
```

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Default name | `titus.ds` | Short, branded |
| Backward compat | None | Clean break, simpler implementation |
| Blob storage | Hybrid (`--store-blobs`) | Optional, avoids storage explosion |
| Git clones | Bare clones | Matches NoseyParker, updatable with fetch |
| `:memory:` support | Keep | Useful for ephemeral scans |
| Triage workflow | Deferred | Focus on core datastore first |

## Interface Design

### Datastore Type

```go
// pkg/datastore/datastore.go

type Datastore struct {
    Path       string       // Directory path (e.g., "titus.ds")
    Store      store.Store  // SQLite store for metadata
    BlobStore  *BlobStore   // Optional blob storage (nil if --store-blobs not set)
    CloneCache *CloneCache  // Git clone cache manager
}

// Open opens or creates a datastore directory
func Open(path string, opts Options) (*Datastore, error)

// Options for datastore behavior
type Options struct {
    StoreBlobs bool  // Enable blob storage (--store-blobs)
}
```

### Blob Storage

```go
// pkg/datastore/blobs.go

type BlobStore struct {
    Root string  // e.g., "titus.ds/blobs"
}

// Store writes content and returns blob ID (SHA-1 hex)
func (b *BlobStore) Store(content []byte) (types.BlobID, error)

// Get retrieves content by blob ID
func (b *BlobStore) Get(id types.BlobID) ([]byte, error)

// Exists checks if blob is already stored
func (b *BlobStore) Exists(id types.BlobID) bool
```

Storage layout uses git-style 2-char prefix:
```
blobs/ab/cdef1234567890...
```

### Clone Cache

```go
// pkg/datastore/clones.go

type CloneCache struct {
    Root string  // e.g., "titus.ds/clones"
}

// GetOrClone returns path to cached bare clone, cloning if needed
func (c *CloneCache) GetOrClone(repoURL string) (string, error)

// Update fetches latest refs for a cached clone
func (c *CloneCache) Update(repoURL string) error
```

Directory layout mirrors URL structure:
```
clones/github.com/org/repo.git/
```

## CLI Changes

**Updated flags:**

```
--output       Output datastore path (default: "titus.ds", use ":memory:" for ephemeral)
--store-blobs  Store file contents in blobs/ directory (default: false)
```

**Example usage:**

```bash
# Default - creates titus.ds/ directory
titus scan ./src

# Ephemeral scan (no files created)
titus scan --output=:memory: ./src

# Custom datastore with blob storage
titus scan --output=results.ds --store-blobs ./src

# Git scan with clone caching
titus scan --git https://github.com/org/repo

# Incremental re-scan (uses cached clone, skips scanned blobs)
titus scan --git --incremental https://github.com/org/repo
```

## Implementation

### New Files

```
pkg/datastore/
├── datastore.go      # Datastore type, Open/Close
├── datastore_test.go
├── blobs.go          # BlobStore implementation
├── blobs_test.go
├── clones.go         # CloneCache implementation
└── clones_test.go
```

### Modified Files

- `cmd/titus/scan.go` - Use Datastore instead of Store directly, add `--store-blobs` flag
- `pkg/store/store_default.go` - Keep for `:memory:` case

### Scan Flow

```go
// In scan.go
if scanOutputPath == ":memory:" {
    // Use in-memory store directly (current behavior)
    s, err := store.New(store.Config{Path: ":memory:"})
} else {
    // Use new datastore directory
    ds, err := datastore.Open(scanOutputPath, datastore.Options{
        StoreBlobs: scanStoreBlobs,
    })
}
```

## Future Work (Deferred)

- Triage workflow: `match_status`, `finding_comment` tables
- `titus accept`, `titus reject`, `titus comment` commands
- Match scoring and redundancy detection
