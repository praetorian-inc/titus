package store

import (
	"fmt"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Store provides persistence for scan results.
// This interface abstracts the underlying storage implementation,
// allowing for different backends (SQLite, PostgreSQL, etc.).
type Store interface {
	// AddBlob stores a blob record.
	AddBlob(id types.BlobID, size int64) error

	// AddMatch stores a match record.
	AddMatch(m *types.Match) error

	// AddFinding stores a finding (deduplicated).
	AddFinding(f *types.Finding) error

	// AddProvenance associates provenance with a blob.
	AddProvenance(blobID types.BlobID, prov types.Provenance) error

	// GetMatches retrieves matches for a blob.
	GetMatches(blobID types.BlobID) ([]*types.Match, error)

	// GetAllMatches retrieves all matches (for JSON export).
	GetAllMatches() ([]*types.Match, error)

	// GetFindings retrieves all findings (for reporting).
	GetFindings() ([]*types.Finding, error)

	// FindingExists checks if a finding with this structural ID exists.
	FindingExists(structuralID string) (bool, error)

	// BlobExists checks if a blob has already been scanned.
	BlobExists(id types.BlobID) (bool, error)

	// Close closes the database connection.
	Close() error
}

// Config for store initialization.
type Config struct {
	// Path is the database file path.
	// Use ":memory:" for in-memory database (useful for testing).
	Path string
}

// New creates a new Store.
// Currently only supports SQLite backend.
func New(cfg Config) (Store, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("path is required")
	}

	return NewSQLite(cfg.Path)
}
