package store

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Store provides persistence for scan results.
// This interface abstracts the underlying storage implementation,
// allowing for different backends (SQLite, PostgreSQL, etc.).
type Store interface {
	// AddBlob stores a blob record.
	AddBlob(id types.BlobID, size int64) error

	// AddRule stores a detection rule.
	AddRule(r *types.Rule) error

	// AddMatch stores a match record.
	AddMatch(m *types.Match) error

	// AddFinding stores a finding (deduplicated).
	AddFinding(f *types.Finding) error

	// AddProvenance associates provenance with a blob.
	AddProvenance(blobID types.BlobID, prov types.Provenance) error

	// GetAllProvenance retrieves all provenance records for a blob.
	GetAllProvenance(blobID types.BlobID) ([]types.Provenance, error)

	// AddOccurrences records every location of a blob. Inserting the same
	// occurrence again is a no-op.
	AddOccurrences(blobID types.BlobID, occs []types.Occurrence) error

	// GetOccurrences returns every location of a blob: its recorded
	// occurrences merged with its provenance rows (see
	// types.MergeOccurrences), deduplicated and sorted. A datastore written
	// before occurrences were recorded still yields its provenance locations.
	GetOccurrences(blobID types.BlobID) ([]types.Occurrence, error)

	// GetMatches retrieves matches for a blob.
	GetMatches(blobID types.BlobID) ([]*types.Match, error)

	// HasMatches reports whether any match is stored for a blob, without
	// loading the matches.
	HasMatches(blobID types.BlobID) (bool, error)

	// GetAllMatches retrieves all matches (for JSON export).
	GetAllMatches() ([]*types.Match, error)

	// GetFindings retrieves all findings (for reporting).
	GetFindings() ([]*types.Finding, error)

	// FindingExists checks if a finding with this structural ID exists.
	FindingExists(structuralID string) (bool, error)

	// BlobExists checks if a blob has already been scanned.
	BlobExists(id types.BlobID) (bool, error)

	// GetProvenance retrieves provenance for a blob.
	GetProvenance(blobID types.BlobID) (types.Provenance, error)

	// ExecBatch executes fn within a database transaction for batched writes.
	// The Store passed to fn uses the transaction; the outer Store is unchanged.
	ExecBatch(fn func(Store) error) error

	// GetAnnotation retrieves an annotation for a target.
	GetAnnotation(targetType, targetID string) (status string, comment string, err error)

	// SetAnnotation creates or updates an annotation.
	SetAnnotation(targetType, targetID, status, comment string) error

	// GetAnnotationsByType returns a map of targetID → status for all annotations
	// of the given targetType. Useful when filtering many findings at once.
	GetAnnotationsByType(targetType string) (map[string]string, error)

	// Close closes the database connection.
	Close() error
}

// Config for store initialization.
type Config struct {
	// Path is the database file path.
	// Use ":memory:" for in-memory database (useful for testing).
	Path string
}

// provenanceRowKey holds the provenance columns that make up the SQLite
// UNIQUE key, minus blob_id.
type provenanceRowKey struct {
	kind, path, repoPath, commitHash string
}

// provenanceKeyOf maps a provenance to its stored key columns.
func provenanceKeyOf(prov types.Provenance) (provenanceRowKey, error) {
	switch p := prov.(type) {
	case types.FileProvenance:
		return provenanceRowKey{kind: "file", path: p.FilePath}, nil
	case types.GitProvenance:
		k := provenanceRowKey{kind: "git", path: p.BlobPath, repoPath: p.RepoPath}
		if p.Commit != nil {
			k.commitHash = p.Commit.CommitID
		}
		return k, nil
	case types.ExtendedProvenance:
		payloadJSON, _ := json.Marshal(p.Payload)
		return provenanceRowKey{kind: "extended", path: string(payloadJSON)}, nil
	case types.ArchiveProvenance:
		return provenanceRowKey{kind: "archive", path: p.ArchivePath, repoPath: p.MemberPath}, nil
	default:
		return provenanceRowKey{}, fmt.Errorf("unknown provenance type: %T", prov)
	}
}

// mergedOccurrences merges location rows with provenance rows and never
// returns nil.
func mergedOccurrences(rows []types.Occurrence, provs []types.Provenance) []types.Occurrence {
	if out := types.MergeOccurrences(rows, provs); out != nil {
		return out
	}
	return []types.Occurrence{}
}
