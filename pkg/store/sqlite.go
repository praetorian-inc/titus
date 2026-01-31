//go:build !wasm

package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/praetorian-inc/titus/pkg/types"
)

// SQLiteStore implements Store using SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLite creates a SQLite-based store.
// Use ":memory:" for in-memory database (useful for testing).
func NewSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Initialize schema
	if err := CreateSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

// AddBlob stores a blob record.
func (s *SQLiteStore) AddBlob(id types.BlobID, size int64) error {
	_, err := s.db.Exec("INSERT OR IGNORE INTO blobs (id, size) VALUES (?, ?)", id.Hex(), size)
	if err != nil {
		return fmt.Errorf("inserting blob: %w", err)
	}
	return nil
}

// AddMatch stores a match record.
func (s *SQLiteStore) AddMatch(m *types.Match) error {
	// Serialize groups to JSON
	groupsJSON, err := json.Marshal(m.Groups)
	if err != nil {
		return fmt.Errorf("marshaling groups: %w", err)
	}

	// Prepare validation fields (nullable)
	var validationStatus, validationMessage, validationTimestamp *string
	var validationConfidence *float64

	if m.ValidationResult != nil {
		status := string(m.ValidationResult.Status)
		validationStatus = &status
		validationConfidence = &m.ValidationResult.Confidence
		validationMessage = &m.ValidationResult.Message
		timestamp := m.ValidationResult.ValidatedAt.Format("2006-01-02T15:04:05.000Z07:00")
		validationTimestamp = &timestamp
	}

	_, err = s.db.Exec(`
		INSERT INTO matches (blob_id, rule_id, structural_id, offset_start, offset_end, snippet_before, snippet_matching, snippet_after, groups_json, validation_status, validation_confidence, validation_message, validation_timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(structural_id) DO UPDATE SET
			validation_status = COALESCE(excluded.validation_status, validation_status),
			validation_confidence = COALESCE(excluded.validation_confidence, validation_confidence),
			validation_message = COALESCE(excluded.validation_message, validation_message),
			validation_timestamp = COALESCE(excluded.validation_timestamp, validation_timestamp)
	`,
		m.BlobID.Hex(),
		m.RuleID,
		m.StructuralID,
		m.Location.Offset.Start,
		m.Location.Offset.End,
		m.Snippet.Before,
		m.Snippet.Matching,
		m.Snippet.After,
		string(groupsJSON),
		validationStatus,
		validationConfidence,
		validationMessage,
		validationTimestamp,
	)
	if err != nil {
		return fmt.Errorf("inserting/updating match: %w", err)
	}

	return nil
}

// AddFinding stores a finding (deduplicated).
func (s *SQLiteStore) AddFinding(f *types.Finding) error {
	// Serialize groups to JSON
	groupsJSON, err := json.Marshal(f.Groups)
	if err != nil {
		return fmt.Errorf("marshaling groups: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT OR IGNORE INTO findings (structural_id, rule_id, groups_json)
		VALUES (?, ?, ?)
	`,
		f.ID,
		f.RuleID,
		string(groupsJSON),
	)
	if err != nil {
		return fmt.Errorf("inserting finding: %w", err)
	}

	return nil
}

// AddProvenance associates provenance with a blob.
func (s *SQLiteStore) AddProvenance(blobID types.BlobID, prov types.Provenance) error {
	var path, repoPath, commitHash *string

	switch p := prov.(type) {
	case types.FileProvenance:
		path = &p.FilePath
	case types.GitProvenance:
		repoPath = &p.RepoPath
		path = &p.BlobPath
		if p.Commit != nil {
			commitHash = &p.Commit.CommitID
		}
	case types.ExtendedProvenance:
		// Extended provenance doesn't have structured fields
	default:
		return fmt.Errorf("unknown provenance type: %T", prov)
	}

	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO provenance (blob_id, type, path, repo_path, commit_hash)
		VALUES (?, ?, ?, ?, ?)
	`,
		blobID.Hex(),
		prov.Kind(),
		path,
		repoPath,
		commitHash,
	)
	if err != nil {
		return fmt.Errorf("inserting provenance: %w", err)
	}

	return nil
}

// GetAllProvenance retrieves all provenance records for a blob.
func (s *SQLiteStore) GetAllProvenance(blobID types.BlobID) ([]types.Provenance, error) {
	rows, err := s.db.Query(`
		SELECT type, path, repo_path, commit_hash
		FROM provenance
		WHERE blob_id = ?
	`, blobID.Hex())
	if err != nil {
		return nil, fmt.Errorf("querying provenance: %w", err)
	}
	defer rows.Close()

	var provenances []types.Provenance
	for rows.Next() {
		var provType string
		var path, repoPath, commitHash *string

		err := rows.Scan(&provType, &path, &repoPath, &commitHash)
		if err != nil {
			return nil, fmt.Errorf("scanning provenance: %w", err)
		}

		// Reconstruct the appropriate provenance type
		switch provType {
		case "file":
			if path != nil {
				provenances = append(provenances, types.FileProvenance{
					FilePath: *path,
				})
			}
		case "git":
			gitProv := types.GitProvenance{}
			if repoPath != nil {
				gitProv.RepoPath = *repoPath
			}
			if path != nil {
				gitProv.BlobPath = *path
			}
			if commitHash != nil {
				gitProv.Commit = &types.CommitMetadata{
					CommitID: *commitHash,
				}
			}
			provenances = append(provenances, gitProv)
		case "extended":
			// Extended provenance doesn't have structured fields
			provenances = append(provenances, types.ExtendedProvenance{})
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating provenance: %w", err)
	}

	return provenances, nil
}

// GetMatches retrieves matches for a blob.
func (s *SQLiteStore) GetMatches(blobID types.BlobID) ([]*types.Match, error) {
	rows, err := s.db.Query(`
		SELECT blob_id, rule_id, structural_id, offset_start, offset_end, snippet_before, snippet_matching, snippet_after, groups_json, validation_status, validation_confidence, validation_message, validation_timestamp
		FROM matches
		WHERE blob_id = ?
	`, blobID.Hex())
	if err != nil {
		return nil, fmt.Errorf("querying matches: %w", err)
	}
	defer rows.Close()

	var matches []*types.Match
	for rows.Next() {
		var m types.Match
		var blobIDHex string
		var groupsJSON string
		var validationStatus, validationMessage, validationTimestamp *string
		var validationConfidence *float64

		err := rows.Scan(
			&blobIDHex,
			&m.RuleID,
			&m.StructuralID,
			&m.Location.Offset.Start,
			&m.Location.Offset.End,
			&m.Snippet.Before,
			&m.Snippet.Matching,
			&m.Snippet.After,
			&groupsJSON,
			&validationStatus,
			&validationConfidence,
			&validationMessage,
			&validationTimestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning match: %w", err)
		}

		// Parse blob ID
		blobID, err := types.ParseBlobID(blobIDHex)
		if err != nil {
			return nil, fmt.Errorf("parsing blob ID: %w", err)
		}
		m.BlobID = blobID

		// Unmarshal groups
		if err := json.Unmarshal([]byte(groupsJSON), &m.Groups); err != nil {
			return nil, fmt.Errorf("unmarshaling groups: %w", err)
		}

		// Reconstruct validation result if present
		if validationStatus != nil {
			validatedAt, err := time.Parse("2006-01-02T15:04:05.000Z07:00", *validationTimestamp)
			if err != nil {
				return nil, fmt.Errorf("parsing validation timestamp: %w", err)
			}

			m.ValidationResult = &types.ValidationResult{
				Status:      types.ValidationStatus(*validationStatus),
				Confidence:  *validationConfidence,
				Message:     *validationMessage,
				ValidatedAt: validatedAt,
			}
		}

		matches = append(matches, &m)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating matches: %w", err)
	}

	return matches, nil
}

// GetAllMatches retrieves all matches (for JSON export).
func (s *SQLiteStore) GetAllMatches() ([]*types.Match, error) {
	rows, err := s.db.Query(`
		SELECT blob_id, rule_id, structural_id, offset_start, offset_end, snippet_before, snippet_matching, snippet_after, groups_json, validation_status, validation_confidence, validation_message, validation_timestamp
		FROM matches
	`)
	if err != nil {
		return nil, fmt.Errorf("querying matches: %w", err)
	}
	defer rows.Close()

	var matches []*types.Match
	for rows.Next() {
		var m types.Match
		var blobIDHex string
		var groupsJSON string
		var validationStatus, validationMessage, validationTimestamp *string
		var validationConfidence *float64

		err := rows.Scan(
			&blobIDHex,
			&m.RuleID,
			&m.StructuralID,
			&m.Location.Offset.Start,
			&m.Location.Offset.End,
			&m.Snippet.Before,
			&m.Snippet.Matching,
			&m.Snippet.After,
			&groupsJSON,
			&validationStatus,
			&validationConfidence,
			&validationMessage,
			&validationTimestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning match: %w", err)
		}

		// Parse blob ID
		blobID, err := types.ParseBlobID(blobIDHex)
		if err != nil {
			return nil, fmt.Errorf("parsing blob ID: %w", err)
		}
		m.BlobID = blobID

		// Unmarshal groups
		if err := json.Unmarshal([]byte(groupsJSON), &m.Groups); err != nil {
			return nil, fmt.Errorf("unmarshaling groups: %w", err)
		}

		// Reconstruct validation result if present
		if validationStatus != nil {
			validatedAt, err := time.Parse("2006-01-02T15:04:05.000Z07:00", *validationTimestamp)
			if err != nil {
				return nil, fmt.Errorf("parsing validation timestamp: %w", err)
			}

			m.ValidationResult = &types.ValidationResult{
				Status:      types.ValidationStatus(*validationStatus),
				Confidence:  *validationConfidence,
				Message:     *validationMessage,
				ValidatedAt: validatedAt,
			}
		}

		matches = append(matches, &m)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating matches: %w", err)
	}

	return matches, nil
}

// GetFindings retrieves all findings (for reporting).
func (s *SQLiteStore) GetFindings() ([]*types.Finding, error) {
	rows, err := s.db.Query(`
		SELECT structural_id, rule_id, groups_json
		FROM findings
	`)
	if err != nil {
		return nil, fmt.Errorf("querying findings: %w", err)
	}
	defer rows.Close()

	var findings []*types.Finding
	for rows.Next() {
		var f types.Finding
		var groupsJSON string

		err := rows.Scan(&f.ID, &f.RuleID, &groupsJSON)
		if err != nil {
			return nil, fmt.Errorf("scanning finding: %w", err)
		}

		// Unmarshal groups
		if err := json.Unmarshal([]byte(groupsJSON), &f.Groups); err != nil {
			return nil, fmt.Errorf("unmarshaling groups: %w", err)
		}

		findings = append(findings, &f)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating findings: %w", err)
	}

	return findings, nil
}

// FindingExists checks if a finding with this structural ID exists.
func (s *SQLiteStore) FindingExists(structuralID string) (bool, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM findings WHERE structural_id = ?", structuralID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("checking finding existence: %w", err)
	}
	return count > 0, nil
}

// BlobExists checks if a blob has already been scanned.
func (s *SQLiteStore) BlobExists(id types.BlobID) (bool, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM blobs WHERE id = ?", id.Hex()).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("checking blob existence: %w", err)
	}
	return count > 0, nil
}

// GetProvenance retrieves provenance for a blob.
func (s *SQLiteStore) GetProvenance(blobID types.BlobID) (types.Provenance, error) {
	var provType string
	var path, repoPath, commitHash *string

	err := s.db.QueryRow(`
		SELECT type, path, repo_path, commit_hash
		FROM provenance
		WHERE blob_id = ?
		LIMIT 1
	`, blobID.Hex()).Scan(&provType, &path, &repoPath, &commitHash)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no provenance found for blob: %s", blobID.Hex())
	}
	if err != nil {
		return nil, fmt.Errorf("querying provenance: %w", err)
	}

	switch provType {
	case "file":
		if path == nil {
			return nil, fmt.Errorf("file provenance missing path")
		}
		return types.FileProvenance{FilePath: *path}, nil
	case "git":
		if path == nil {
			return nil, fmt.Errorf("git provenance missing path")
		}
		prov := types.GitProvenance{
			BlobPath: *path,
		}
		if repoPath != nil {
			prov.RepoPath = *repoPath
		}
		if commitHash != nil {
			prov.Commit = &types.CommitMetadata{
				CommitID: *commitHash,
			}
		}
		return prov, nil
	case "extended":
		return types.ExtendedProvenance{Payload: make(map[string]interface{})}, nil
	default:
		return nil, fmt.Errorf("unknown provenance type: %s", provType)
	}
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
