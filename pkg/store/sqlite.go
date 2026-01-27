package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

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

	_, err = s.db.Exec(`
		INSERT OR IGNORE INTO matches (blob_id, rule_id, structural_id, offset_start, offset_end, snippet_matching, groups_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`,
		m.BlobID.Hex(),
		m.RuleID,
		m.StructuralID,
		m.Location.Offset.Start,
		m.Location.Offset.End,
		m.Snippet.Matching,
		string(groupsJSON),
	)
	if err != nil {
		return fmt.Errorf("inserting match: %w", err)
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
		INSERT INTO provenance (blob_id, type, path, repo_path, commit_hash)
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

// GetMatches retrieves matches for a blob.
func (s *SQLiteStore) GetMatches(blobID types.BlobID) ([]*types.Match, error) {
	rows, err := s.db.Query(`
		SELECT blob_id, rule_id, structural_id, offset_start, offset_end, snippet_matching, groups_json
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

		err := rows.Scan(
			&blobIDHex,
			&m.RuleID,
			&m.StructuralID,
			&m.Location.Offset.Start,
			&m.Location.Offset.End,
			&m.Snippet.Matching,
			&groupsJSON,
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

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
