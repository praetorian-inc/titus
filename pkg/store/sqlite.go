//go:build !wasm

package store

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enabling WAL mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enabling foreign keys: %w", err)
	}
	if err := CreateSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) AddBlob(id types.BlobID, size int64) error {
	_, err := s.db.Exec("INSERT OR IGNORE INTO blobs (id, size) VALUES (?, ?)", id.Hex(), size)
	return err
}

func (s *SQLiteStore) AddRule(r *types.Rule) error {
	_, err := s.db.Exec("INSERT OR IGNORE INTO rules (id, name, pattern, structural_id) VALUES (?, ?, ?, ?)",
		r.ID, r.Name, r.Pattern, r.StructuralID)
	return err
}

func (s *SQLiteStore) BlobExists(id types.BlobID) (bool, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM blobs WHERE id = ?", id.Hex()).Scan(&count)
	return count > 0, err
}

func (s *SQLiteStore) AddMatch(m *types.Match) error {
	groupsJSON, err := serializeGroups(m.Groups)
	if err != nil {
		return fmt.Errorf("serializing groups: %w", err)
	}
	var validationStatus, validationMessage, validationTimestamp sql.NullString
	var validationConfidence sql.NullFloat64
	if m.ValidationResult != nil {
		validationStatus = sql.NullString{String: string(m.ValidationResult.Status), Valid: true}
		validationConfidence = sql.NullFloat64{Float64: m.ValidationResult.Confidence, Valid: true}
		validationMessage = sql.NullString{String: m.ValidationResult.Message, Valid: true}
		validationTimestamp = sql.NullString{String: m.ValidationResult.ValidatedAt.Format(time.RFC3339), Valid: true}
	}

	// Extract line/column from m.Location.Source
	var startLine, startColumn, endLine, endColumn sql.NullInt64
	if m.Location.Source.Start.Line != 0 {
		startLine = sql.NullInt64{Int64: int64(m.Location.Source.Start.Line), Valid: true}
	}
	if m.Location.Source.Start.Column != 0 {
		startColumn = sql.NullInt64{Int64: int64(m.Location.Source.Start.Column), Valid: true}
	}
	if m.Location.Source.End.Line != 0 {
		endLine = sql.NullInt64{Int64: int64(m.Location.Source.End.Line), Valid: true}
	}
	if m.Location.Source.End.Column != 0 {
		endColumn = sql.NullInt64{Int64: int64(m.Location.Source.End.Column), Valid: true}
	}

	// finding_id is null for now
	var findingID sql.NullInt64

	_, err = s.db.Exec(`INSERT OR IGNORE INTO matches (blob_id, rule_id, structural_id, offset_start, offset_end, snippet_before, snippet_matching, snippet_after, groups_json, validation_status, validation_confidence, validation_message, validation_timestamp, finding_id, start_line, start_column, end_line, end_column) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.BlobID.Hex(), m.RuleID, m.StructuralID, m.Location.Offset.Start, m.Location.Offset.End,
		m.Snippet.Before, m.Snippet.Matching, m.Snippet.After, groupsJSON,
		validationStatus, validationConfidence, validationMessage, validationTimestamp,
		findingID, startLine, startColumn, endLine, endColumn)
	return err
}

func (s *SQLiteStore) GetMatches(blobID types.BlobID) ([]*types.Match, error) {
	rows, err := s.db.Query(`SELECT blob_id, rule_id, structural_id, offset_start, offset_end, snippet_before, snippet_matching, snippet_after, groups_json, validation_status, validation_confidence, validation_message, validation_timestamp, finding_id, start_line, start_column, end_line, end_column FROM matches WHERE blob_id = ?`, blobID.Hex())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMatches(rows)
}

func (s *SQLiteStore) GetAllMatches() ([]*types.Match, error) {
	rows, err := s.db.Query(`SELECT blob_id, rule_id, structural_id, offset_start, offset_end, snippet_before, snippet_matching, snippet_after, groups_json, validation_status, validation_confidence, validation_message, validation_timestamp, finding_id, start_line, start_column, end_line, end_column FROM matches`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMatches(rows)
}

func (s *SQLiteStore) AddFinding(f *types.Finding) error {
	groupsJSON, err := serializeGroups(f.Groups)
	if err != nil {
		return fmt.Errorf("serializing groups: %w", err)
	}
	_, err = s.db.Exec("INSERT OR IGNORE INTO findings (structural_id, rule_id, groups_json) VALUES (?, ?, ?)", f.ID, f.RuleID, groupsJSON)
	return err
}

func (s *SQLiteStore) GetFindings() ([]*types.Finding, error) {
	rows, err := s.db.Query("SELECT structural_id, rule_id, groups_json FROM findings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*types.Finding
	for rows.Next() {
		var f types.Finding
		var groupsJSON sql.NullString
		if err := rows.Scan(&f.ID, &f.RuleID, &groupsJSON); err != nil {
			return nil, err
		}
		if groupsJSON.Valid {
			f.Groups, _ = deserializeGroups(groupsJSON.String)
		}
		result = append(result, &f)
	}
	if result == nil {
		return []*types.Finding{}, nil
	}
	return result, rows.Err()
}

func (s *SQLiteStore) FindingExists(structuralID string) (bool, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM findings WHERE structural_id = ?", structuralID).Scan(&count)
	return count > 0, err
}

func (s *SQLiteStore) AddProvenance(blobID types.BlobID, prov types.Provenance) error {
	var provType, path, repoPath, commitHash string
	switch p := prov.(type) {
	case types.FileProvenance:
		provType, path = "file", p.FilePath
	case types.GitProvenance:
		provType, path, repoPath = "git", p.BlobPath, p.RepoPath
		if p.Commit != nil {
			commitHash = p.Commit.CommitID
		}
	case types.ExtendedProvenance:
		provType = "extended"
		payloadJSON, _ := json.Marshal(p.Payload)
		path = string(payloadJSON)
	default:
		return fmt.Errorf("unknown provenance type: %T", prov)
	}
	_, err := s.db.Exec("INSERT OR IGNORE INTO provenance (blob_id, type, path, repo_path, commit_hash) VALUES (?, ?, ?, ?, ?)", blobID.Hex(), provType, path, repoPath, commitHash)
	return err
}

func (s *SQLiteStore) GetAllProvenance(blobID types.BlobID) ([]types.Provenance, error) {
	rows, err := s.db.Query("SELECT type, path, repo_path, commit_hash FROM provenance WHERE blob_id = ?", blobID.Hex())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []types.Provenance
	for rows.Next() {
		var provType string
		var path, repoPath, commitHash sql.NullString
		if err := rows.Scan(&provType, &path, &repoPath, &commitHash); err != nil {
			return nil, err
		}
		switch provType {
		case "file":
			result = append(result, types.FileProvenance{FilePath: path.String})
		case "git":
			prov := types.GitProvenance{RepoPath: repoPath.String, BlobPath: path.String}
			if commitHash.Valid && commitHash.String != "" {
				prov.Commit = &types.CommitMetadata{CommitID: commitHash.String}
			}
			result = append(result, prov)
		case "extended":
			var payload map[string]interface{}
			if path.Valid {
				json.Unmarshal([]byte(path.String), &payload)
			}
			result = append(result, types.ExtendedProvenance{Payload: payload})
		}
	}
	if result == nil {
		return []types.Provenance{}, nil
	}
	return result, rows.Err()
}

func (s *SQLiteStore) GetProvenance(blobID types.BlobID) (types.Provenance, error) {
	provs, err := s.GetAllProvenance(blobID)
	if err != nil {
		return nil, err
	}
	if len(provs) == 0 {
		return nil, fmt.Errorf("no provenance found for blob %s", blobID.Hex())
	}
	return provs[0], nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func scanMatches(rows *sql.Rows) ([]*types.Match, error) {
	var result []*types.Match
	for rows.Next() {
		var m types.Match
		var blobIDHex string
		var groupsJSON sql.NullString
		var snippetBefore, snippetMatching, snippetAfter []byte
		var validationStatus, validationMessage, validationTimestamp sql.NullString
		var validationConfidence sql.NullFloat64
		var findingID, startLine, startColumn, endLine, endColumn sql.NullInt64
		err := rows.Scan(&blobIDHex, &m.RuleID, &m.StructuralID, &m.Location.Offset.Start, &m.Location.Offset.End,
			&snippetBefore, &snippetMatching, &snippetAfter, &groupsJSON,
			&validationStatus, &validationConfidence, &validationMessage, &validationTimestamp,
			&findingID, &startLine, &startColumn, &endLine, &endColumn)
		if err != nil {
			return nil, err
		}
		m.BlobID, _ = types.ParseBlobID(blobIDHex)
		m.Snippet = types.Snippet{Before: snippetBefore, Matching: snippetMatching, After: snippetAfter}
		if groupsJSON.Valid {
			m.Groups, _ = deserializeGroups(groupsJSON.String)
		}
		if validationStatus.Valid {
			m.ValidationResult = &types.ValidationResult{
				Status:     types.ValidationStatus(validationStatus.String),
				Confidence: validationConfidence.Float64,
				Message:    validationMessage.String,
			}
			if validationTimestamp.Valid {
				m.ValidationResult.ValidatedAt, _ = time.Parse(time.RFC3339, validationTimestamp.String)
			}
		}
		// Populate m.Location.Source from the line/column values
		if startLine.Valid {
			m.Location.Source.Start.Line = int(startLine.Int64)
		}
		if startColumn.Valid {
			m.Location.Source.Start.Column = int(startColumn.Int64)
		}
		if endLine.Valid {
			m.Location.Source.End.Line = int(endLine.Int64)
		}
		if endColumn.Valid {
			m.Location.Source.End.Column = int(endColumn.Int64)
		}
		result = append(result, &m)
	}
	if result == nil {
		return []*types.Match{}, nil
	}
	return result, rows.Err()
}

func serializeGroups(groups [][]byte) (string, error) {
	if groups == nil {
		return "null", nil
	}
	encoded := make([]string, len(groups))
	for i, g := range groups {
		encoded[i] = base64.StdEncoding.EncodeToString(g)
	}
	data, _ := json.Marshal(encoded)
	return string(data), nil
}

func deserializeGroups(data string) ([][]byte, error) {
	if data == "" || data == "null" {
		return nil, nil
	}
	var encoded []string
	if err := json.Unmarshal([]byte(data), &encoded); err != nil {
		return nil, err
	}
	result := make([][]byte, len(encoded))
	for i, e := range encoded {
		result[i], _ = base64.StdEncoding.DecodeString(e)
	}
	return result, nil
}
