package store

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

// MergeConfig configures the merge operation.
type MergeConfig struct {
	// SourcePaths are the database files to merge from.
	SourcePaths []string
	// DestPath is the destination database file.
	DestPath string
}

// MergeStats tracks merge operation statistics.
type MergeStats struct {
	BlobsMerged      int
	MatchesMerged    int
	FindingsMerged   int
	ProvenanceMerged int
	SourcesProcessed int
}

// Merge combines multiple Titus databases into one.
// Deduplication is handled via INSERT OR IGNORE on primary keys.
func Merge(cfg MergeConfig) (*MergeStats, error) {
	if len(cfg.SourcePaths) == 0 {
		return nil, fmt.Errorf("no source databases specified")
	}
	if cfg.DestPath == "" {
		return nil, fmt.Errorf("destination path is required")
	}

	// Open/create destination database
	destDB, err := sql.Open("sqlite3", cfg.DestPath)
	if err != nil {
		return nil, fmt.Errorf("opening destination database: %w", err)
	}
	defer destDB.Close()

	// Initialize schema on destination
	if err := CreateSchema(destDB); err != nil {
		return nil, fmt.Errorf("creating schema: %w", err)
	}

	stats := &MergeStats{}

	// Process each source database
	for _, sourcePath := range cfg.SourcePaths {
		sourceStats, err := mergeFrom(destDB, sourcePath)
		if err != nil {
			return stats, fmt.Errorf("merging from %s: %w", sourcePath, err)
		}
		stats.BlobsMerged += sourceStats.BlobsMerged
		stats.MatchesMerged += sourceStats.MatchesMerged
		stats.FindingsMerged += sourceStats.FindingsMerged
		stats.ProvenanceMerged += sourceStats.ProvenanceMerged
		stats.SourcesProcessed++
	}

	return stats, nil
}

// mergeFrom copies data from a source database to the destination.
func mergeFrom(destDB *sql.DB, sourcePath string) (*MergeStats, error) {
	// Open source database
	sourceDB, err := sql.Open("sqlite3", sourcePath)
	if err != nil {
		return nil, fmt.Errorf("opening source database: %w", err)
	}
	defer sourceDB.Close()

	stats := &MergeStats{}

	// Start transaction for efficiency
	tx, err := destDB.Begin()
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %w", err)
	}
	defer tx.Rollback()

	// Merge blobs
	blobCount, err := mergeBlobs(tx, sourceDB)
	if err != nil {
		return nil, fmt.Errorf("merging blobs: %w", err)
	}
	stats.BlobsMerged = blobCount

	// Merge matches
	matchCount, err := mergeMatches(tx, sourceDB)
	if err != nil {
		return nil, fmt.Errorf("merging matches: %w", err)
	}
	stats.MatchesMerged = matchCount

	// Merge findings
	findingCount, err := mergeFindings(tx, sourceDB)
	if err != nil {
		return nil, fmt.Errorf("merging findings: %w", err)
	}
	stats.FindingsMerged = findingCount

	// Merge provenance
	provCount, err := mergeProvenance(tx, sourceDB)
	if err != nil {
		return nil, fmt.Errorf("merging provenance: %w", err)
	}
	stats.ProvenanceMerged = provCount

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}

	return stats, nil
}

func mergeBlobs(tx *sql.Tx, sourceDB *sql.DB) (int, error) {
	rows, err := sourceDB.Query("SELECT id, size FROM blobs")
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO blobs (id, size) VALUES (?, ?)")
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for rows.Next() {
		var id string
		var size int64
		if err := rows.Scan(&id, &size); err != nil {
			return count, err
		}
		result, err := stmt.Exec(id, size)
		if err != nil {
			return count, err
		}
		affected, _ := result.RowsAffected()
		if affected > 0 {
			count++
		}
	}
	return count, rows.Err()
}

func mergeMatches(tx *sql.Tx, sourceDB *sql.DB) (int, error) {
	rows, err := sourceDB.Query(`
		SELECT blob_id, rule_id, structural_id, offset_start, offset_end,
		       snippet_before, snippet_matching, snippet_after, groups_json
		FROM matches
	`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO matches
		(blob_id, rule_id, structural_id, offset_start, offset_end,
		 snippet_before, snippet_matching, snippet_after, groups_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for rows.Next() {
		var blobID, ruleID, structuralID string
		var offsetStart, offsetEnd int64
		var snippetBefore, snippetMatching, snippetAfter []byte
		var groupsJSON string

		if err := rows.Scan(&blobID, &ruleID, &structuralID, &offsetStart, &offsetEnd,
			&snippetBefore, &snippetMatching, &snippetAfter, &groupsJSON); err != nil {
			return count, err
		}
		result, err := stmt.Exec(blobID, ruleID, structuralID, offsetStart, offsetEnd,
			snippetBefore, snippetMatching, snippetAfter, groupsJSON)
		if err != nil {
			return count, err
		}
		affected, _ := result.RowsAffected()
		if affected > 0 {
			count++
		}
	}
	return count, rows.Err()
}

func mergeFindings(tx *sql.Tx, sourceDB *sql.DB) (int, error) {
	rows, err := sourceDB.Query("SELECT structural_id, rule_id, groups_json FROM findings")
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO findings (structural_id, rule_id, groups_json) VALUES (?, ?, ?)")
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for rows.Next() {
		var structuralID, ruleID, groupsJSON string
		if err := rows.Scan(&structuralID, &ruleID, &groupsJSON); err != nil {
			return count, err
		}
		result, err := stmt.Exec(structuralID, ruleID, groupsJSON)
		if err != nil {
			return count, err
		}
		affected, _ := result.RowsAffected()
		if affected > 0 {
			count++
		}
	}
	return count, rows.Err()
}

func mergeProvenance(tx *sql.Tx, sourceDB *sql.DB) (int, error) {
	rows, err := sourceDB.Query("SELECT blob_id, type, path, repo_path, commit_hash FROM provenance")
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO provenance (blob_id, type, path, repo_path, commit_hash)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for rows.Next() {
		var blobID, provType string
		var path, repoPath, commitHash *string
		if err := rows.Scan(&blobID, &provType, &path, &repoPath, &commitHash); err != nil {
			return count, err
		}
		result, err := stmt.Exec(blobID, provType, path, repoPath, commitHash)
		if err != nil {
			return count, err
		}
		affected, _ := result.RowsAffected()
		if affected > 0 {
			count++
		}
	}
	return count, rows.Err()
}
