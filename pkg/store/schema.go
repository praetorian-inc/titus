package store

import (
	"database/sql"
	"fmt"
)

// SchemaVersion is the current database schema version (compatible with NoseyParker v70).
const SchemaVersion = 70

// CreateSchema creates the database schema if it doesn't exist.
// This matches NoseyParker's schema v70 for compatibility.
func CreateSchema(db *sql.DB) error {
	// Create schema_version table
	if err := createSchemaVersionTable(db); err != nil {
		return fmt.Errorf("creating schema_version table: %w", err)
	}

	// Create main tables
	if err := createBlobsTable(db); err != nil {
		return fmt.Errorf("creating blobs table: %w", err)
	}

	if err := createRulesTable(db); err != nil {
		return fmt.Errorf("creating rules table: %w", err)
	}

	if err := createMatchesTable(db); err != nil {
		return fmt.Errorf("creating matches table: %w", err)
	}

	if err := createFindingsTable(db); err != nil {
		return fmt.Errorf("creating findings table: %w", err)
	}

	if err := createProvenanceTable(db); err != nil {
		return fmt.Errorf("creating provenance table: %w", err)
	}

	return nil
}

func createSchemaVersionTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	// Insert version if table is empty
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM schema_version").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		_, err = db.Exec("INSERT INTO schema_version (version) VALUES (?)", SchemaVersion)
		return err
	}

	return nil
}

func createBlobsTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS blobs (
			id TEXT PRIMARY KEY NOT NULL,
			size INTEGER NOT NULL
		)
	`)
	return err
}

func createRulesTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS rules (
			id TEXT PRIMARY KEY NOT NULL,
			name TEXT NOT NULL,
			pattern TEXT NOT NULL,
			structural_id TEXT NOT NULL
		)
	`)
	return err
}

func createMatchesTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS matches (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			blob_id TEXT NOT NULL REFERENCES blobs(id),
			rule_id TEXT NOT NULL REFERENCES rules(id),
			structural_id TEXT NOT NULL UNIQUE,
			offset_start INTEGER NOT NULL,
			offset_end INTEGER NOT NULL,
			snippet_before BLOB,
			snippet_matching BLOB,
			snippet_after BLOB,
			groups_json TEXT,
			validation_status TEXT,
			validation_confidence REAL,
			validation_message TEXT,
			validation_timestamp TEXT,
			finding_id INTEGER,
			start_line INTEGER,
			start_column INTEGER,
			end_line INTEGER,
			end_column INTEGER
		)
	`)
	return err
}

func createFindingsTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			structural_id TEXT NOT NULL UNIQUE,
			rule_id TEXT NOT NULL,
			groups_json TEXT
		)
	`)
	return err
}

func createProvenanceTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS provenance (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			blob_id TEXT NOT NULL REFERENCES blobs(id),
			type TEXT NOT NULL,
			path TEXT,
			repo_path TEXT,
			commit_hash TEXT,
			UNIQUE(blob_id, type, path, repo_path, commit_hash)
		)
	`)
	if err != nil {
		return err
	}

	// Create index for efficient provenance lookup by blob_id
	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_provenance_blob_id ON provenance(blob_id)
	`)
	return err
}
