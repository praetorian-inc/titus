//go:build !wasm

package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestFindingsTable_HasScoreColumns(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if err := CreateSchema(db); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}

	rows, err := db.Query("PRAGMA table_info(findings)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()

	got := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		got[name] = true
	}
	required := []string{"score_final", "score_base", "score_suggested_severity", "score_applied_json"}
	for _, col := range required {
		if !got[col] {
			t.Errorf("findings table missing column %q", col)
		}
	}
}

func TestFindingsTable_MigratesOldSchema(t *testing.T) {
	// Simulate an old-format datastore by creating the findings table without score columns
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Create old-format findings table
	_, err = db.Exec(`CREATE TABLE findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        structural_id TEXT NOT NULL UNIQUE,
        rule_id TEXT NOT NULL,
        groups_json TEXT
    )`)
	if err != nil {
		t.Fatal(err)
	}
	// Insert a row to verify it survives migration
	_, err = db.Exec(`INSERT INTO findings (structural_id, rule_id, groups_json) VALUES ('abc', 'np.test.1', '[]')`)
	if err != nil {
		t.Fatal(err)
	}

	// Now run CreateSchema — should ADD COLUMN for the missing score columns without losing data
	if err := CreateSchema(db); err != nil {
		t.Fatalf("CreateSchema on old schema: %v", err)
	}

	// Verify row still exists
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM findings").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 row after migration, got %d", count)
	}

	// Verify new columns exist and are nullable
	var scoreFinal sql.NullInt64
	if err := db.QueryRow("SELECT score_final FROM findings WHERE structural_id = 'abc'").Scan(&scoreFinal); err != nil {
		t.Fatalf("SELECT score_final: %v", err)
	}
	if scoreFinal.Valid {
		t.Errorf("expected score_final to be NULL for migrated row, got %d", scoreFinal.Int64)
	}
}
