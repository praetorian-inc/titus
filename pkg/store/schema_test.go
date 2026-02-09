//go:build !wasm && cgo

package store

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSchema(t *testing.T) {
	// Arrange
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	// Act
	err = CreateSchema(db)

	// Assert
	require.NoError(t, err)

	// Verify schema version table exists
	var version int
	err = db.QueryRow("SELECT version FROM schema_version LIMIT 1").Scan(&version)
	require.NoError(t, err)
	assert.Equal(t, SchemaVersion, version)

	// Verify all tables exist
	tables := []string{"blobs", "rules", "matches", "findings", "provenance"}
	for _, table := range tables {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count, "table %s should exist", table)
	}
}

func TestCreateSchema_Idempotent(t *testing.T) {
	// Arrange
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	// Act - create schema twice
	err = CreateSchema(db)
	require.NoError(t, err)

	err = CreateSchema(db)

	// Assert - should not error on second call
	assert.NoError(t, err)
}
