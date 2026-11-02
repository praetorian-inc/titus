//go:build !wasm

package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLite_SchemaWithLocationColumns(t *testing.T) {
	// Arrange
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	store, err := NewSQLite(dbPath)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	blobID := types.ComputeBlobID([]byte("test content"))
	err = store.AddBlob(blobID, 12)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:           "np.test.1",
		Name:         "Test Rule",
		Pattern:      "test",
		StructuralID: "struct123",
	}
	err = store.AddRule(rule)
	require.NoError(t, err)

	// Create match with location data
	match := &types.Match{
		BlobID:       blobID,
		StructuralID: "match123",
		RuleID:       "np.test.1",
		RuleName:     "Test Rule",
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 10, End: 20},
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 5, Column: 3},
				End:   types.SourcePoint{Line: 7, Column: 15},
			},
		},
		Snippet: types.Snippet{Matching: []byte("test match")},
	}

	// Act - Add match
	err = store.AddMatch(match)
	require.NoError(t, err)

	// Retrieve match
	matches, err := store.GetMatches(blobID)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	// Assert - Verify location data persisted correctly
	retrieved := matches[0]
	assert.Equal(t, int64(10), retrieved.Location.Offset.Start)
	assert.Equal(t, int64(20), retrieved.Location.Offset.End)
	assert.Equal(t, 5, retrieved.Location.Source.Start.Line)
	assert.Equal(t, 3, retrieved.Location.Source.Start.Column)
	assert.Equal(t, 7, retrieved.Location.Source.End.Line)
	assert.Equal(t, 15, retrieved.Location.Source.End.Column)
}

func TestSQLite_GetAllMatchesWithLocation(t *testing.T) {
	// Arrange
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	store, err := NewSQLite(dbPath)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	blobID1 := types.ComputeBlobID([]byte("content1"))
	blobID2 := types.ComputeBlobID([]byte("content2"))

	err = store.AddBlob(blobID1, 8)
	require.NoError(t, err)
	err = store.AddBlob(blobID2, 8)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:           "np.test.1",
		Name:         "Test Rule",
		Pattern:      "test",
		StructuralID: "struct123",
	}
	err = store.AddRule(rule)
	require.NoError(t, err)

	match1 := &types.Match{
		BlobID:       blobID1,
		StructuralID: "match1",
		RuleID:       "np.test.1",
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 0, End: 5},
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 1, Column: 1},
				End:   types.SourcePoint{Line: 1, Column: 6},
			},
		},
	}

	match2 := &types.Match{
		BlobID:       blobID2,
		StructuralID: "match2",
		RuleID:       "np.test.1",
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 10, End: 15},
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 2, Column: 5},
				End:   types.SourcePoint{Line: 3, Column: 1},
			},
		},
	}

	err = store.AddMatch(match1)
	require.NoError(t, err)
	err = store.AddMatch(match2)
	require.NoError(t, err)

	// Act
	allMatches, err := store.GetAllMatches()

	// Assert
	require.NoError(t, err)
	require.Len(t, allMatches, 2)

	// Verify both matches have location data
	for _, m := range allMatches {
		assert.NotZero(t, m.Location.Source.Start.Line, "Start line should be populated")
		assert.NotZero(t, m.Location.Source.Start.Column, "Start column should be populated")
		assert.NotZero(t, m.Location.Source.End.Line, "End line should be populated")
		assert.NotZero(t, m.Location.Source.End.Column, "End column should be populated")
	}
}

func TestSQLite_GetMatchesRuleName(t *testing.T) {
	// Arrange
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	store, err := NewSQLite(dbPath)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	blobID := types.ComputeBlobID([]byte("test content"))
	err = store.AddBlob(blobID, 12)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:           "np.test.1",
		Name:         "Test Rule",
		Pattern:      "test",
		StructuralID: "struct123",
	}
	err = store.AddRule(rule)
	require.NoError(t, err)

	// Create match without RuleName — the store should populate it
	match := &types.Match{
		BlobID:       blobID,
		StructuralID: "match123",
		RuleID:       "np.test.1",
		Location:     types.Location{Offset: types.OffsetSpan{Start: 0, End: 10}},
		Snippet:      types.Snippet{Matching: []byte("test")},
	}

	err = store.AddMatch(match)
	require.NoError(t, err)

	// Act
	matches, err := store.GetMatches(blobID)

	// Assert
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, "Test Rule", matches[0].RuleName)
}

func TestSQLite_GetAllMatchesRuleName(t *testing.T) {
	// Arrange
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	store, err := NewSQLite(dbPath)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	blobID1 := types.ComputeBlobID([]byte("content1"))
	blobID2 := types.ComputeBlobID([]byte("content2"))

	err = store.AddBlob(blobID1, 8)
	require.NoError(t, err)
	err = store.AddBlob(blobID2, 8)
	require.NoError(t, err)

	rule1 := &types.Rule{
		ID:           "np.test.1",
		Name:         "Test Rule 1",
		Pattern:      "test1",
		StructuralID: "struct123",
	}
	rule2 := &types.Rule{
		ID:           "np.test.2",
		Name:         "Test Rule 2",
		Pattern:      "test2",
		StructuralID: "struct456",
	}
	err = store.AddRule(rule1)
	require.NoError(t, err)
	err = store.AddRule(rule2)
	require.NoError(t, err)

	// Create matches without RuleName — the store should populate it
	match1 := &types.Match{
		BlobID:       blobID1,
		StructuralID: "match1",
		RuleID:       "np.test.1",
		Location:     types.Location{Offset: types.OffsetSpan{Start: 0, End: 5}},
	}
	match2 := &types.Match{
		BlobID:       blobID2,
		StructuralID: "match2",
		RuleID:       "np.test.2",
		Location:     types.Location{Offset: types.OffsetSpan{Start: 0, End: 5}},
	}

	err = store.AddMatch(match1)
	require.NoError(t, err)
	err = store.AddMatch(match2)
	require.NoError(t, err)

	// Act
	allMatches, err := store.GetAllMatches()

	// Assert
	require.NoError(t, err)
	require.Len(t, allMatches, 2)

	ruleNames := make(map[string]string)
	for _, m := range allMatches {
		ruleNames[m.RuleID] = m.RuleName
	}
	assert.Equal(t, "Test Rule 1", ruleNames["np.test.1"])
	assert.Equal(t, "Test Rule 2", ruleNames["np.test.2"])
}

func TestSQLite_NullLocationValues(t *testing.T) {
	// Test that matches without location data (finding_id and line/column nulls) work correctly
	// This ensures backward compatibility

	// Arrange
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	store, err := NewSQLite(dbPath)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	blobID := types.ComputeBlobID([]byte("test content"))
	err = store.AddBlob(blobID, 12)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:           "np.test.1",
		Name:         "Test Rule",
		Pattern:      "test",
		StructuralID: "struct123",
	}
	err = store.AddRule(rule)
	require.NoError(t, err)

	// Create match WITHOUT location source data (only offsets)
	match := &types.Match{
		BlobID:       blobID,
		StructuralID: "match_no_location",
		RuleID:       "np.test.1",
		RuleName:     "Test Rule",
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 0, End: 10},
			Source: types.SourceSpan{}, // Zero values - no line/column data
		},
		Snippet: types.Snippet{Matching: []byte("test")},
	}

	// Act
	err = store.AddMatch(match)
	require.NoError(t, err)

	// Retrieve
	matches, err := store.GetMatches(blobID)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	// Assert - Zero values should be preserved
	retrieved := matches[0]
	assert.Equal(t, 0, retrieved.Location.Source.Start.Line)
	assert.Equal(t, 0, retrieved.Location.Source.Start.Column)
	assert.Equal(t, 0, retrieved.Location.Source.End.Line)
	assert.Equal(t, 0, retrieved.Location.Source.End.Column)
}

func TestSQLite_ProvenanceWithCommitMetadata(t *testing.T) {
	dir := t.TempDir()
	store, err := New(Config{Path: filepath.Join(dir, "test.db")})
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	blobID := types.ComputeBlobID([]byte("secret content"))
	err = store.AddBlob(blobID, 14)
	require.NoError(t, err)

	authorTS := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	committerTS := time.Date(2024, 3, 15, 11, 0, 0, 0, time.UTC)

	prov := types.GitProvenance{
		RepoPath: "/tmp/repo",
		BlobPath: "config.yml",
		Commit: &types.CommitMetadata{
			CommitID:           "abc123def456",
			AuthorName:         "John Doe",
			AuthorEmail:        "john@example.com",
			AuthorTimestamp:    authorTS,
			CommitterName:      "Jane Smith",
			CommitterEmail:     "jane@example.com",
			CommitterTimestamp: committerTS,
			Message:            "add config",
		},
	}

	err = store.AddProvenance(blobID, prov)
	require.NoError(t, err)

	provs, err := store.GetAllProvenance(blobID)
	require.NoError(t, err)
	require.Len(t, provs, 1)

	got, ok := provs[0].(types.GitProvenance)
	require.True(t, ok)
	assert.Equal(t, "/tmp/repo", got.RepoPath)
	assert.Equal(t, "config.yml", got.BlobPath)
	require.NotNil(t, got.Commit)
	assert.Equal(t, "abc123def456", got.Commit.CommitID)
	assert.Equal(t, "John Doe", got.Commit.AuthorName)
	assert.Equal(t, "john@example.com", got.Commit.AuthorEmail)
	assert.Equal(t, authorTS, got.Commit.AuthorTimestamp)
	assert.Equal(t, "Jane Smith", got.Commit.CommitterName)
	assert.Equal(t, "jane@example.com", got.Commit.CommitterEmail)
	assert.Equal(t, committerTS, got.Commit.CommitterTimestamp)
	assert.Equal(t, "add config", got.Commit.Message)
}

func TestSQLite_ArchiveProvenance(t *testing.T) {
	dir := t.TempDir()
	store, err := New(Config{Path: filepath.Join(dir, "test.db")})
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	blobID := types.ComputeBlobID([]byte("extracted secret content"))
	err = store.AddBlob(blobID, 24)
	require.NoError(t, err)

	prov := types.ArchiveProvenance{
		ArchivePath: "docker://example/app:latest/layer.tar:config.zip",
		MemberPath:  "config/secrets.yml",
	}
	err = store.AddProvenance(blobID, prov)
	require.NoError(t, err)

	provs, err := store.GetAllProvenance(blobID)
	require.NoError(t, err)
	require.Len(t, provs, 1)

	got, ok := provs[0].(types.ArchiveProvenance)
	require.True(t, ok)
	assert.Equal(t, prov.ArchivePath, got.ArchivePath)
	assert.Equal(t, prov.MemberPath, got.MemberPath)
	assert.Equal(t, "docker://example/app:latest/layer.tar:config.zip:config/secrets.yml", got.Path())
}

func TestSQLiteStore_AddFinding_PersistsScore(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := NewSQLite(filepath.Join(tmpDir, "test.db"))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	finding := &types.Finding{
		ID:     "abc",
		RuleID: "np.aws.1",
		Groups: [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")},
		Score: &types.Score{
			Final:             85,
			Base:              60,
			SuggestedSeverity: "critical",
			Applied:           []types.ScoreModifier{},
		},
	}
	require.NoError(t, s.AddFinding(finding))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	require.Len(t, findings, 1)

	got := findings[0]
	require.NotNil(t, got.Score, "expected Score to be non-nil after round-trip")
	assert.Equal(t, 85, got.Score.Final)
	assert.Equal(t, 60, got.Score.Base)
	assert.Equal(t, "critical", got.Score.SuggestedSeverity)
	assert.NotNil(t, got.Score.Applied, "Score.Applied must be non-nil (empty slice)")
}

func TestSQLiteStore_AddFinding_NilScoreAllowed(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := NewSQLite(filepath.Join(tmpDir, "test.db"))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	finding := &types.Finding{
		ID:     "xyz",
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("x")},
		// Score is nil
	}
	require.NoError(t, s.AddFinding(finding), "AddFinding with nil Score should not error")

	findings, err := s.GetFindings()
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Nil(t, findings[0].Score, "expected Score to stay nil after round-trip")
}

func TestSQLiteStore_AddFinding_PersistsOwner(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := NewSQLite(filepath.Join(tmpDir, "test.db"))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	finding := &types.Finding{
		ID:     "owner-test",
		RuleID: "np.aws.6",
		Groups: [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")},
		Owner: &types.OwnerInfo{
			Service:   "aws",
			User:      "alice",
			AccountID: "123456789012",
			ARN:       "arn:aws:iam::123456789012:user/alice",
		},
	}
	require.NoError(t, s.AddFinding(finding))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.NotNil(t, findings[0].Owner)
	assert.Equal(t, "aws", findings[0].Owner.Service)
	assert.Equal(t, "alice", findings[0].Owner.User)
	assert.Equal(t, "123456789012", findings[0].Owner.AccountID)
	assert.Equal(t, "arn:aws:iam::123456789012:user/alice", findings[0].Owner.ARN)
}

func TestSQLiteStore_AddFinding_NilOwnerAllowed(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := NewSQLite(filepath.Join(tmpDir, "test.db"))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	finding := &types.Finding{
		ID:     "no-owner",
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("x")},
	}
	require.NoError(t, s.AddFinding(finding))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Nil(t, findings[0].Owner)
}

func TestSQLiteStore_AddFinding_PersistsResources(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := NewSQLite(filepath.Join(tmpDir, "test.db"))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	finding := &types.Finding{
		ID:     "resources-test",
		RuleID: "np.aws.6",
		Groups: [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")},
		Resources: []types.ResourceInfo{
			{Service: "aws", Type: "s3_bucket", Name: "prod-data"},
			{Service: "aws", Type: "secret", Name: "db-password"},
		},
	}
	require.NoError(t, s.AddFinding(finding))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Len(t, findings[0].Resources, 2)
	assert.Equal(t, "s3_bucket", findings[0].Resources[0].Type)
	assert.Equal(t, "prod-data", findings[0].Resources[0].Name)
	assert.Equal(t, "secret", findings[0].Resources[1].Type)
	assert.Equal(t, "db-password", findings[0].Resources[1].Name)
}

func TestSQLiteStore_AddFinding_NilResourcesAllowed(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := NewSQLite(filepath.Join(tmpDir, "test.db"))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	finding := &types.Finding{
		ID:     "no-resources",
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("x")},
	}
	require.NoError(t, s.AddFinding(finding))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Nil(t, findings[0].Resources)
}

func gitOcc(repo, path string, c *types.CommitMetadata) types.Occurrence {
	o := types.Occurrence{Kind: "git", Repository: repo, Path: path, HostRecorded: true}
	if c != nil {
		o.Commit, o.CommitDate = c.CommitID, c.CommitterTimestamp
	}
	return o
}

// legacySchema4059973 is the DDL a titus binary at 4059973 (before ENG-9178)
// writes: there is no blob_locations table.
var legacySchema4059973 = []string{
	`CREATE TABLE schema_version (version INTEGER NOT NULL)`,
	`INSERT INTO schema_version (version) VALUES (70)`,
	`CREATE TABLE blobs (id TEXT PRIMARY KEY NOT NULL, size INTEGER NOT NULL)`,
	`CREATE TABLE rules (id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, pattern TEXT NOT NULL, structural_id TEXT NOT NULL)`,
	`CREATE TABLE matches (id INTEGER PRIMARY KEY AUTOINCREMENT, blob_id TEXT NOT NULL REFERENCES blobs(id), rule_id TEXT NOT NULL REFERENCES rules(id), structural_id TEXT NOT NULL UNIQUE, offset_start INTEGER NOT NULL, offset_end INTEGER NOT NULL, snippet_before BLOB, snippet_matching BLOB, snippet_after BLOB, groups_json TEXT, validation_status TEXT, validation_confidence REAL, validation_message TEXT, validation_timestamp TEXT, finding_id INTEGER, start_line INTEGER, start_column INTEGER, end_line INTEGER, end_column INTEGER)`,
	`CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, structural_id TEXT NOT NULL UNIQUE, rule_id TEXT NOT NULL, groups_json TEXT, score_final INTEGER, score_base INTEGER, score_suggested_severity TEXT, score_applied_json TEXT, owner_json TEXT, resources_json TEXT)`,
	`CREATE TABLE provenance (id INTEGER PRIMARY KEY AUTOINCREMENT, blob_id TEXT NOT NULL REFERENCES blobs(id), type TEXT NOT NULL, path TEXT, repo_path TEXT, commit_hash TEXT, author_name TEXT, author_email TEXT, author_timestamp TEXT, committer_name TEXT, committer_email TEXT, committer_timestamp TEXT, commit_message TEXT, UNIQUE(blob_id, type, path, repo_path, commit_hash))`,
	`CREATE INDEX idx_provenance_blob_id ON provenance(blob_id)`,
	`CREATE TABLE annotations (id INTEGER PRIMARY KEY AUTOINCREMENT, target_type TEXT NOT NULL, target_id TEXT NOT NULL, status TEXT, comment TEXT, updated_at TEXT NOT NULL, UNIQUE(target_type, target_id))`,
}

func writeLegacyDatastore(t *testing.T, path string, blob types.BlobID) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	for _, stmt := range legacySchema4059973 {
		_, err := db.Exec(stmt)
		require.NoError(t, err)
	}
	_, err = db.Exec(`INSERT INTO blobs (id, size) VALUES (?, ?)`, blob.Hex(), 6)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO provenance (blob_id, type, path, repo_path, commit_hash, committer_timestamp) VALUES (?, 'git', 'config.yml', 'acme/api', ?, ?)`,
		blob.Hex(), commitA.CommitID, commitA.CommitterTimestamp.Format(time.RFC3339))
	require.NoError(t, err)
}

func TestSQLite_OpensPreChangeDatastore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	blob := types.ComputeBlobID([]byte("secret"))
	writeLegacyDatastore(t, path, blob)
	legacy := types.Occurrence{Kind: "git", Repository: "acme/api", Path: "config.yml", Commit: commitA.CommitID, CommitDate: commitA.CommitterTimestamp, HostRecorded: false}

	// Open twice: CreateSchema must be idempotent on an old datastore (SEC-16).
	for range 2 {
		s, err := NewSQLite(path)
		require.NoError(t, err)

		// C-OLDDS-1: the legacy row shows, host not recorded, no reset needed.
		got, err := s.GetOccurrences(blob)
		require.NoError(t, err)
		assert.Equal(t, []types.Occurrence{legacy}, got)
		require.NoError(t, s.Close())
	}

	s, err := NewSQLite(path)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	var version int
	require.NoError(t, s.db.QueryRow(`SELECT version FROM schema_version`).Scan(&version))
	assert.Equal(t, 70, version)
	assert.Equal(t, 70, SchemaVersion)

	// C-OLDDS-2: a rescan into the old datastore shows both identities.
	fresh := gitOcc("github.com/acme/api", "config.yml", commitA)
	require.NoError(t, s.AddProvenance(blob, types.GitProvenance{RepoPath: "github.com/acme/api", BlobPath: "config.yml", Commit: commitA}))
	require.NoError(t, s.AddOccurrences(blob, []types.Occurrence{fresh}))
	got, err := s.GetOccurrences(blob)
	require.NoError(t, err)
	assert.Equal(t, []types.Occurrence{legacy, fresh}, got)

	var fkViolations int
	require.NoError(t, s.db.QueryRow(`SELECT COUNT(*) FROM pragma_foreign_key_check`).Scan(&fkViolations))
	assert.Zero(t, fkViolations)
	var integrity string
	require.NoError(t, s.db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity))
	assert.Equal(t, "ok", integrity)
}

func TestSQLite_BlobLocationsSchema(t *testing.T) {
	s, err := NewSQLite(filepath.Join(t.TempDir(), "ds.db"))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	rows, err := s.db.Query(`SELECT name, "notnull" FROM pragma_table_info('blob_locations')`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	notNull := map[string]bool{}
	for rows.Next() {
		var name string
		var nn bool
		require.NoError(t, rows.Scan(&name, &nn))
		notNull[name] = nn
	}
	require.NoError(t, rows.Err())

	// Every UNIQUE column is NOT NULL, so the key is total (SEC-16).
	for _, name := range []string{"blob_id", "kind", "repository", "path", "absolute_path", "commit_hash", "working_tree", "commit_ts"} {
		nn, ok := notNull[name]
		require.True(t, ok, "missing column %s", name)
		assert.True(t, nn, "column %s must be NOT NULL", name)
	}

	var idx int
	require.NoError(t, s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_blob_locations_blob_id'`).Scan(&idx))
	assert.Equal(t, 1, idx)
}

func TestSQLite_HostilePathLeavesFindingsTable(t *testing.T) {
	s, err := NewSQLite(filepath.Join(t.TempDir(), "ds.db"))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	blob := types.ComputeBlobID([]byte("secret"))
	require.NoError(t, s.AddBlob(blob, 6))

	require.NoError(t, s.AddOccurrences(blob, []types.Occurrence{gitOcc("r", "x'); DROP TABLE findings;--", nil)}))

	var n int
	require.NoError(t, s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'findings'`).Scan(&n))
	assert.Equal(t, 1, n)
}

// A datastore written before the column existed (writeLegacyDatastore) opens,
// reads the flag as false with its commit metadata intact, and can then be
// marked truncated by a rescan.
func TestSQLite_LegacyDatastoreLocationsTruncated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	blob := types.ComputeBlobID([]byte("secret"))
	writeLegacyDatastore(t, path, blob)

	s, err := NewSQLite(path)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	provs, err := s.GetAllProvenance(blob)
	require.NoError(t, err)
	require.Len(t, provs, 1)
	g := provs[0].(types.GitProvenance)
	assert.False(t, g.LocationsTruncated)
	require.NotNil(t, g.Commit)
	assert.Equal(t, commitA.CommitterTimestamp, g.Commit.CommitterTimestamp, "full query, not the legacy fallback")

	g.LocationsTruncated = true
	require.NoError(t, s.AddProvenance(blob, g))
	assert.Equal(t, map[string]bool{"config.yml": true}, truncByPath(t, s, blob))
}

// locationsTruncatedColumn reads the declared NOT NULL flag and default of
// provenance.locations_truncated.
func locationsTruncatedColumn(t *testing.T, s *SQLiteStore) (notNull bool, dflt sql.NullString) {
	t.Helper()
	require.NoError(t, s.db.QueryRow(
		`SELECT "notnull", dflt_value FROM pragma_table_info('provenance') WHERE name = 'locations_truncated'`,
	).Scan(&notNull, &dflt), "locations_truncated column missing")
	return notNull, dflt
}

// SEC-16: opening a pre-ENG-9178 datastore adds locations_truncated as
// NOT NULL DEFAULT 0, so the old row reads 0 (not NULL) and false; a second
// open is a no-op.
func TestSQLite_LegacyDatastoreLocationsTruncatedColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	blob := types.ComputeBlobID([]byte("secret"))
	writeLegacyDatastore(t, path, blob)

	for open := range 2 {
		s, err := NewSQLite(path)
		require.NoError(t, err, "open %d", open)

		notNull, dflt := locationsTruncatedColumn(t, s)
		assert.True(t, notNull, "open %d: locations_truncated must be NOT NULL", open)
		assert.Equal(t, sql.NullString{String: "0", Valid: true}, dflt, "open %d: locations_truncated default", open)

		var raw sql.NullInt64
		require.NoError(t, s.db.QueryRow(`SELECT locations_truncated FROM provenance WHERE blob_id = ?`, blob.Hex()).Scan(&raw))
		assert.Equal(t, sql.NullInt64{Int64: 0, Valid: true}, raw, "open %d: legacy row value", open)

		provs, err := s.GetAllProvenance(blob)
		require.NoError(t, err)
		require.Len(t, provs, 1)
		g, ok := provs[0].(types.GitProvenance)
		require.True(t, ok)
		assert.False(t, g.LocationsTruncated)
		assert.Equal(t, "config.yml", g.BlobPath)

		require.NoError(t, s.Close())
	}
}

// SEC-16: a fresh datastore declares the same NOT NULL DEFAULT 0 column.
func TestSQLite_FreshDatastoreLocationsTruncatedColumn(t *testing.T) {
	s, err := NewSQLite(filepath.Join(t.TempDir(), "ds.db"))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	notNull, dflt := locationsTruncatedColumn(t, s)
	assert.True(t, notNull)
	assert.Equal(t, sql.NullString{String: "0", Valid: true}, dflt)
}
