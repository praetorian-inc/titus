# pkg/store Implementation Report

**Date:** 2026-01-28
**Agent:** backend-developer
**Task:** Implement pkg/store package for Titus secrets scanner

## Summary

Successfully implemented the `pkg/store` package - a SQLite datastore for match persistence and deduplication, compatible with NoseyParker schema v70.

## Implementation Overview

### Architecture Decision

- **Database:** mattn/go-sqlite3 (cgo) for full schema v70 compatibility with NoseyParker
- **Pattern:** Repository pattern with interface-based design for extensibility
- **Testing:** TDD methodology with 75.6% test coverage

### Package Structure

```
pkg/store/
├── store.go           # Store interface and Config
├── store_test.go      # Interface and E2E tests
├── sqlite.go          # SQLite implementation
├── sqlite_test.go     # SQLite-specific tests
├── schema.go          # Database schema v70
└── schema_test.go     # Schema tests
```

## Files Implemented

### 1. store.go (Core Interface)

**Purpose:** Defines the Store interface and factory function

**Key Components:**
- `Store` interface with 8 methods
- `Config` struct for initialization
- `New()` factory function

**Interface Methods:**
- `AddBlob(id types.BlobID, size int64) error`
- `AddMatch(m *types.Match) error`
- `AddFinding(f *types.Finding) error`
- `AddProvenance(blobID types.BlobID, prov types.Provenance) error`
- `GetMatches(blobID types.BlobID) ([]*types.Match, error)`
- `GetFindings() ([]*types.Finding, error)`
- `FindingExists(structuralID string) (bool, error)`
- `Close() error`

### 2. schema.go (Database Schema)

**Purpose:** Creates NoseyParker-compatible schema v70

**Key Tables:**
- `schema_version` - Version tracking (v70)
- `blobs` - Blob metadata (id, size)
- `rules` - Rule definitions (id, name, pattern, structural_id)
- `matches` - Match records (blob_id, rule_id, location, groups, snippet)
- `findings` - Deduplicated findings (structural_id, rule_id, groups)
- `provenance` - Blob provenance (type, path, repo_path, commit_hash)

**Functions:**
- `CreateSchema(db *sql.DB) error` - Idempotent schema creation
- Helper functions for each table creation

**Schema Version:** 70 (compatible with NoseyParker)

### 3. sqlite.go (SQLite Implementation)

**Purpose:** Implements Store interface using SQLite

**Key Features:**
- Full Store interface implementation
- JSON serialization for groups
- Provenance type detection (File, Git, Extended)
- Deduplication via `INSERT OR IGNORE`
- Error context wrapping

**Constructor:**
- `NewSQLite(path string) (*SQLiteStore, error)`
- Supports `:memory:` for testing
- Auto-initializes schema

## Testing Strategy

### Test Coverage: 75.6%

**Test Files:**
- `schema_test.go` - 2 tests (schema creation, idempotency)
- `sqlite_test.go` - 9 tests (CRUD operations, provenance variants)
- `store_test.go` - 3 tests (interface compliance, E2E workflow)

**Total: 14 tests, all passing**

### TDD Methodology

Every implementation followed RED-GREEN-REFACTOR:
1. **RED:** Write failing test
2. **GREEN:** Implement minimal code to pass
3. **REFACTOR:** Clean up (minimal refactoring needed)

### Test Highlights

**Schema Tests:**
- ✅ Schema creation with version tracking
- ✅ Idempotent schema application

**SQLite Tests:**
- ✅ Memory database initialization
- ✅ Blob insertion and deduplication
- ✅ Match storage with JSON groups
- ✅ Finding deduplication
- ✅ Provenance for File and Git sources
- ✅ Existence checking
- ✅ Connection closing

**Integration Tests:**
- ✅ End-to-end workflow (blob → match → finding → provenance)
- ✅ Interface compliance verification

## Dependencies Added

```
github.com/mattn/go-sqlite3 v1.14.33
```

**Rationale:** Full SQLite3 support with JSON extensions, required for NoseyParker schema v70 compatibility.

## Verification

### Compilation

```bash
$ GOWORK=off go build ./pkg/store
# Success - no errors
```

### Test Results

```bash
$ GOWORK=off go test ./pkg/store -v -cover
PASS
coverage: 75.6% of statements
ok  	github.com/praetorian-inc/titus/pkg/store	0.550s
```

**Test Summary:**
- 14/14 tests passing
- 75.6% code coverage
- 0 compilation errors
- 0 test failures

## Design Decisions

### 1. Interface-Based Design

**Decision:** Store interface with SQLite implementation

**Rationale:**
- Extensibility for future backends (PostgreSQL, DuckDB)
- Easy mocking for tests
- Clear separation of concerns
- Follows Go best practices for dependency inversion

### 2. Constructor Returns Interface

**Decision:** `New(Config) Store` returns interface, not concrete type

**Rationale:**
- Consumer works with interface
- Easy to swap implementations
- Better testability
- Follows `go-best-practices` skill guidance

### 3. Embedded Queries (No queries.go)

**Decision:** SQL queries embedded in sqlite.go methods

**Rationale:**
- Simpler implementation (KISS principle)
- Queries are specific to SQLite implementation
- No need for abstraction with single backend
- Avoids premature extraction

### 4. JSON Serialization for Groups

**Decision:** Store regex groups as JSON in database

**Rationale:**
- Flexible storage for variable-length capture groups
- NoseyParker compatibility
- Easy deserialization
- Standard library support (no dependencies)

### 5. Error Context Wrapping

**Decision:** Wrap all database errors with context

**Rationale:**
- Better debugging (know which operation failed)
- Error chain preservation (`%w` formatting)
- Follows Go error handling best practices

## Usage Example

```go
package main

import (
    "github.com/praetorian-inc/titus/pkg/store"
    "github.com/praetorian-inc/titus/pkg/types"
)

func main() {
    // Create store
    st, err := store.New(store.Config{Path: "scan.db"})
    if err != nil {
        panic(err)
    }
    defer st.Close()

    // Add blob
    blobID := types.ComputeBlobID([]byte("content"))
    err = st.AddBlob(blobID, 7)

    // Add match
    match := &types.Match{
        BlobID:       blobID,
        StructuralID: "abc123",
        RuleID:       "np.aws.1",
        Location:     types.Location{...},
        Groups:       [][]byte{[]byte("AKIA...")},
    }
    err = st.AddMatch(match)

    // Check for duplicate findings
    exists, err := st.FindingExists("finding123")
    if !exists {
        finding := &types.Finding{
            ID:     "finding123",
            RuleID: "np.aws.1",
            Groups: [][]byte{[]byte("AKIA...")},
        }
        err = st.AddFinding(finding)
    }
}
```

## Integration Points

### Upstream Dependencies

- `github.com/praetorian-inc/titus/pkg/types` - Data structures
- `github.com/mattn/go-sqlite3` - SQLite driver
- `github.com/stretchr/testify` - Test assertions (mandatory)

### Downstream Consumers

Expected consumers:
- `pkg/scanner` - Scan orchestration
- `pkg/matcher` - Match detection
- `cmd/titus` - CLI commands (scan, report)

## Compliance Checklist

### Go Best Practices ✅

- [x] Function organization: Exported first, helpers last
- [x] Early returns to avoid nesting (max 2 levels)
- [x] Constructor returns interface (Store, not *SQLiteStore)
- [x] Clear error context wrapping
- [x] No useless comments (only non-obvious behavior)

### TDD Methodology ✅

- [x] Tests written before implementation
- [x] RED phase verified (tests failed)
- [x] GREEN phase verified (tests passed)
- [x] All tests passing
- [x] MANDATORY: testify assertions used throughout

### YAGNI Compliance ✅

- [x] No premature abstractions
- [x] No unused configuration options
- [x] No speculative features
- [x] Minimal viable implementation

### KISS Principle ✅

- [x] Queries embedded (no separate queries.go)
- [x] Single backend implementation
- [x] Standard library JSON (no extra deps)
- [x] Straightforward error handling

## Known Limitations

1. **Single Backend:** Only SQLite supported (by design)
2. **No Migration:** Schema is v70 only (future: add migration support)
3. **No Transactions:** Operations are auto-commit (future: batch API)
4. **No Indexes:** Basic schema only (future: add indexes for performance)

These limitations are intentional to keep initial implementation simple. They can be addressed when actual requirements emerge.

## Next Steps

Suggested follow-up tasks:
1. Add indexes for common query patterns (blob_id, structural_id)
2. Implement batch insert methods for performance
3. Add transaction support for multi-operation consistency
4. Create migration system for schema versioning

## Metadata

```json
{
  "agent": "backend-developer",
  "output_type": "implementation",
  "timestamp": "2026-01-28T00:00:00Z",
  "feature_directory": "/Users/engineer/tasks/integration-tests/praetorian-development-platform/titus",
  "skills_invoked": [
    "using-skills",
    "discovering-reusable-code",
    "calibrating-time-estimates",
    "enforcing-evidence-based-analysis",
    "gateway-backend",
    "persisting-agent-outputs",
    "developing-with-tdd",
    "verifying-before-completion"
  ],
  "library_skills_read": [
    ".claude/skill-library/development/backend/go-best-practices/SKILL.md",
    ".claude/skill-library/testing/backend/implementing-golang-tests/SKILL.md"
  ],
  "source_files_verified": [
    "pkg/types/blobid.go",
    "pkg/types/match.go",
    "pkg/types/finding.go",
    "pkg/types/provenance.go",
    "pkg/types/rule.go",
    "pkg/types/location.go",
    "pkg/types/snippet.go"
  ],
  "status": "complete",
  "files_created": [
    "pkg/store/store.go",
    "pkg/store/store_test.go",
    "pkg/store/sqlite.go",
    "pkg/store/sqlite_test.go",
    "pkg/store/schema.go",
    "pkg/store/schema_test.go"
  ],
  "test_coverage": "75.6%",
  "tests_passing": "14/14"
}
```
