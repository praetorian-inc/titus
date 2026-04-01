# Design: Persist and display commit timestamps in explore TUI

## Overview

Persist full `CommitMetadata` (timestamps, author/committer info, message) from git enumeration into the SQLite datastore, and display the committer timestamp in the explore TUI details pane. Existing old datastores are not migrated — new columns only appear in newly created datastores.

## Requirements

1. New datastores include 7 additional columns in the `provenance` table for commit metadata
2. `AddProvenance` persists all `CommitMetadata` fields for git provenance
3. `GetAllProvenance` reads the new columns; falls back gracefully on old datastores where columns don't exist
4. The explore details pane displays the committer timestamp as a "Date:" line beneath the existing "Author:" line
5. No auto-migration of old datastores — `CREATE TABLE IF NOT EXISTS` handles new datastores; old ones keep their existing schema

## Schema change (`pkg/store/schema.go`)

Add 7 nullable columns to the `CREATE TABLE IF NOT EXISTS provenance` statement:

```sql
author_name TEXT,
author_email TEXT,
author_timestamp TEXT,
committer_name TEXT,
committer_email TEXT,
committer_timestamp TEXT,
commit_message TEXT
```

Timestamps stored as RFC 3339 strings (e.g., `2025-06-15T14:32:07Z`).

## Store write (`pkg/store/sqlite.go` — `AddProvenance`)

When inserting a `GitProvenance` with `Commit != nil`, persist all metadata fields alongside the existing `commit_hash`. The INSERT statement grows from 5 columns to 12.

## Store read (`pkg/store/sqlite.go` — `GetAllProvenance`)

Attempt a SELECT with all 11 columns (type, path, repo_path, commit_hash, author_name, author_email, author_timestamp, committer_name, committer_email, committer_timestamp, commit_message). If the query fails (old datastore without these columns), fall back to the original 4-column SELECT.

On successful read of the new columns, populate the full `CommitMetadata` struct including `AuthorTimestamp` and `CommitterTimestamp` (parsed from RFC 3339).

## Display

### Explore TUI (`pkg/explore/details.go`)

After the existing "Author:" line in the git provenance section, add:

```
Date:   2025-06-15 14:32:07
```

Uses `CommitterTimestamp.Format("2006-01-02 15:04:05")`. Only displayed when `CommitterTimestamp` is non-zero.

The existing "Author:" line will now also display correctly for new datastores (author name/email are currently always empty because they weren't persisted).

### Report command (`cmd/titus/report.go`)

In `outputReportHuman`, after the "File:" line for each match provenance, add a "Date:" line showing the committer timestamp. The report command uses `GetProvenance` which returns the first provenance — if it's a `GitProvenance` with a non-zero `CommitterTimestamp`, display it:

```
    File: path/to/file.yml
    Date: 2025-06-15 14:32:07
    Blob: abc123...
```

Only displayed when provenance is `GitProvenance` with a populated timestamp.

## Backward compatibility

- **Old datastores opened by new code:** `ALTER TABLE ADD COLUMN` migration adds the 7 new columns on open (errors ignored if columns already exist). Existing rows have NULL/empty values — no "Date:" line shown. New scans populate metadata for new blobs.
- **New datastores opened by old code:** Old code uses `SELECT type, path, repo_path, commit_hash` which still works — the extra columns are ignored.
- **Query fallback:** `GetAllProvenance` tries the full 11-column query first; falls back to the legacy 4-column query as a defensive safety net.

## Files changed

| File | Change |
|------|--------|
| `pkg/store/schema.go` | Add 7 columns to provenance CREATE TABLE |
| `pkg/store/sqlite.go` | Update `AddProvenance` to write all metadata; update `GetAllProvenance` with fallback query |
| `pkg/explore/details.go` | Add "Date:" line for committer timestamp |
| `cmd/titus/report.go` | Add "Date:" line for committer timestamp in human report output |
| `pkg/store/sqlite_test.go` | Test round-trip of commit metadata; test fallback on old schema |
