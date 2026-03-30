# Design: `titus report summary`

## Overview

Add a `summary` subcommand to `titus report` that displays an aggregated overview of all secrets found in a scan datastore. Shows total counts and a per-rule-type breakdown with finding and match counts, sorted by finding count descending.

## Command

```
titus report summary [--datastore titus.ds] [--format human|json] [--color auto|always|never]
```

- `--datastore`: Path to datastore directory or file (inherited from parent `report` command, default `titus.ds`)
- `--format`: Output format, `human` (default) or `json`
- `--color`: Color output, `auto` (default), `always`, or `never` (inherited from parent)

## Requirements

1. `titus report summary` outputs a total findings/matches header line followed by a per-rule-type table
2. Per-rule rows show rule name, finding count (unique secrets), and match count (total occurrences)
3. Rows are sorted by finding count descending
4. Supports `--format human` (table) and `--format json` (structured object)
5. Inherits `--datastore` and `--color` flags from the parent `report` command
6. Human output uses the same table style as `outputNoseyParkerSummary` in `scan.go` for visual consistency

## Data Flow

1. Open the datastore (same store-opening logic as `runReport`)
2. Call `s.GetFindings()` and `s.GetAllMatches()`
3. Load builtin rules via `rule.NewLoader().LoadBuiltinRules()` for name resolution and finding ID computation
4. Use existing `buildFindingMatchMap()` to associate matches to findings
5. Aggregate: for each `RuleID`, count unique findings and total matches. If a rule ID doesn't resolve to a builtin rule, use the raw `RuleID` as the display name (same fallback as `outputReportHuman`)
6. Sort aggregated results by finding count descending
7. Output in the selected format

## Human Output Format

```
Total: 16 findings, 47 matches

 Rule                   Findings   Matches
────────────────────────────────────────────
 AWS API Key                   5        18
 GitHub Token                  4        12
 Slack Webhook URL             3         9
 Generic Password              2         4
 SSH Private Key               2         4
```

## JSON Output Format

```json
{
  "total_findings": 16,
  "total_matches": 47,
  "rules": [
    {"rule_id": "np.aws.1", "rule_name": "AWS API Key", "findings": 5, "matches": 18},
    {"rule_id": "np.github.1", "rule_name": "GitHub Token", "findings": 4, "matches": 12}
  ]
}
```

## Files Changed

### `cmd/titus/report.go`

- Add `summaryCmd` cobra command registered as child of `reportCmd`
- Add `summaryFormat` flag variable (`human`/`json`)
- Add `runSummary()` function: opens store, loads data, aggregates, dispatches to format function
- Add `outputSummaryHuman()`: prints total line + formatted table with color support
- Add `outputSummaryJSON()`: encodes structured JSON to stdout

### `cmd/titus/report_test.go`

- Test summary aggregation logic (multiple rules, correct counts, sort order)
- Test human output format (total line present, table structure)
- Test JSON output format (valid JSON, correct fields)
- Test edge case: empty datastore (no findings)

## Architecture Notes

- Follows existing subcommand pattern: subcommand defined in same file as parent (matches `github.go`, `gitlab.go`, `rules.go`)
- Reuses `buildFindingMatchMap()` helper already in `report.go`
- No new packages, types, or store methods required
- Existing `report` command behavior is unchanged
- `scan.go`'s `outputNoseyParkerSummary` is not modified (serves different context: post-scan in-memory summary)
