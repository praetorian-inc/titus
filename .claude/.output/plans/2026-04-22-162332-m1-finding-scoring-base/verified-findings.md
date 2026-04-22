# Verified Findings — Milestone 1 Foundation

Evidence-based analysis completed before writing the implementation plan. Every API reference in the plan files is grounded in source file quotes from `/tmp/titus-ci-fix` at branch `design/finding-scoring` (HEAD: `5ddf1f8`).

## Verified APIs

### API: `types.Rule` struct

**Source:** `pkg/types/rule.go` (lines 21-41)
**Actual:**
```go
type Rule struct {
    ID               string   // e.g., "np.aws.1"
    Name             string   // human-readable name
    Pattern          string   // regex pattern
    StructuralID     string   // SHA-1 of pattern (computed)
    Description      string   // optional
    Examples         []string // positive test cases
    NegativeExamples []string // negative test cases
    References       []string // documentation URLs
    Categories       []string // classification tags
    Keywords         []string // keywords for Aho-Corasick prefiltering
    MinEntropy       float64
    PatternRequirements *PatternRequirements
}
```
**Planned usage:** Append `BaseScore int` field. **Verified: struct does not currently contain a BaseScore field** (`grep -n BaseScore pkg/types/rule.go` returns 0 matches).

### API: `types.Finding` struct

**Source:** `pkg/types/finding.go` (lines 10-15)
**Actual:**
```go
type Finding struct {
    ID      string   // SHA-1(rule_structural_id + '\0' + json(groups))
    RuleID  string
    Groups  [][]byte
    Matches []*Match // matches belonging to this finding
}
```
**Planned usage:** Append `Score *Score` field. **Verified: no JSON tags present**; default serialization uses capitalized field names.

### API: `pkg/rule.yamlRule` struct

**Source:** `pkg/rule/yaml.go` (lines 15-26)
**Actual:**
```go
type yamlRule struct {
    Name                string                   `yaml:"name"`
    ID                  string                   `yaml:"id"`
    Pattern             string                   `yaml:"pattern"`
    Description         string                   `yaml:"description,omitempty"`
    Examples            []string                 `yaml:"examples,omitempty"`
    NegativeExamples    []string                 `yaml:"negative_examples,omitempty"`
    References          []string                 `yaml:"references,omitempty"`
    Categories          []string                 `yaml:"categories,omitempty"`
    MinEntropy          float64                  `yaml:"min_entropy,omitempty"`
    PatternRequirements *yamlPatternRequirements `yaml:"pattern_requirements,omitempty"`
}
```
**Planned usage:** Add `BaseScore *int `yaml:"base_score"`` (pointer type so we can distinguish "unset" from "explicitly 0").

### API: `convertYAMLRule` function

**Source:** `pkg/rule/loader.go` (lines 161-185)
**Actual signature:**
```go
func convertYAMLRule(yr yamlRule) *types.Rule
```
**Planned change:** Signature becomes `func convertYAMLRule(yr yamlRule) (*types.Rule, error)`. All call sites (`LoadRule` at line 47, `LoadBuiltinRules` at line 110) must propagate the error.

### API: `pkg/store.Store` interface

**Source:** `pkg/store/store.go` (lines 10-63)
**Actual methods:**
```go
AddFinding(f *types.Finding) error
GetFindings() ([]*types.Finding, error)
FindingExists(structuralID string) (bool, error)
```
**Planned change:** **No interface modification**. Score lives on `*types.Finding` (pointer), so implementations that store the finding store the score automatically.

### API: `SQLiteStore.AddFinding`

**Source:** `pkg/store/sqlite.go` (lines 136-143)
**Actual:**
```go
func (s *SQLiteStore) AddFinding(f *types.Finding) error {
    groupsJSON, err := serializeGroups(f.Groups)
    if err != nil {
        return fmt.Errorf("serializing groups: %w", err)
    }
    _, err = s.e.Exec("INSERT OR IGNORE INTO findings (structural_id, rule_id, groups_json) VALUES (?, ?, ?)", f.ID, f.RuleID, groupsJSON)
    return err
}
```
**Planned change:** INSERT extends to 7 columns (add `score_final`, `score_base`, `score_suggested_severity`, `score_applied_json`). Uses `sql.NullInt64` / `sql.NullString` for when Score is nil.

### API: `createFindingsTable` function

**Source:** `pkg/store/schema.go` (lines 121-131)
**Actual:**
```go
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
```
**Planned change:** Extend CREATE TABLE with 4 new nullable columns; add migration via `ALTER TABLE ADD COLUMN` pattern (following the verified precedent in `createProvenanceTable` at lines 156-169).

### API: `createProvenanceTable` migration pattern (REFERENCE)

**Source:** `pkg/store/schema.go` (lines 156-169)
**Actual migration block:**
```go
// Migrate old datastores: add commit metadata columns if missing.
// ALTER TABLE ADD COLUMN is safe in SQLite — it's a no-op if the column exists
// only in newer SQLite versions, so we ignore errors (column already exists).
for _, col := range []string{
    "author_name TEXT",
    "author_email TEXT",
    ...
} {
    _, _ = db.Exec("ALTER TABLE provenance ADD COLUMN " + col)
}
```
**Implication:** This is the idiomatic migration pattern in this codebase. Task 0.5 follows it verbatim for the findings table.

### API: `SQLiteStore.GetFindings`

**Source:** `pkg/store/sqlite.go` (lines 145-167)
**Actual:**
```go
func (s *SQLiteStore) GetFindings() ([]*types.Finding, error) {
    rows, err := s.e.Query("SELECT structural_id, rule_id, groups_json FROM findings")
    ...
    for rows.Next() {
        var f types.Finding
        var groupsJSON sql.NullString
        if err := rows.Scan(&f.ID, &f.RuleID, &groupsJSON); err != nil {
            return nil, err
        }
        ...
    }
}
```
**Planned change:** SELECT extended to 7 columns; scan Score fields into new `sql.NullInt64` / `sql.NullString` locals; populate `f.Score` if any score column is non-NULL.

### API: `MemoryStore.AddFinding` / `MemoryStore.GetFindings`

**Source:** `pkg/store/memory.go` (lines 71-82, 153-162)
**Actual:** Stores `*types.Finding` pointers in a map keyed by `f.ID`. No serialization — returns same pointers.
**Implication:** No code change needed. The `Score *Score` field is carried by the pointer automatically. Task 0.7 adds a test to lock in this behavior.

### API: `pkg/sarif.Result` struct

**Source:** `pkg/sarif/sarif.go` (lines 58-63)
**Actual:**
```go
type Result struct {
    RuleID    string     `json:"ruleId"`
    Level     string     `json:"level"`
    Message   Message    `json:"message"`
    Locations []Location `json:"locations"`
}
```
**Planned change:** Append `Properties *ResultProperties `json:"properties,omitempty"``.

### API: `pkg/sarif.Report.AddResult`

**Source:** `pkg/sarif/sarif.go` (lines 139-177)
**Actual: `Level: "warning"` hardcoded at line 160.**
**Planned change:** Add a new method `AddResultWithScore(match, filePath, score)` that maps score → band; existing `AddResult` stays for backward compatibility (callers who don't have a score).

### API: `cmd/titus/scan.go` finding creation

**Source:** `cmd/titus/scan.go` (lines 281-288 inside `runScan` flush closure)
**Actual:**
```go
if !exists {
    findingCount.Add(1)
    if err := tx.AddFinding(&types.Finding{
        ID:     findingID,
        RuleID: match.RuleID,
        Groups: match.Groups,
    }); err != nil {
        return fmt.Errorf("storing finding: %w", err)
    }
}
```
**Planned change:** Pass `Score: synthesizeBaseScore(rule)` in the struct literal. `rule` is already in scope (bound from `ruleMap[match.RuleID]` at line 270).

### API: `cmd/titus/scan.go` JSON emitter

**Source:** `cmd/titus/scan.go` (lines 1137-1141)
**Actual:**
```go
func outputMatches(cmd *cobra.Command, matches []*types.Match) error {
    encoder := json.NewEncoder(cmd.OutOrStdout())
    encoder.SetIndent("", "  ")
    return encoder.Encode(matches)
}
```
**Planned change:** **No change**. Scan JSON stays as a matches array; findings (with Score) come from `titus report --format=json`. Documentation comment added to clarify this (Task 1.4).

### API: `cmd/titus/scan.go` SARIF emitter

**Source:** `cmd/titus/scan.go` (function `outputSARIF`, discovered via `grep 'func outputSARIF'`; takes matches + rules + store)
**Planned change:** Load findings, build `findingByID map[string]*types.Finding`, and for each match look up its finding to get `Score` — pass to `AddResultWithScore`.

### API: `cmd/titus/report.go outputReportJSON`

**Source:** `cmd/titus/report.go` (lines 572-584)
**Actual:**
```go
func outputReportJSON(cmd *cobra.Command, findings []*types.Finding, matches []*types.Match, ruleMap map[string]*types.Rule) error {
    matchesByFinding := buildFindingMatchMap(findings, matches, ruleMap)
    for _, f := range findings {
        f.Matches = matchesByFinding[f.ID]
    }
    encoder := json.NewEncoder(cmd.OutOrStdout())
    encoder.SetIndent("", "  ")
    return encoder.Encode(findings)
}
```
**Implication:** No code change needed to emit Score (default JSON serialization includes `f.Score` automatically). Task 1.5 adds a golden-file test to lock in the schema.

### API: `cmd/titus/report.go outputReportHuman` finding header render

**Source:** `cmd/titus/report.go` (lines 624-630)
**Actual:**
```go
_, _ = fmt.Fprintf(out, "%s (%s %s)\n",
    s.findingHeading.Sprintf("Finding %d/%d", i+1, totalFindings),
    s.heading.Sprint("id"),
    s.id.Sprint(f.ID))
```
**Planned change:** Insert score-badge block immediately after this header.

### API: Rule YAML structure (example)

**Source:** `pkg/rule/rules/aws.yml` (lines 1-14)
**Actual format:**
```yaml
rules:
- name: AWS API Key
  id: np.aws.1
  pattern: '\b(?P<key_id>...)\b'
  references: [...]
  categories: [api, ...]
```
**Observation:** Rule block begins with `- name:` or `- id:` at column 0 (or 2 with indentation). Multiple rules per file are common. Task 2.2 migration tool uses this structure via line-based parsing.

### API: Existing cmd directory

**Source:** `ls /tmp/titus-ci-fix/cmd/` returns only `titus/`.
**Implication:** No prior `cmd/titus-*` pattern exists. Phase 2 creates `cmd/titus-migrate-scores/` and Phase 4 creates `cmd/titus-score-lint/` as new packages.

### API: Makefile existing targets

**Source:** `Makefile` line 4
**Actual:**
```makefile
.PHONY: all build build-pure build-static build-wasm build-extension test vet lint clean integration-test static-test build-burp install-burp clean-burp clean-extension check-vectorscan
```
**Planned change:** Add `build-migrate-scores migrate-scores-dryrun migrate-scores-apply score-lint` to `.PHONY`; define targets near `build:` target.

### API: Test patterns

**Source:** `pkg/rule/loader_test.go` (lines 10-63)
**Observation:** Tests use:
- Stdlib `testing` package only (no testify)
- `t.Errorf` / `t.Fatalf` for assertions
- Inline YAML strings via backtick literals
- `t.TempDir()` for isolated filesystem

**Implication:** All new tests follow these conventions.

## Assumptions (not directly verified, with risk assessment)

| Assumption | Why unverified | Risk if wrong | Mitigation |
|---|---|---|---|
| SQLite `ALTER TABLE ADD COLUMN` tolerates "column already exists" via ignored error | Depends on the SQLite version; the provenance pattern uses this but I can't verify on every SQLite build | Low — the pattern is already used in production for the provenance table at `schema.go:156-169` | Follow existing pattern exactly; add an integration test (Task 0.5 `TestFindingsTable_MigratesOldSchema`) that exercises the migration path |
| Rule count is ~500 (299 files × avg rules/file) | Didn't parse every YAML to count rules | Medium — batching in Phase 3 may need adjustment if count is 200 or 700 | Task 3.1 has an explicit `wc -l all_rules.csv` step that produces the real count before batching |
| `Finding` with no JSON tags serializes `Score *Score` as `"Score": {...}` | Observed behavior from `Match` which has most fields untagged | Low — if capitalization is wrong, add explicit `json:"score"` tags (backward-compat-safe since no existing consumer expects `"Score"` under this schema) | Golden file test (Task 1.5) locks in the exact JSON shape |
| Pre-M1 datastores can be opened and read without error once migration columns are added | Didn't test against a pre-existing datastore file | Medium — breaking existing users would require a data migration tool | `TestFindingsTable_MigratesOldSchema` (Task 0.5) creates a simulated pre-M1 schema and exercises the upgrade path |
| Research subagents can successfully differentiate tiers given the prompt in Task 3.2 | Can't verify subagent behavior without running | Medium — if scores cluster at medium (safe default), differentiation fails | Task 3.6 distribution review catches this; explicit `LOW CONFIDENCE` marking in prompt surfaces uncertain rules for human review |
| The existing `outputSARIF` function signature allows passing a store for finding lookup | `grep 'func outputSARIF' cmd/titus/scan.go` shows it takes `(cmd, s, rules, matches)` — store is already available | None, verified | — |

## Integration Flow

Evidence-based analysis (this document) discovered WHAT EXISTS. The plan files (PLAN.md, phase-0 through phase-4) document HOW TO CHANGE IT — every code block references these verified sources by file:line.

## Pre-Planning Validation Checklist

- [x] I invoked `enforcing-evidence-based-analysis` skill
- [x] I have source-file quotes (with Read tool evidence) for every API the plan references
- [x] I have exact line numbers for all referenced code
- [x] I verified planned API usage matches actual signatures (e.g., `convertYAMLRule` current return type is `*types.Rule`, plan changes to `(*types.Rule, error)` — compatible refactor)
- [x] Assumptions section lists unverified items with risk + mitigation
- [x] Every code example in the plan uses APIs that actually exist in the codebase
