<!--
{
  "feature": "m1-finding-scoring-base",
  "linear": "LAB-2431",
  "phases": 5,
  "tasks": 36,
  "design_doc": "docs/plans/2026-04-22-finding-scoring-design.md"
}
-->

# Milestone 1 — Base Scoring Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `plan-execute` to implement this plan phase-by-phase.

**Goal:** Every Titus finding carries a deterministic `Score` object (0-100) derived from a required `base_score` field on its detection rule. No modifier engine yet — that ships in Milestones 2-4.

**Architecture:** Minimal additions to existing types, loader, datastore, and three output formats (JSON / SARIF / human). A one-shot migration tool populates `base_score` across all ~500 rule YAMLs using researched-per-rule values provided by parallel research subagents.

**Tech Stack:** Go 1.24, gopkg.in/yaml.v3, modernc.org/sqlite, fatih/color, spf13/cobra.

**Branch strategy:** Create `feat/finding-scoring-m1` from `design/finding-scoring`. All phases commit directly to this branch. Single PR at end.

---

## Verified APIs (from evidence-based analysis)

### types.Rule

**Source:** `pkg/types/rule.go:21-41`
```go
type Rule struct {
    ID               string
    Name             string
    Pattern          string
    StructuralID     string
    Description      string
    Examples         []string
    NegativeExamples []string
    References       []string
    Categories       []string
    Keywords         []string
    MinEntropy       float64
    PatternRequirements *PatternRequirements
}
```
**Change:** append `BaseScore int` field.

### types.Finding

**Source:** `pkg/types/finding.go:10-15`
```go
type Finding struct {
    ID      string
    RuleID  string
    Groups  [][]byte
    Matches []*Match
}
```
**Change:** append `Score *Score` field (pointer so nil == "unscored", preserves back-compat for old datastores).

### pkg/rule yamlRule

**Source:** `pkg/rule/yaml.go:15-26`
```go
type yamlRule struct {
    Name                string                   `yaml:"name"`
    ID                  string                   `yaml:"id"`
    Pattern             string                   `yaml:"pattern"`
    // ... other yaml tags ...
    PatternRequirements *yamlPatternRequirements `yaml:"pattern_requirements,omitempty"`
}
```
**Change:** add `BaseScore int `yaml:"base_score"`` field. NOT marked `omitempty` — we want to detect missing fields explicitly.

### pkg/rule.convertYAMLRule

**Source:** `pkg/rule/loader.go:161-185`
```go
func convertYAMLRule(yr yamlRule) *types.Rule {
    r := &types.Rule{ID: yr.ID, Name: yr.Name, Pattern: yr.Pattern, ...}
    ...
    r.StructuralID = r.ComputeStructuralID()
    return r
}
```
**Change:** signature becomes `func convertYAMLRule(yr yamlRule) (*types.Rule, error)` so validation can fail; set `r.BaseScore = yr.BaseScore`, validate range and required.

### pkg/rule.Loader.LoadBuiltinRules

**Source:** `pkg/rule/loader.go:87-121`
Current callers treat rule conversion as infallible (direct append after `convertYAMLRule`). **Change:** all call sites (`LoadRule`, `LoadBuiltinRules`) must propagate error from `convertYAMLRule`.

### pkg/store.Store interface

**Source:** `pkg/store/store.go:10-63`
```go
type Store interface {
    AddFinding(f *types.Finding) error
    GetFindings() ([]*types.Finding, error)
    // ... other methods
}
```
**Change:** NO interface change. `*types.Finding` now carries `Score *Score`; implementations must persist/restore it.

### pkg/store.SQLiteStore.AddFinding

**Source:** `pkg/store/sqlite.go:136-143`
```go
func (s *SQLiteStore) AddFinding(f *types.Finding) error {
    groupsJSON, err := serializeGroups(f.Groups)
    if err != nil { return fmt.Errorf("serializing groups: %w", err) }
    _, err = s.e.Exec("INSERT OR IGNORE INTO findings (structural_id, rule_id, groups_json) VALUES (?, ?, ?)",
        f.ID, f.RuleID, groupsJSON)
    return err
}
```
**Change:** extend INSERT with 4 new columns: `score_final`, `score_base`, `score_suggested_severity`, `score_applied_json` (JSON-encoded `[]ScoreModifier`, empty `[]` for M1).

### pkg/store.SQLiteStore.GetFindings

**Source:** `pkg/store/sqlite.go:145-167`
**Change:** SELECT new columns, populate `f.Score` when `score_final` is non-NULL.

### pkg/store findings table schema

**Source:** `pkg/store/schema.go:121-131`
```sql
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    structural_id TEXT NOT NULL UNIQUE,
    rule_id TEXT NOT NULL,
    groups_json TEXT
)
```
**Change:** add four columns + migration pattern. Follow the `provenance` table migration pattern at `schema.go:156-169` — `for _, col := range [...] { _, _ = db.Exec("ALTER TABLE findings ADD COLUMN " + col) }`.

### pkg/store.MemoryStore

**Source:** `pkg/store/memory.go:71-82`, `pkg/store/memory.go:153-162`
**Change:** `AddFinding` stores the `*types.Finding` pointer as-is (already does); `GetFindings` returns pointers as-is. No explicit Score handling needed — the struct carries it.

### pkg/sarif

**Source:** `pkg/sarif/sarif.go:58-63`
```go
type Result struct {
    RuleID    string     `json:"ruleId"`
    Level     string     `json:"level"`
    Message   Message    `json:"message"`
    Locations []Location `json:"locations"`
}
```
**Source:** `pkg/sarif/sarif.go:158-174` — `AddResult` currently hardcodes `Level: "warning"`.
**Change:** add `Properties *ResultProperties `json:"properties,omitempty"`` to `Result`; map `score.final` → `Level` band; emit `security-severity` and `titus_score` under `properties`.

### cmd/titus/scan.go outputMatches (JSON scan output)

**Source:** `cmd/titus/scan.go:1137-1141`
```go
func outputMatches(cmd *cobra.Command, matches []*types.Match) error {
    encoder := json.NewEncoder(cmd.OutOrStdout())
    encoder.SetIndent("", "  ")
    return encoder.Encode(matches)
}
```
**Change:** MINIMAL for M1 — scan JSON output stays as matches. Score lives on findings (persisted in datastore), and `titus report --format=json` is the canonical score-bearing output. Document this in a code comment. (Chariot reads findings via report, not raw matches.)

### cmd/titus/report.go outputReportJSON

**Source:** `cmd/titus/report.go:572-584`
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
**Change:** no code change here — `Score *Score` serializes via the Finding struct automatically. BUT must verify: before encoding, ensure every finding has `Score` populated. For M1, if `f.Score == nil` (legacy datastore), synthesize from `ruleMap[f.RuleID].BaseScore`.

### cmd/titus/report.go outputReportHuman

**Source:** `cmd/titus/report.go:624-630` (finding header render)
```go
_, _ = fmt.Fprintf(out, "%s (%s %s)\n",
    s.findingHeading.Sprintf("Finding %d/%d", i+1, totalFindings),
    s.heading.Sprint("id"),
    s.id.Sprint(f.ID))
```
**Change:** immediately after finding header, emit a score line: `Score: %d/%d (%s)\n` using `f.Score.Final`, 100, and `f.Score.SuggestedSeverity`. Use band-appropriate color (critical=red, high=yellow, medium=blue, low/info=dim).

### Finding creation in runScan

**Source:** `cmd/titus/scan.go:281-288`
```go
if err := tx.AddFinding(&types.Finding{
    ID:     findingID,
    RuleID: match.RuleID,
    Groups: match.Groups,
}); err != nil {
    return fmt.Errorf("storing finding: %w", err)
}
```
**Change:** populate `Score` on the new finding before calling `AddFinding`:
```go
rule := ruleMap[match.RuleID]
finding := &types.Finding{ID: findingID, RuleID: match.RuleID, Groups: match.Groups}
finding.Score = &types.Score{
    Final:             rule.BaseScore,
    Base:              rule.BaseScore,
    SuggestedSeverity: types.SeverityForScore(rule.BaseScore),
    Applied:           []types.ScoreModifier{}, // always non-nil for stable JSON
}
if err := tx.AddFinding(finding); err != nil { ... }
```

### Rule YAML structure

**Source:** `pkg/rule/rules/aws.yml:1-14`
```yaml
rules:
- name: AWS API Key
  id: np.aws.1
  pattern: '\b(?P<key_id>...)\b'
  references: [ ... ]
  categories: [ api, ... ]
```
**Change:** every rule YAML gets a `base_score:` field inserted (by migration tool). Value is researched per rule.

### Makefile existing targets

**Source:** `Makefile:4`
```
.PHONY: all build build-pure build-static build-wasm build-extension test vet lint clean integration-test static-test build-burp install-burp clean-burp clean-extension check-vectorscan
```
**Change:** add `score-lint` to `.PHONY` list; add new target definition that runs `go run ./cmd/titus-score-lint` which validates every rule has `base_score` in range [0, 100] and flags tier/naming mismatches.

### Rule loader test patterns

**Source:** `pkg/rule/loader_test.go:10-63`
- Tests use embedded YAML strings
- Assertions use `t.Errorf`/`t.Fatalf`, no testify
- Pattern: `loader := NewLoader(); rule, err := loader.LoadRule([]byte(yaml)); if err != nil { t.Fatalf(...) }`
**New tests follow this style** — no testify imports, use stdlib `testing`.

### Existing cmd/ binaries

**Source:** `ls /tmp/titus-ci-fix/cmd/` returns only `titus/`.
**Implication:** no prior `cmd/titus-*` pattern to follow. We create a fresh `cmd/titus-migrate-scores/` and `cmd/titus-score-lint/` with standard `package main` + cobra-or-flag. Register in Makefile `build-migrate-scores` target (no need for full `install` integration since these are dev tools).

---

## Assumptions (not directly verified)

| Assumption | Why unverified | Risk if wrong |
|---|---|---|
| SQLite's `ALTER TABLE ... ADD COLUMN` error-on-exists is ignored safely (used in provenance migration) | Existing code uses `_, _ = db.Exec(...)` pattern to swallow errors; can't verify behavior on all SQLite versions without running | Low — we're following the established pattern |
| The ~500 rule count is approximate — verified `ls pkg/rule/rules/ | wc -l` returns 299 `.yml` files, but one file may contain multiple rules | Didn't audit total rule count by parsing every YAML | Medium — research batching may need adjustment if actual count is 600+ or 200. Mitigated: phase 3 has a rule-count verification step |
| Existing datastores (pre-M1) with findings but no score columns should render gracefully in JSON/human output | Didn't test against a pre-M1 datastore | Medium — if SELECT fails on missing columns, existing users can't open old datastores. Mitigated: phase 0 has a migration test |
| `types.Finding.Score *Score` serializes as `{"Score": {...}}` in JSON (capital-S) matching existing field capitalization in Finding struct (no json tags) | Observed `Match` uses default capitalization for most fields | Low — if capitalization is wrong, fix with explicit `json:"score"` tag |

---

## Phases

| # | File | Title | Dep | Parallel with |
|---|---|---|---|---|
| 0 | phase-0-foundation.md | Foundation types + datastore | — | — |
| 1 | phase-1-output.md | JSON / SARIF / human output | 0 | 2 |
| 2 | phase-2-migration-tool.md | cmd/titus-migrate-scores tool | 0 | 1 |
| 3 | phase-3-research-campaign.md | 500-rule parallel research | 2 | — |
| 4 | phase-4-enforcement-tests.md | score-lint + test suite + final verification | 0, 1, 3 | — |

Recommended execution: Phase 0 sequentially, Phases 1 and 2 in parallel, Phase 3 (long-running research campaign), Phase 4 at the end.

## Exit Criteria (entire Milestone 1)

- [ ] Every rule in `pkg/rule/rules/*.yml` has a `base_score` field in [0, 100] (verify: `go run ./cmd/titus-score-lint .` exits 0; verify count with `grep -c 'base_score:' pkg/rule/rules/*.yml | awk -F: '{s+=$2}END{print s}'` equals `grep -c '^- id:\|^  - id:\|^  id:' pkg/rule/rules/*.yml | awk -F: '{s+=$2}END{print s}'`)
- [ ] `go build ./...` succeeds
- [ ] `go test ./...` passes all tests including new `TestAllRules_HaveBaseScore`, `TestCriticalTier_RulesExist`, `TestTierBoundaries`, `TestScoreJSON_SchemaStability`
- [ ] `titus scan testdata/secrets --format=human` output includes a `Score: N/100 (tier)` line for each finding
- [ ] `titus report --format=json` emits a `Score` object on every finding
- [ ] `titus report --format=sarif` maps score to `level` per band and emits `properties.security-severity` + `properties.titus_score`
- [ ] SQLite datastore schema contains 4 new columns on `findings` table; old datastores opened without error
- [ ] `make score-lint` runs cleanly

## Execution Handoff

This plan is structured for **subagent-driven execution** — each task has a single focused responsibility, and phases 1 and 2 can run concurrently in separate subagents.

Recommended approach: use `developing-with-subagents` skill, dispatching one subagent per task with code review between tasks.
