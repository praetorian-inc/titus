<!--
{
  "phase": 0,
  "title": "Foundation: Score type, Rule.BaseScore, datastore schema",
  "feature": "m1-finding-scoring-base",
  "linear": "LAB-2431",
  "depends_on": [],
  "tasks": 10
}
-->

# Phase 0 — Foundation

> **For Claude:** Execute tasks in order. TDD throughout — write test first, verify red, implement, verify green, commit. No task skipped.

## Entry criteria
- Branch `feat/finding-scoring-m1` created from `design/finding-scoring`
- `go build ./...` passes cleanly on branch start

## Exit criteria
- [ ] `types.Score` struct + `types.SeverityForScore` helper exist with tests
- [ ] `types.Rule.BaseScore` field exists
- [ ] `types.Finding.Score` pointer field exists
- [ ] YAML loader reads `base_score` and returns error when missing (during Phase 0, missing is allowed as warning; hardened in Phase 4)
- [ ] SQLite `findings` table has 4 new columns; old-format datastores still open
- [ ] `runScan` populates `Score` on every new finding
- [ ] All existing tests still pass; all new tests pass
- [ ] `go build ./...` succeeds

---

## Task 0.1: Create `types.Score` struct + tier helper

**Files:**
- Create: `pkg/types/score.go`
- Create: `pkg/types/score_test.go`

**Step 1: Write the failing test**

File: `pkg/types/score_test.go`
```go
package types

import (
    "encoding/json"
    "testing"
)

func TestSeverityForScore(t *testing.T) {
    cases := []struct {
        score int
        want  string
    }{
        {0, "info"}, {10, "info"}, {19, "info"},
        {20, "low"}, {30, "low"}, {39, "low"},
        {40, "medium"}, {50, "medium"}, {59, "medium"},
        {60, "high"}, {70, "high"}, {79, "high"},
        {80, "critical"}, {90, "critical"}, {100, "critical"},
    }
    for _, c := range cases {
        if got := SeverityForScore(c.score); got != c.want {
            t.Errorf("SeverityForScore(%d) = %q, want %q", c.score, got, c.want)
        }
    }
}

func TestSeverityForScore_OutOfRange(t *testing.T) {
    if got := SeverityForScore(-5); got != "info" {
        t.Errorf("SeverityForScore(-5) = %q, want info (clamped)", got)
    }
    if got := SeverityForScore(150); got != "critical" {
        t.Errorf("SeverityForScore(150) = %q, want critical (clamped)", got)
    }
}

func TestScore_JSONSerialization(t *testing.T) {
    s := &Score{
        Final:             85,
        Base:              60,
        SuggestedSeverity: "critical",
        Applied: []ScoreModifier{
            {Name: "iam-admin", Scorer: "aws", Kind: "set_score", Value: 95, Priority: 50},
        },
    }
    data, err := json.Marshal(s)
    if err != nil {
        t.Fatalf("json.Marshal: %v", err)
    }
    got := string(data)
    want := `{"Final":85,"Base":60,"SuggestedSeverity":"critical","Applied":[{"Name":"iam-admin","Scorer":"aws","Kind":"set_score","Value":95,"Priority":50}]}`
    if got != want {
        t.Errorf("JSON mismatch\n got: %s\nwant: %s", got, want)
    }
}

func TestScore_EmptyAppliedSerializesAsEmptyArray(t *testing.T) {
    s := &Score{Final: 50, Base: 50, SuggestedSeverity: "medium", Applied: []ScoreModifier{}}
    data, _ := json.Marshal(s)
    got := string(data)
    // Must contain "Applied":[] not "Applied":null
    want := `"Applied":[]`
    if !containsSubstring(got, want) {
        t.Errorf("expected %q in output, got %s", want, got)
    }
}

func containsSubstring(s, sub string) bool {
    for i := 0; i+len(sub) <= len(s); i++ {
        if s[i:i+len(sub)] == sub {
            return true
        }
    }
    return false
}
```

**Step 2: Run test to verify it fails**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/types/ -run 'TestSeverityForScore|TestScore_' -v`
Expected: FAIL — undefined: Score, SeverityForScore

**Step 3: Write minimal implementation**

File: `pkg/types/score.go`
```go
package types

// Score captures a finding's computed severity score and the modifiers that
// produced it. Score values are integers in [0, 100] where 0 is minimal
// severity and 100 is maximum severity.
type Score struct {
    // Final is the clamped 0-100 score after all modifiers are applied.
    Final int
    // Base is the rule's BaseScore before any modifiers.
    Base int
    // SuggestedSeverity is a tier hint derived from Final. Downstream
    // consumers (Chariot, SARIF) may remap these bands.
    // Values: "info" (0-19), "low" (20-39), "medium" (40-59),
    //         "high" (60-79), "critical" (80-100).
    SuggestedSeverity string
    // Applied is the audit trail of modifiers that fired, in evaluation order.
    // For Milestone 1 this is always empty (no engine yet) — the engine lands
    // in Milestones 2+.
    Applied []ScoreModifier
}

// ScoreModifier records a single modifier that fired during scoring.
type ScoreModifier struct {
    Name     string
    Scorer   string
    Kind     string // "delta" or "set_score"
    Value    int
    Priority int
}

// SeverityForScore maps a numeric score to its suggested severity tier.
// Out-of-range inputs are clamped (below 0 → info, above 100 → critical).
func SeverityForScore(score int) string {
    switch {
    case score < 20:
        return "info"
    case score < 40:
        return "low"
    case score < 60:
        return "medium"
    case score < 80:
        return "high"
    default:
        return "critical"
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/types/ -run 'TestSeverityForScore|TestScore_' -v`
Expected: PASS (all 4 tests)

**Step 5: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f pkg/types/score.go pkg/types/score_test.go && git commit -m "feat(types): add Score struct and SeverityForScore helper"
```

**Exit Criteria:**
- [ ] `pkg/types/score.go` exists, defines `Score`, `ScoreModifier`, `SeverityForScore` (verify: `grep -c '^type Score\|^type ScoreModifier\|^func SeverityForScore' pkg/types/score.go` returns 3)
- [ ] 4 tests pass in `pkg/types/score_test.go` (verify: `go test ./pkg/types/ -run TestScore_ -v | grep -c 'PASS:'` >= 3; `go test ./pkg/types/ -run TestSeverityForScore -v | grep -c 'PASS:'` >= 2)

---

## Task 0.2: Add `BaseScore` field to `types.Rule`

**Files:**
- Modify: `pkg/types/rule.go` (line 21-41)

**Step 1: Write the failing test**

Add to `pkg/types/rule_test.go` (new function, append):
```go
func TestRule_HasBaseScore(t *testing.T) {
    r := &Rule{ID: "test.1", BaseScore: 75}
    if r.BaseScore != 75 {
        t.Errorf("BaseScore = %d, want 75", r.BaseScore)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/types/ -run TestRule_HasBaseScore`
Expected: FAIL — unknown field 'BaseScore' in struct literal

**Step 3: Implement**

Modify `pkg/types/rule.go` line 40 — add after `PatternRequirements *PatternRequirements`:
```go
    // BaseScore is the inherent severity of this rule's secret class,
    // ranging 0-100. Assigned via research per rule. Required.
    BaseScore int
```

**Step 4: Verify test passes**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/types/ -run TestRule_HasBaseScore`
Expected: PASS

**Step 5: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f pkg/types/rule.go pkg/types/rule_test.go && git commit -m "feat(types): add BaseScore field to Rule struct"
```

**Exit Criteria:**
- [ ] `Rule.BaseScore` field exists (verify: `grep -c 'BaseScore int' pkg/types/rule.go` returns 1)
- [ ] `TestRule_HasBaseScore` passes
- [ ] `go build ./...` still succeeds

---

## Task 0.3: Add `Score` pointer field to `types.Finding`

**Files:**
- Modify: `pkg/types/finding.go` (lines 10-15)

**Step 1: Write the failing test**

Add to `pkg/types/finding_test.go` (new function, append):
```go
func TestFinding_HasScoreField(t *testing.T) {
    f := &Finding{
        ID:     "abc",
        RuleID: "np.aws.1",
        Score: &Score{
            Final: 75, Base: 60, SuggestedSeverity: "high",
            Applied: []ScoreModifier{},
        },
    }
    if f.Score == nil {
        t.Fatal("expected non-nil Score")
    }
    if f.Score.Final != 75 {
        t.Errorf("Score.Final = %d, want 75", f.Score.Final)
    }
}

func TestFinding_ScoreNilForLegacy(t *testing.T) {
    // A Finding without Score should serialize without issue (nil pointer).
    f := &Finding{ID: "abc", RuleID: "np.test.1"}
    if f.Score != nil {
        t.Errorf("expected Score to default to nil, got %+v", f.Score)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/types/ -run TestFinding_`
Expected: FAIL — unknown field 'Score' in struct literal

**Step 3: Implement**

Modify `pkg/types/finding.go`. Change the Finding struct to:
```go
// Finding groups matches with same (rule, groups) for deduplication.
type Finding struct {
    ID      string   // SHA-1(rule_structural_id + '\0' + json(groups))
    RuleID  string
    Groups  [][]byte
    Matches []*Match // matches belonging to this finding
    // Score is the computed severity score for this finding. Nil indicates
    // the finding predates scoring (legacy datastores) or scoring was skipped.
    Score *Score
}
```

**Step 4: Verify test passes**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/types/ -run TestFinding_ -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f pkg/types/finding.go pkg/types/finding_test.go && git commit -m "feat(types): add Score pointer to Finding"
```

**Exit Criteria:**
- [ ] `Finding.Score *Score` field exists (verify: `grep 'Score \*Score' pkg/types/finding.go` returns 1 match)
- [ ] Both new tests pass
- [ ] `go build ./...` still succeeds

---

## Task 0.4: Add `base_score` to YAML rule parser

**Files:**
- Modify: `pkg/rule/yaml.go` (line 15-26)
- Modify: `pkg/rule/loader.go` (function `convertYAMLRule`, line 161-185)

**Step 1: Write the failing test**

Add to `pkg/rule/loader_test.go` (append):
```go
func TestLoadRule_BaseScoreParsed(t *testing.T) {
    loader := NewLoader()
    yaml := `rules:
  - name: Test Rule
    id: np.test.1
    pattern: 'test'
    base_score: 75
`
    rule, err := loader.LoadRule([]byte(yaml))
    if err != nil {
        t.Fatalf("LoadRule: %v", err)
    }
    if rule.BaseScore != 75 {
        t.Errorf("BaseScore = %d, want 75", rule.BaseScore)
    }
}

func TestLoadRule_BaseScoreMissing_PhaseZero(t *testing.T) {
    // During Phase 0, missing base_score is allowed (will be hardened to error
    // in Phase 4 after migration is complete). Default value is 0.
    loader := NewLoader()
    yaml := `rules:
  - name: Test Rule
    id: np.test.1
    pattern: 'test'
`
    rule, err := loader.LoadRule([]byte(yaml))
    if err != nil {
        t.Fatalf("LoadRule (Phase 0 permissive): %v", err)
    }
    if rule.BaseScore != 0 {
        t.Errorf("BaseScore = %d, want 0 (default)", rule.BaseScore)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/rule/ -run TestLoadRule_BaseScore -v`
Expected: FAIL — `BaseScore = 0, want 75` (field ignored by YAML parser)

**Step 3: Implement**

Modify `pkg/rule/yaml.go`. Change `yamlRule` struct to:
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
    BaseScore           int                      `yaml:"base_score"`
}
```

Modify `pkg/rule/loader.go` `convertYAMLRule`. Change the struct literal at line 162-172 to include `BaseScore: yr.BaseScore`:
```go
func convertYAMLRule(yr yamlRule) *types.Rule {
    r := &types.Rule{
        ID:               yr.ID,
        Name:             yr.Name,
        Pattern:          yr.Pattern,
        Description:      yr.Description,
        Examples:         yr.Examples,
        NegativeExamples: yr.NegativeExamples,
        References:       yr.References,
        Categories:       yr.Categories,
        MinEntropy:       yr.MinEntropy,
        BaseScore:        yr.BaseScore,
    }
    // ... rest unchanged
}
```

**Step 4: Verify test passes**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/rule/ -run TestLoadRule_BaseScore -v`
Expected: PASS (both new tests)

**Step 5: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f pkg/rule/yaml.go pkg/rule/loader.go pkg/rule/loader_test.go && git commit -m "feat(rule): parse base_score field from rule YAML"
```

**Exit Criteria:**
- [ ] `yamlRule.BaseScore` with `yaml:"base_score"` tag exists (verify: `grep 'yaml:"base_score"' pkg/rule/yaml.go` returns 1 match)
- [ ] `convertYAMLRule` sets `BaseScore: yr.BaseScore` (verify: `grep 'BaseScore: yr.BaseScore' pkg/rule/loader.go` returns 1)
- [ ] 2 new tests pass

---

## Task 0.5: Extend findings SQL schema with score columns + migration

**Files:**
- Modify: `pkg/store/schema.go` (function `createFindingsTable`, lines 121-131)

**Step 1: Write the failing test**

Create new file `pkg/store/score_migration_test.go`:
```go
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
```

**Step 2: Run test to verify it fails**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/store/ -run 'TestFindingsTable_' -v`
Expected: FAIL — `findings table missing column "score_final"` etc.

**Step 3: Implement**

Modify `pkg/store/schema.go` `createFindingsTable`. Follow the pattern from `createProvenanceTable` at lines 156-169:

```go
func createFindingsTable(db *sql.DB) error {
    _, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            structural_id TEXT NOT NULL UNIQUE,
            rule_id TEXT NOT NULL,
            groups_json TEXT,
            score_final INTEGER,
            score_base INTEGER,
            score_suggested_severity TEXT,
            score_applied_json TEXT
        )
    `)
    if err != nil {
        return err
    }

    // Migrate old datastores: add score columns if missing.
    // ALTER TABLE ADD COLUMN errors (column already exists) are ignored,
    // following the same pattern as provenance table migration.
    for _, col := range []string{
        "score_final INTEGER",
        "score_base INTEGER",
        "score_suggested_severity TEXT",
        "score_applied_json TEXT",
    } {
        _, _ = db.Exec("ALTER TABLE findings ADD COLUMN " + col)
    }

    return nil
}
```

**Step 4: Verify test passes**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/store/ -run 'TestFindingsTable_' -v`
Expected: PASS (both tests)

Run the full store test suite to confirm no regression:
Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/store/...`
Expected: all pass

**Step 5: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f pkg/store/schema.go pkg/store/score_migration_test.go && git commit -m "feat(store): extend findings table with score columns and migration"
```

**Exit Criteria:**
- [ ] `findings` table has 4 new columns after `CreateSchema` on a fresh DB (verify: `TestFindingsTable_HasScoreColumns` passes)
- [ ] `findings` table on an old-format DB gets columns added without data loss (verify: `TestFindingsTable_MigratesOldSchema` passes)
- [ ] All existing store tests still pass

---

## Task 0.6: Update `SQLiteStore.AddFinding` to persist score

**Files:**
- Modify: `pkg/store/sqlite.go` (function `AddFinding`, lines 136-143)

**Step 1: Write the failing test**

Add to `pkg/store/sqlite_test.go` (append):
```go
func TestSQLiteStore_AddFinding_PersistsScore(t *testing.T) {
    tmpDir := t.TempDir()
    s, err := NewSQLite(filepath.Join(tmpDir, "test.db"))
    if err != nil {
        t.Fatal(err)
    }
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
    if err := s.AddFinding(finding); err != nil {
        t.Fatalf("AddFinding: %v", err)
    }

    findings, err := s.GetFindings()
    if err != nil {
        t.Fatalf("GetFindings: %v", err)
    }
    if len(findings) != 1 {
        t.Fatalf("expected 1 finding, got %d", len(findings))
    }
    got := findings[0]
    if got.Score == nil {
        t.Fatal("expected Score to be non-nil after round-trip")
    }
    if got.Score.Final != 85 {
        t.Errorf("Score.Final = %d, want 85", got.Score.Final)
    }
    if got.Score.Base != 60 {
        t.Errorf("Score.Base = %d, want 60", got.Score.Base)
    }
    if got.Score.SuggestedSeverity != "critical" {
        t.Errorf("Score.SuggestedSeverity = %q, want critical", got.Score.SuggestedSeverity)
    }
    if got.Score.Applied == nil {
        t.Errorf("Score.Applied = nil, want empty slice")
    }
}

func TestSQLiteStore_AddFinding_NilScoreAllowed(t *testing.T) {
    tmpDir := t.TempDir()
    s, err := NewSQLite(filepath.Join(tmpDir, "test.db"))
    if err != nil {
        t.Fatal(err)
    }
    defer func() { _ = s.Close() }()

    finding := &types.Finding{
        ID:     "xyz",
        RuleID: "np.test.1",
        Groups: [][]byte{[]byte("x")},
        // Score is nil
    }
    if err := s.AddFinding(finding); err != nil {
        t.Fatalf("AddFinding with nil Score: %v", err)
    }

    findings, _ := s.GetFindings()
    if len(findings) != 1 {
        t.Fatalf("expected 1 finding, got %d", len(findings))
    }
    if findings[0].Score != nil {
        t.Errorf("expected Score to stay nil after round-trip, got %+v", findings[0].Score)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/store/ -run TestSQLiteStore_AddFinding_ -v`
Expected: FAIL — `Score = nil, want non-nil` (AddFinding doesn't persist score yet)

**Step 3: Implement**

Modify `pkg/store/sqlite.go` `AddFinding`:
```go
func (s *SQLiteStore) AddFinding(f *types.Finding) error {
    groupsJSON, err := serializeGroups(f.Groups)
    if err != nil {
        return fmt.Errorf("serializing groups: %w", err)
    }

    var scoreFinal, scoreBase sql.NullInt64
    var scoreSeverity, scoreApplied sql.NullString
    if f.Score != nil {
        scoreFinal = sql.NullInt64{Int64: int64(f.Score.Final), Valid: true}
        scoreBase = sql.NullInt64{Int64: int64(f.Score.Base), Valid: true}
        scoreSeverity = sql.NullString{String: f.Score.SuggestedSeverity, Valid: true}

        // Always marshal Applied (empty array if no modifiers fired).
        appliedJSON, err := json.Marshal(f.Score.Applied)
        if err != nil {
            return fmt.Errorf("marshaling score.applied: %w", err)
        }
        scoreApplied = sql.NullString{String: string(appliedJSON), Valid: true}
    }

    _, err = s.e.Exec(
        `INSERT OR IGNORE INTO findings (structural_id, rule_id, groups_json, score_final, score_base, score_suggested_severity, score_applied_json) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        f.ID, f.RuleID, groupsJSON,
        scoreFinal, scoreBase, scoreSeverity, scoreApplied,
    )
    return err
}
```

Now modify `GetFindings` (lines 145-167) to scan the new columns:
```go
func (s *SQLiteStore) GetFindings() ([]*types.Finding, error) {
    rows, err := s.e.Query("SELECT structural_id, rule_id, groups_json, score_final, score_base, score_suggested_severity, score_applied_json FROM findings")
    if err != nil {
        return nil, err
    }
    defer func() { _ = rows.Close() }()
    var result []*types.Finding
    for rows.Next() {
        var f types.Finding
        var groupsJSON, scoreSeverity, scoreApplied sql.NullString
        var scoreFinal, scoreBase sql.NullInt64
        if err := rows.Scan(&f.ID, &f.RuleID, &groupsJSON, &scoreFinal, &scoreBase, &scoreSeverity, &scoreApplied); err != nil {
            return nil, err
        }
        if groupsJSON.Valid {
            f.Groups, _ = deserializeGroups(groupsJSON.String)
        }
        if scoreFinal.Valid {
            sc := &types.Score{
                Final:             int(scoreFinal.Int64),
                Base:              int(scoreBase.Int64),
                SuggestedSeverity: scoreSeverity.String,
                Applied:           []types.ScoreModifier{},
            }
            if scoreApplied.Valid && scoreApplied.String != "" {
                _ = json.Unmarshal([]byte(scoreApplied.String), &sc.Applied)
                if sc.Applied == nil {
                    sc.Applied = []types.ScoreModifier{}
                }
            }
            f.Score = sc
        }
        result = append(result, &f)
    }
    if result == nil {
        return []*types.Finding{}, nil
    }
    return result, rows.Err()
}
```

**Step 4: Verify test passes**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/store/ -v`
Expected: all pass, including 2 new score tests

**Step 5: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f pkg/store/sqlite.go pkg/store/sqlite_test.go && git commit -m "feat(store): persist Score on findings through SQLite"
```

**Exit Criteria:**
- [ ] Both new SQLite tests pass
- [ ] All existing SQLite tests still pass (verify: `go test ./pkg/store/ | grep -c FAIL` returns 0)
- [ ] INSERT statement in `AddFinding` has 7 placeholders (verify: `grep -c 'VALUES (?, ?, ?, ?, ?, ?, ?)' pkg/store/sqlite.go` returns 1)

---

## Task 0.7: Update `MemoryStore` finding semantics (no-op, verify only)

**Files:**
- Modify: `pkg/store/memory_test.go` (append test)

MemoryStore stores `*types.Finding` as-is, so the Score pointer is already preserved automatically. We just need a test to lock in this behavior.

**Step 1: Write the test**

Add to `pkg/store/memory_test.go`:
```go
func TestMemoryStore_AddFinding_PreservesScore(t *testing.T) {
    s := NewMemory()
    finding := &types.Finding{
        ID:     "abc",
        RuleID: "np.aws.1",
        Score: &types.Score{
            Final: 85, Base: 60, SuggestedSeverity: "critical",
            Applied: []types.ScoreModifier{},
        },
    }
    if err := s.AddFinding(finding); err != nil {
        t.Fatalf("AddFinding: %v", err)
    }
    findings, err := s.GetFindings()
    if err != nil {
        t.Fatalf("GetFindings: %v", err)
    }
    if len(findings) != 1 {
        t.Fatalf("expected 1 finding, got %d", len(findings))
    }
    if findings[0].Score == nil || findings[0].Score.Final != 85 {
        t.Errorf("Score not preserved through memory store")
    }
}
```

**Step 2: Run test to verify it passes immediately** (memory store already preserves pointer)

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/store/ -run TestMemoryStore_AddFinding_PreservesScore -v`
Expected: PASS (no code change required — the pointer semantics already work)

**Step 3: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f pkg/store/memory_test.go && git commit -m "test(store): verify memory store preserves Score pointer"
```

**Exit Criteria:**
- [ ] `TestMemoryStore_AddFinding_PreservesScore` passes without any code change to memory.go

---

## Task 0.8: Populate Score when creating findings in `runScan`

**Files:**
- Modify: `cmd/titus/scan.go` (lines ~281-288, inside the flush closure)

**Step 1: Write the failing test**

Add to `cmd/titus/scan_test.go` (or create `cmd/titus/scan_score_test.go`):
```go
package main

import (
    "testing"

    "github.com/praetorian-inc/titus/pkg/types"
)

// TestSynthesizeScore_FromRuleBaseScore is a table-driven test for the pure function
// that will live alongside runScan. It's tested here because the integration path
// (runScan end-to-end) requires scaffolding; the pure function captures the logic.
func TestSynthesizeScore_FromRuleBaseScore(t *testing.T) {
    cases := []struct {
        name string
        rule *types.Rule
        want *types.Score
    }{
        {
            name: "critical tier",
            rule: &types.Rule{ID: "np.aws.1", BaseScore: 85},
            want: &types.Score{Final: 85, Base: 85, SuggestedSeverity: "critical", Applied: []types.ScoreModifier{}},
        },
        {
            name: "low tier",
            rule: &types.Rule{ID: "np.linkedin.1", BaseScore: 25},
            want: &types.Score{Final: 25, Base: 25, SuggestedSeverity: "low", Applied: []types.ScoreModifier{}},
        },
        {
            name: "zero base score (unscored rule, legacy)",
            rule: &types.Rule{ID: "np.old.1", BaseScore: 0},
            want: &types.Score{Final: 0, Base: 0, SuggestedSeverity: "info", Applied: []types.ScoreModifier{}},
        },
    }
    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            got := synthesizeBaseScore(c.rule)
            if got.Final != c.want.Final || got.Base != c.want.Base || got.SuggestedSeverity != c.want.SuggestedSeverity {
                t.Errorf("synthesizeBaseScore = %+v, want %+v", got, c.want)
            }
            if got.Applied == nil {
                t.Errorf("Applied must be non-nil (empty slice) for stable JSON")
            }
        })
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus/ -run TestSynthesizeScore`
Expected: FAIL — undefined: synthesizeBaseScore

**Step 3: Implement**

Add helper near the top of `cmd/titus/scan.go` (or in a new file `cmd/titus/scan_score.go` within package main):
```go
// synthesizeBaseScore creates a Score from a rule's BaseScore with no modifiers
// applied. This is the Milestone 1 scoring — the modifier engine lands in M2+.
func synthesizeBaseScore(rule *types.Rule) *types.Score {
    return &types.Score{
        Final:             rule.BaseScore,
        Base:              rule.BaseScore,
        SuggestedSeverity: types.SeverityForScore(rule.BaseScore),
        Applied:           []types.ScoreModifier{},
    }
}
```

Then change the finding-creation block in `runScan` at `cmd/titus/scan.go:281-288` from:
```go
if err := tx.AddFinding(&types.Finding{
    ID:     findingID,
    RuleID: match.RuleID,
    Groups: match.Groups,
}); err != nil {
    return fmt.Errorf("storing finding: %w", err)
}
```
to:
```go
if err := tx.AddFinding(&types.Finding{
    ID:     findingID,
    RuleID: match.RuleID,
    Groups: match.Groups,
    Score:  synthesizeBaseScore(rule),
}); err != nil {
    return fmt.Errorf("storing finding: %w", err)
}
```

Note: `rule` is the variable bound from `ruleMap[match.RuleID]` at line 270.

**Step 4: Verify tests pass**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus/...`
Expected: all pass, new test included

Run: `cd /tmp/titus-ci-fix && GOWORK=off go build ./...`
Expected: exit 0

**Step 5: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f cmd/titus/scan.go cmd/titus/scan_score_test.go && git commit -m "feat(scan): synthesize base Score on finding creation"
```

**Exit Criteria:**
- [ ] `synthesizeBaseScore` function exists (verify: `grep -n 'func synthesizeBaseScore' cmd/titus/scan.go` returns a match)
- [ ] All 3 subtests of `TestSynthesizeScore_FromRuleBaseScore` pass
- [ ] Finding creation in runScan uses `Score: synthesizeBaseScore(rule)` (verify: `grep 'Score:  synthesizeBaseScore' cmd/titus/scan.go` returns 1)

---

## Task 0.9: Integration smoke test — scan produces scored findings

**Files:**
- Create: `cmd/titus/scan_score_integration_test.go`

**Step 1: Write the failing test**

```go
package main

import (
    "path/filepath"
    "testing"

    "github.com/praetorian-inc/titus/pkg/rule"
    "github.com/praetorian-inc/titus/pkg/store"
    "github.com/praetorian-inc/titus/pkg/types"
)

func TestScan_EndToEnd_FindingHasScore(t *testing.T) {
    // This is an integration smoke test: we manually drive the pieces of runScan
    // that are relevant to scoring — we don't invoke cobra / enumerator / matcher.
    // Goal: confirm that when AddFinding is called with a synthesized score,
    // GetFindings returns the score back.

    tmpDir := t.TempDir()
    s, err := store.New(store.Config{Path: filepath.Join(tmpDir, "test.db")})
    if err != nil {
        t.Fatal(err)
    }
    defer func() { _ = s.Close() }()

    // Load a real rule so we have a real BaseScore path (BaseScore may be 0 pre-migration).
    loader := rule.NewLoader()
    rules, err := loader.LoadBuiltinRules()
    if err != nil {
        t.Fatal(err)
    }
    if len(rules) == 0 {
        t.Skip("no builtin rules available")
    }

    r := rules[0]
    if err := s.AddRule(r); err != nil {
        t.Fatal(err)
    }

    finding := &types.Finding{
        ID:     "test-finding-abc",
        RuleID: r.ID,
        Groups: [][]byte{[]byte("synthetic")},
        Score:  synthesizeBaseScore(r),
    }
    if err := s.AddFinding(finding); err != nil {
        t.Fatal(err)
    }

    findings, err := s.GetFindings()
    if err != nil {
        t.Fatal(err)
    }
    if len(findings) != 1 {
        t.Fatalf("expected 1 finding, got %d", len(findings))
    }
    got := findings[0]
    if got.Score == nil {
        t.Fatal("expected Score to be non-nil after round-trip")
    }
    if got.Score.Base != r.BaseScore {
        t.Errorf("Score.Base = %d, want %d", got.Score.Base, r.BaseScore)
    }
    if got.Score.SuggestedSeverity != types.SeverityForScore(r.BaseScore) {
        t.Errorf("Score.SuggestedSeverity = %q, want %q",
            got.Score.SuggestedSeverity, types.SeverityForScore(r.BaseScore))
    }
}
```

**Step 2: Verify test passes**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus/ -run TestScan_EndToEnd_FindingHasScore -v`
Expected: PASS

**Step 3: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f cmd/titus/scan_score_integration_test.go && git commit -m "test(scan): end-to-end smoke test for finding score persistence"
```

**Exit Criteria:**
- [ ] Integration test passes against real SQLite + real loaded rule

---

## Task 0.10: Final Phase 0 verification

**Step 1: Run the entire test suite**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./...`
Expected: All packages pass

**Step 2: Build**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go build ./...`
Expected: exit 0

**Step 3: Verify branch state**

Run: `cd /tmp/titus-ci-fix && git log --oneline design/finding-scoring..HEAD`
Expected: 8 commits (one per task 0.1-0.9), none unexpected

**Exit Criteria:**
- [ ] All tests pass across the entire repo
- [ ] `go build ./...` succeeds
- [ ] Commit history is clean: 8 feature/test commits on `feat/finding-scoring-m1`

## Handoff to Phase 1 and Phase 2

At this point:
- `types.Score` exists and round-trips through SQLite ✅
- `Rule.BaseScore` exists and is parsed from YAML (optional for now) ✅
- Findings get synthesized scores at scan time ✅

Phases 1 (output formats) and 2 (migration tool) can now proceed **in parallel** — they touch different code areas and have no interdependencies.
