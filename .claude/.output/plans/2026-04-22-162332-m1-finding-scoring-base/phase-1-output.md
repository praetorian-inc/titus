<!--
{
  "phase": 1,
  "title": "Output: JSON, SARIF, human report with score",
  "feature": "m1-finding-scoring-base",
  "linear": "LAB-2431",
  "depends_on": [0],
  "parallel_safe_with": [2],
  "tasks": 7
}
-->

# Phase 1 — Output Formats

> Depends on Phase 0. Parallel-safe with Phase 2 (migration tool).

## Entry criteria
- Phase 0 exit criteria met — `types.Score` exists, `Finding.Score` persisted through datastore
- Branch `feat/finding-scoring-m1` is current

## Exit criteria
- [ ] `titus report --format=json` includes `Score` object on every finding
- [ ] `titus report --format=sarif` maps score to `level` band + emits `properties.security-severity` and `properties.titus_score`
- [ ] `titus report --format=human` shows score badge with tier color immediately after the finding header
- [ ] Golden file test confirms JSON schema stability
- [ ] Golden file test confirms SARIF properties shape

---

## Task 1.1: Extend SARIF `Result` struct with properties

**Files:**
- Modify: `pkg/sarif/sarif.go` (lines 58-63 and 158-174)

**Step 1: Write the failing test**

Add to `pkg/sarif/sarif_test.go`:
```go
func TestAddResult_WithScore_EmitsPropertiesAndLevel(t *testing.T) {
    r := NewReport()
    match := &types.Match{
        RuleID:   "np.aws.1",
        RuleName: "AWS API Key",
        Location: types.Location{
            Source: types.SourceLocation{
                Start: types.Position{Line: 10, Column: 5},
                End:   types.Position{Line: 10, Column: 25},
            },
        },
        Snippet: types.Snippet{Matching: []byte("AKIAIOSFODNN7EXAMPLE")},
    }
    score := &types.Score{
        Final:             85,
        Base:              60,
        SuggestedSeverity: "critical",
        Applied:           []types.ScoreModifier{},
    }
    r.AddResultWithScore(match, "/path/to/file.txt", score)

    if len(r.Runs[0].Results) != 1 {
        t.Fatalf("expected 1 result, got %d", len(r.Runs[0].Results))
    }
    res := r.Runs[0].Results[0]

    // score 85 → level "error"
    if res.Level != "error" {
        t.Errorf("Level = %q, want error (score 85)", res.Level)
    }
    if res.Properties == nil {
        t.Fatal("Properties is nil")
    }
    if res.Properties.SecuritySeverity != "8.5" {
        t.Errorf("SecuritySeverity = %q, want 8.5", res.Properties.SecuritySeverity)
    }
    if res.Properties.TitusScore == nil {
        t.Fatal("TitusScore is nil")
    }
    if res.Properties.TitusScore.Final != 85 {
        t.Errorf("TitusScore.Final = %d, want 85", res.Properties.TitusScore.Final)
    }
}

func TestLevelForScore(t *testing.T) {
    cases := []struct {
        score int
        want  string
    }{
        {0, "none"}, {19, "none"},
        {20, "note"}, {39, "note"},
        {40, "warning"}, {59, "warning"},
        {60, "error"}, {99, "error"}, {100, "error"},
    }
    for _, c := range cases {
        if got := LevelForScore(c.score); got != c.want {
            t.Errorf("LevelForScore(%d) = %q, want %q", c.score, got, c.want)
        }
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/sarif/ -run 'TestAddResult_WithScore|TestLevelForScore' -v`
Expected: FAIL — undefined: AddResultWithScore, LevelForScore, Properties.SecuritySeverity

**Step 3: Implement**

Modify `pkg/sarif/sarif.go`. Add after the existing `Result` struct (around line 63):
```go
// ResultProperties holds the SARIF `properties` bag. Emitted under
// `result.properties` in the output JSON.
type ResultProperties struct {
    // SecuritySeverity is a string-encoded float in [0.0, 10.0] — the
    // GitHub Code Scanning convention. Computed as Score.Final / 10.
    SecuritySeverity string `json:"security-severity,omitempty"`
    // TitusScore is the full Score object for consumers that want the breakdown.
    TitusScore *types.Score `json:"titus_score,omitempty"`
}
```

Modify the `Result` struct (line 58-63) to add `Properties`:
```go
type Result struct {
    RuleID     string            `json:"ruleId"`
    Level      string            `json:"level"`
    Message    Message           `json:"message"`
    Locations  []Location        `json:"locations"`
    Properties *ResultProperties `json:"properties,omitempty"`
}
```

Add two new functions at the bottom of the file:
```go
// LevelForScore maps a 0-100 score to a SARIF level enum value.
func LevelForScore(score int) string {
    switch {
    case score < 20:
        return "none"
    case score < 40:
        return "note"
    case score < 60:
        return "warning"
    default:
        return "error"
    }
}

// AddResultWithScore adds a finding result with score metadata. Preferred over
// AddResult when a Score is available — level is band-mapped from score, and
// properties carry the full Score object for downstream consumers.
func (r *Report) AddResultWithScore(match *types.Match, filePath string, score *types.Score) {
    uri := formatFileURI(filePath)

    region := Region{
        StartLine:   match.Location.Source.Start.Line,
        StartColumn: match.Location.Source.Start.Column,
        EndLine:     match.Location.Source.End.Line,
        EndColumn:   match.Location.Source.End.Column,
    }
    if len(match.Snippet.Matching) > 0 {
        region.Snippet = Snippet{Text: string(match.Snippet.Matching)}
    }

    level := "warning"
    var props *ResultProperties
    if score != nil {
        level = LevelForScore(score.Final)
        props = &ResultProperties{
            SecuritySeverity: fmt.Sprintf("%.1f", float64(score.Final)/10.0),
            TitusScore:       score,
        }
    }

    result := Result{
        RuleID:  match.RuleID,
        Level:   level,
        Message: Message{Text: match.RuleName},
        Locations: []Location{{
            PhysicalLocation: PhysicalLocation{
                ArtifactLocation: ArtifactLocation{URI: uri},
                Region:           region,
            },
        }},
        Properties: props,
    }
    r.Runs[0].Results = append(r.Runs[0].Results, result)
}
```

Add `"fmt"` to imports if not already present.

**Step 4: Verify tests pass**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/sarif/ -v`
Expected: all pass, new tests included

**Step 5: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f pkg/sarif/sarif.go pkg/sarif/sarif_test.go && git commit -m "feat(sarif): add Result properties and score-aware AddResultWithScore"
```

**Exit Criteria:**
- [ ] `ResultProperties` type exists (verify: `grep 'type ResultProperties' pkg/sarif/sarif.go` returns 1)
- [ ] `LevelForScore` and `AddResultWithScore` functions exist
- [ ] `Result.Properties *ResultProperties` field added
- [ ] New tests pass; existing SARIF tests still pass

---

## Task 1.2: Route scan SARIF output through score-aware writer

**Files:**
- Modify: `cmd/titus/scan.go` function `outputSARIF` (find via `grep -n 'func outputSARIF' cmd/titus/scan.go`)

**Step 1: Write the failing test**

Add to `cmd/titus/scan_test.go` (or new file `cmd/titus/sarif_score_test.go`):
```go
package main

import (
    "bytes"
    "encoding/json"
    "testing"

    "github.com/praetorian-inc/titus/pkg/sarif"
    "github.com/praetorian-inc/titus/pkg/types"
    "github.com/spf13/cobra"
)

func TestOutputSARIF_IncludesScoreProperties(t *testing.T) {
    // Construct a fake match + finding and route through the SARIF writer
    match := &types.Match{
        RuleID:   "np.aws.1",
        RuleName: "AWS API Key",
        Location: types.Location{
            Source: types.SourceLocation{
                Start: types.Position{Line: 1, Column: 1},
                End:   types.Position{Line: 1, Column: 20},
            },
        },
    }

    score := &types.Score{
        Final:             85,
        Base:              85,
        SuggestedSeverity: "critical",
        Applied:           []types.ScoreModifier{},
    }

    report := sarif.NewReport()
    report.AddResultWithScore(match, "testdata/fake.txt", score)

    var buf bytes.Buffer
    data, err := report.ToJSON()
    if err != nil {
        t.Fatal(err)
    }
    buf.Write(data)

    // Parse and verify
    var parsed map[string]interface{}
    if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
        t.Fatal(err)
    }
    runs := parsed["runs"].([]interface{})
    results := runs[0].(map[string]interface{})["results"].([]interface{})
    if len(results) != 1 {
        t.Fatalf("expected 1 result, got %d", len(results))
    }
    r := results[0].(map[string]interface{})
    if r["level"] != "error" {
        t.Errorf("level = %v, want error", r["level"])
    }
    props := r["properties"].(map[string]interface{})
    if props["security-severity"] != "8.5" {
        t.Errorf("security-severity = %v, want 8.5", props["security-severity"])
    }
    if props["titus_score"] == nil {
        t.Error("titus_score missing")
    }
    _ = cobra.Command{} // keep import
}
```

**Step 2: Verify test passes** (no code change needed since Task 1.1 already added AddResultWithScore)

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus/ -run TestOutputSARIF_IncludesScoreProperties -v`
Expected: PASS

**Step 3: Wire into `outputSARIF` in scan.go**

Locate `outputSARIF` in `cmd/titus/scan.go`. Its current signature takes matches and rules. We need to pass findings (or a finding lookup) so we can get each match's Score from its Finding.

The current `outputSARIF` (around line 467) iterates matches and calls `report.AddResult(match, path)`. Change:
- Build a `findingByID map[string]*types.Finding` from `s.GetFindings()`.
- For each match, compute its finding ID via `types.ComputeFindingID(rule.StructuralID, match.Groups)`.
- Look up the finding's Score and call `report.AddResultWithScore(match, path, finding.Score)` instead of `AddResult`.

Reference diff (conceptual):
```go
// Before:
report.AddResult(match, filePath)

// After:
var score *types.Score
if r, ok := ruleMap[match.RuleID]; ok {
    fid := types.ComputeFindingID(r.StructuralID, match.Groups)
    if f, ok := findingByID[fid]; ok && f.Score != nil {
        score = f.Score
    }
}
report.AddResultWithScore(match, filePath, score)
```

Find the exact location with:
```bash
grep -n 'report.AddResult\|func outputSARIF' cmd/titus/scan.go
```

Then make the edit: load findings up-front in `outputSARIF`, build the `findingByID` map, and replace the `AddResult` call.

**Step 4: Verify**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go build ./... && GOWORK=off go test ./cmd/titus/ -v | head -60`
Expected: build succeeds, tests pass

**Step 5: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f cmd/titus/scan.go cmd/titus/sarif_score_test.go && git commit -m "feat(scan): route SARIF output through score-aware writer"
```

**Exit Criteria:**
- [ ] `outputSARIF` uses `AddResultWithScore` (verify: `grep 'AddResultWithScore' cmd/titus/scan.go` returns 1+ matches)
- [ ] `outputSARIF` builds `findingByID` map before iterating matches
- [ ] SARIF output test passes

---

## Task 1.3: Same SARIF treatment for report command

**Files:**
- Modify: `cmd/titus/report.go` (function `outputReportSARIF` if exists, else extend `outputReportJSON` path — check via grep)

Run: `grep -n 'sarif\|SARIF' cmd/titus/report.go` to see how report currently handles SARIF.

**If report does not already support SARIF output**, implement it symmetrically to the scan path using `AddResultWithScore`. If the current code returns `"SARIF output not yet implemented"` (see design doc note), replace that stub with a real implementation.

**Step 1: Write the failing test**

Add to `cmd/titus/report_test.go`:
```go
func TestOutputReportSARIF_EmitsScore(t *testing.T) {
    // ... similar to Task 1.2 test but via runReport path ...
    // Smoke test: seed a datastore with a finding that has Score, invoke report,
    // capture SARIF output, assert level and properties.
    // Follow pattern of existing report_test.go cases.
}
```

**Step 2-5: Write/verify/commit** — same TDD loop. Commit message: `feat(report): add score-aware SARIF output`.

**Exit Criteria:**
- [ ] `titus report --format=sarif` no longer returns "not yet implemented" (verify: `grep -c 'SARIF output not yet implemented' cmd/titus/report.go` returns 0)
- [ ] Report SARIF output contains `properties.titus_score` for findings with Score

---

## Task 1.4: JSON scan output stays as-is (documentation change only)

**Files:**
- Modify: `cmd/titus/scan.go` — add comment above `outputMatches`

**Step 1: No test needed (pure comment change)**

**Step 2: Edit**

Above `func outputMatches` (at `cmd/titus/scan.go:1137`), add:
```go
// outputMatches emits the scan's raw matches as JSON for `titus scan --format=json`.
// This is NOT the score-bearing output — findings (with their Score) are persisted
// in the datastore and surfaced via `titus report --format=json`. Downstream
// consumers (Chariot, CI) that need severity should use the report output.
```

**Step 3: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f cmd/titus/scan.go && git commit -m "docs(scan): clarify that JSON scan output is matches not findings"
```

**Exit Criteria:**
- [ ] Comment documents the score-consumer path via `titus report`

---

## Task 1.5: Report JSON output emits Score via Finding struct

**Files:**
- Already works — `outputReportJSON` at `cmd/titus/report.go:572-584` encodes findings directly. Adding `Score *Score` to `Finding` (Phase 0 Task 0.3) means JSON encoder emits it automatically.

**Verification only — no code change required.**

**Step 1: Write a golden-file test**

Create `cmd/titus/testdata/golden/score_json.golden.json`:
```json
[
  {
    "ID": "test-finding-abc",
    "RuleID": "np.test.1",
    "Groups": [
      "eDF4Mng="
    ],
    "Matches": null,
    "Score": {
      "Final": 75,
      "Base": 75,
      "SuggestedSeverity": "high",
      "Applied": []
    }
  }
]
```

Add test in `cmd/titus/report_test.go`:
```go
func TestReport_JSON_ScoreRoundTrip_Golden(t *testing.T) {
    // Seed a datastore with a single finding carrying a known Score,
    // run outputReportJSON, compare against golden file.

    tmpDir := t.TempDir()
    s, err := store.New(store.Config{Path: filepath.Join(tmpDir, "test.db")})
    if err != nil {
        t.Fatal(err)
    }
    defer func() { _ = s.Close() }()

    rule := &types.Rule{ID: "np.test.1", Name: "Test", Pattern: "x"}
    rule.StructuralID = rule.ComputeStructuralID()
    if err := s.AddRule(rule); err != nil {
        t.Fatal(err)
    }

    finding := &types.Finding{
        ID:     "test-finding-abc",
        RuleID: "np.test.1",
        Groups: [][]byte{[]byte("x1x2x")},
        Score: &types.Score{
            Final:             75,
            Base:              75,
            SuggestedSeverity: "high",
            Applied:           []types.ScoreModifier{},
        },
    }
    if err := s.AddFinding(finding); err != nil {
        t.Fatal(err)
    }

    findings, _ := s.GetFindings()
    matches, _ := s.GetAllMatches()
    ruleMap := map[string]*types.Rule{"np.test.1": rule}

    cmd := &cobra.Command{}
    var buf bytes.Buffer
    cmd.SetOut(&buf)
    if err := outputReportJSON(cmd, findings, matches, ruleMap); err != nil {
        t.Fatal(err)
    }

    goldenPath := "testdata/golden/score_json.golden.json"
    wantBytes, err := os.ReadFile(goldenPath)
    if err != nil {
        if os.Getenv("UPDATE_GOLDEN") != "" {
            _ = os.WriteFile(goldenPath, buf.Bytes(), 0644)
            t.Skip("wrote golden file, rerun without UPDATE_GOLDEN")
        }
        t.Fatalf("golden file not found: %v", err)
    }

    if !bytes.Equal(bytes.TrimSpace(buf.Bytes()), bytes.TrimSpace(wantBytes)) {
        t.Errorf("JSON output mismatch\n got: %s\nwant: %s\n(regenerate with UPDATE_GOLDEN=1)",
            buf.String(), string(wantBytes))
    }
}
```

**Step 2: Run test**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus/ -run TestReport_JSON_ScoreRoundTrip_Golden -v`

First run: may fail if golden file doesn't exist. Regenerate with `UPDATE_GOLDEN=1 go test ...`. Then verify the golden content manually matches what's documented above.

Second run: should PASS.

**Step 3: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f cmd/titus/report_test.go cmd/titus/testdata/golden/score_json.golden.json && git commit -m "test(report): golden-file test for JSON score schema stability"
```

**Exit Criteria:**
- [ ] Golden file exists at `cmd/titus/testdata/golden/score_json.golden.json`
- [ ] Test passes on a second run (no `UPDATE_GOLDEN`)

---

## Task 1.6: Human report shows score badge

**Files:**
- Modify: `cmd/titus/report.go` at lines ~624-630 (finding header render)

**Step 1: Write the failing test**

Add to `cmd/titus/report_test.go`:
```go
func TestOutputReportHuman_ShowsScoreBadge(t *testing.T) {
    tmpDir := t.TempDir()
    s, err := store.New(store.Config{Path: filepath.Join(tmpDir, "test.db")})
    if err != nil {
        t.Fatal(err)
    }
    defer func() { _ = s.Close() }()

    rule := &types.Rule{ID: "np.test.1", Name: "Test", Pattern: "x"}
    rule.StructuralID = rule.ComputeStructuralID()
    _ = s.AddRule(rule)

    finding := &types.Finding{
        ID:     "f1",
        RuleID: "np.test.1",
        Score: &types.Score{
            Final: 85, Base: 85, SuggestedSeverity: "critical",
            Applied: []types.ScoreModifier{},
        },
    }
    _ = s.AddFinding(finding)

    findings, _ := s.GetFindings()
    matches, _ := s.GetAllMatches()
    ruleMap := map[string]*types.Rule{"np.test.1": rule}

    // Disable color for stable output
    reportColor = "never"

    cmd := &cobra.Command{}
    var buf bytes.Buffer
    cmd.SetOut(&buf)
    if err := outputReportHuman(cmd, findings, matches, filepath.Join(tmpDir, "test.db"), ruleMap); err != nil {
        t.Fatal(err)
    }

    output := buf.String()
    if !strings.Contains(output, "Score:") {
        t.Errorf("expected 'Score:' in output, got:\n%s", output)
    }
    if !strings.Contains(output, "85/100") {
        t.Errorf("expected '85/100' in output")
    }
    if !strings.Contains(output, "critical") {
        t.Errorf("expected 'critical' severity in output")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus/ -run TestOutputReportHuman_ShowsScoreBadge -v`
Expected: FAIL — output does not contain "Score:"

**Step 3: Implement**

In `cmd/titus/report.go` — inside the `outputReportHuman` function's finding loop (around line 624), after:
```go
_, _ = fmt.Fprintf(out, "%s (%s %s)\n",
    s.findingHeading.Sprintf("Finding %d/%d", i+1, totalFindings),
    s.heading.Sprint("id"),
    s.id.Sprint(f.ID))
```

Insert:
```go
// Score badge
if f.Score != nil {
    severityColor := s.heading // default
    switch f.Score.SuggestedSeverity {
    case "critical":
        severityColor = color.New(color.FgHiRed, color.Bold)
        if color.NoColor {
            severityColor.DisableColor()
        }
    case "high":
        severityColor = color.New(color.FgHiYellow, color.Bold)
        if color.NoColor {
            severityColor.DisableColor()
        }
    case "medium":
        severityColor = color.New(color.FgHiBlue)
        if color.NoColor {
            severityColor.DisableColor()
        }
    case "low", "info":
        severityColor = color.New(color.Faint)
        if color.NoColor {
            severityColor.DisableColor()
        }
    }
    _, _ = fmt.Fprintf(out, "%s %d/100 (%s)\n",
        s.heading.Sprint("Score:"),
        f.Score.Final,
        severityColor.Sprint(f.Score.SuggestedSeverity))
}
```

**Step 4: Verify**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus/ -run TestOutputReportHuman_ShowsScoreBadge -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f cmd/titus/report.go cmd/titus/report_test.go && git commit -m "feat(report): show score badge in human output"
```

**Exit Criteria:**
- [ ] Human output contains `Score: N/100 (tier)` for each finding with a Score
- [ ] Test `TestOutputReportHuman_ShowsScoreBadge` passes

---

## Task 1.7: Phase 1 final verification

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./...`
Expected: all pass

Run: `cd /tmp/titus-ci-fix && GOWORK=off go build ./...`
Expected: exit 0

**Exit Criteria:**
- [ ] All Phase 1 tests pass
- [ ] No regressions in Phase 0 tests
- [ ] Commit history is clean (6 commits from Phase 1 tasks 1.1-1.6)

## Handoff

Phase 1 is complete. Phase 4 (enforcement tests) depends on Phase 3 (research campaign), which depends on Phase 2 (migration tool). Phase 2 can have been running in parallel — merge in before starting Phase 3.
