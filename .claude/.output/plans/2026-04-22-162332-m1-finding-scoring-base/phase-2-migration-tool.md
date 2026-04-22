<!--
{
  "phase": 2,
  "title": "Migration tool: cmd/titus-migrate-scores",
  "feature": "m1-finding-scoring-base",
  "linear": "LAB-2431",
  "depends_on": [0],
  "parallel_safe_with": [1],
  "tasks": 5
}
-->

# Phase 2 — Migration Tool

> Depends on Phase 0. Parallel-safe with Phase 1.

A command-line tool that takes a CSV of `(rule_id, base_score)` tuples (produced by the Phase 3 research campaign) and inserts `base_score: N` into each rule's YAML file. The tool preserves YAML formatting and is idempotent.

## Entry criteria
- Phase 0 exit criteria met
- Branch `feat/finding-scoring-m1` has Phase 0 commits

## Exit criteria
- [ ] `cmd/titus-migrate-scores/main.go` exists and compiles
- [ ] `go run ./cmd/titus-migrate-scores -scores scores.csv -rules pkg/rule/rules/ -apply` updates every referenced rule YAML in-place
- [ ] Dry-run mode (`-apply=false`) prints diff without modifying files
- [ ] Tool is idempotent: running twice produces no-op on second run
- [ ] Tool verifies every rule referenced in CSV exists in the rules directory
- [ ] Tool flags unscored rules (rules in directory but missing from CSV)

---

## Task 2.1: Scaffold `cmd/titus-migrate-scores` + CSV parser

**Files:**
- Create: `cmd/titus-migrate-scores/main.go`
- Create: `cmd/titus-migrate-scores/main_test.go`

**Step 1: Write the failing test**

File: `cmd/titus-migrate-scores/main_test.go`
```go
package main

import (
    "os"
    "path/filepath"
    "testing"
)

func TestParseScoreCSV_Valid(t *testing.T) {
    tmp := t.TempDir()
    csvPath := filepath.Join(tmp, "scores.csv")
    content := `rule_id,base_score,tier,reasoning
np.aws.1,85,critical,"AWS keys can cost significant money"
np.linkedin.1,25,low,"Limited to one user's profile"
`
    if err := os.WriteFile(csvPath, []byte(content), 0644); err != nil {
        t.Fatal(err)
    }
    scores, err := parseScoreCSV(csvPath)
    if err != nil {
        t.Fatalf("parseScoreCSV: %v", err)
    }
    if len(scores) != 2 {
        t.Fatalf("expected 2 entries, got %d", len(scores))
    }
    if scores["np.aws.1"].BaseScore != 85 {
        t.Errorf("np.aws.1 = %d, want 85", scores["np.aws.1"].BaseScore)
    }
    if scores["np.linkedin.1"].Tier != "low" {
        t.Errorf("tier = %q, want low", scores["np.linkedin.1"].Tier)
    }
}

func TestParseScoreCSV_InvalidScore(t *testing.T) {
    tmp := t.TempDir()
    csvPath := filepath.Join(tmp, "scores.csv")
    content := `rule_id,base_score,tier,reasoning
np.test.1,150,critical,"Out of range"
`
    if err := os.WriteFile(csvPath, []byte(content), 0644); err != nil {
        t.Fatal(err)
    }
    _, err := parseScoreCSV(csvPath)
    if err == nil {
        t.Error("expected error for score 150, got nil")
    }
}

func TestParseScoreCSV_MissingRuleID(t *testing.T) {
    tmp := t.TempDir()
    csvPath := filepath.Join(tmp, "scores.csv")
    content := `rule_id,base_score,tier,reasoning
,50,medium,"No rule ID"
`
    if err := os.WriteFile(csvPath, []byte(content), 0644); err != nil {
        t.Fatal(err)
    }
    _, err := parseScoreCSV(csvPath)
    if err == nil {
        t.Error("expected error for missing rule_id, got nil")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus-migrate-scores/ -run TestParseScoreCSV -v`
Expected: FAIL — cannot find package (no main.go yet)

**Step 3: Implement**

File: `cmd/titus-migrate-scores/main.go`
```go
// Command titus-migrate-scores applies researched base_score values to rule YAMLs.
//
// Input: a CSV file with header "rule_id,base_score,tier,reasoning" produced
// by the Phase 3 research campaign. For each row, the tool locates the
// referenced rule's YAML file and inserts `base_score: N` into the rule block.
//
// Usage:
//
//    titus-migrate-scores -scores scores.csv -rules pkg/rule/rules/ -apply
//
// Flags:
//
//    -scores PATH      path to CSV file with scores (required)
//    -rules PATH       path to rules directory (default: pkg/rule/rules)
//    -apply            apply changes (default: false = dry-run / diff output)
//    -allow-missing    do not error when rules are missing from CSV
package main

import (
    "encoding/csv"
    "flag"
    "fmt"
    "io"
    "os"
    "strconv"
    "strings"
)

type ScoreEntry struct {
    RuleID    string
    BaseScore int
    Tier      string
    Reasoning string
}

func parseScoreCSV(path string) (map[string]ScoreEntry, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, fmt.Errorf("opening scores csv: %w", err)
    }
    defer func() { _ = f.Close() }()

    reader := csv.NewReader(f)
    reader.FieldsPerRecord = -1 // allow trailing fields

    // Read header
    header, err := reader.Read()
    if err != nil {
        return nil, fmt.Errorf("reading header: %w", err)
    }
    if len(header) < 2 || header[0] != "rule_id" || header[1] != "base_score" {
        return nil, fmt.Errorf("expected header 'rule_id,base_score,...' got %v", header)
    }

    result := map[string]ScoreEntry{}
    row := 1
    for {
        record, err := reader.Read()
        if err == io.EOF {
            break
        }
        if err != nil {
            return nil, fmt.Errorf("row %d: %w", row, err)
        }
        row++
        if len(record) < 2 {
            return nil, fmt.Errorf("row %d: expected at least 2 columns, got %d", row, len(record))
        }
        ruleID := strings.TrimSpace(record[0])
        if ruleID == "" {
            return nil, fmt.Errorf("row %d: empty rule_id", row)
        }
        score, err := strconv.Atoi(strings.TrimSpace(record[1]))
        if err != nil {
            return nil, fmt.Errorf("row %d rule %q: parsing base_score %q: %w", row, ruleID, record[1], err)
        }
        if score < 0 || score > 100 {
            return nil, fmt.Errorf("row %d rule %q: base_score %d out of range [0,100]", row, ruleID, score)
        }
        entry := ScoreEntry{RuleID: ruleID, BaseScore: score}
        if len(record) >= 3 {
            entry.Tier = strings.TrimSpace(record[2])
        }
        if len(record) >= 4 {
            entry.Reasoning = record[3]
        }
        if _, dup := result[ruleID]; dup {
            return nil, fmt.Errorf("row %d rule %q: duplicate entry", row, ruleID)
        }
        result[ruleID] = entry
    }
    return result, nil
}

func main() {
    scoresPath := flag.String("scores", "", "path to CSV file with scores (required)")
    rulesPath := flag.String("rules", "pkg/rule/rules", "path to rules directory")
    apply := flag.Bool("apply", false, "apply changes (default: dry-run)")
    allowMissing := flag.Bool("allow-missing", false, "do not error on rules missing from CSV")
    flag.Parse()

    if *scoresPath == "" {
        fmt.Fprintln(os.Stderr, "error: -scores is required")
        flag.Usage()
        os.Exit(2)
    }

    scores, err := parseScoreCSV(*scoresPath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "error: %v\n", err)
        os.Exit(1)
    }

    changes, missing, err := applyScoresToRules(*rulesPath, scores, *apply)
    if err != nil {
        fmt.Fprintf(os.Stderr, "error: %v\n", err)
        os.Exit(1)
    }
    _ = changes

    if len(missing) > 0 {
        fmt.Fprintf(os.Stderr, "\n%d rules missing from scores CSV:\n", len(missing))
        for _, m := range missing {
            fmt.Fprintf(os.Stderr, "  - %s\n", m)
        }
        if !*allowMissing {
            os.Exit(1)
        }
    }

    if *apply {
        fmt.Fprintln(os.Stderr, "Changes applied.")
    } else {
        fmt.Fprintln(os.Stderr, "Dry run complete. Re-run with -apply to write changes.")
    }
}

// applyScoresToRules is implemented in Task 2.2.
func applyScoresToRules(rulesDir string, scores map[string]ScoreEntry, apply bool) (int, []string, error) {
    // Stub — Task 2.2 implements this.
    return 0, nil, fmt.Errorf("applyScoresToRules not yet implemented")
}
```

**Step 4: Verify tests pass**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus-migrate-scores/ -run TestParseScoreCSV -v`
Expected: all 3 parse tests pass

**Step 5: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f cmd/titus-migrate-scores/ && git commit -m "feat(migrate-scores): scaffold tool and CSV parser"
```

**Exit Criteria:**
- [ ] `cmd/titus-migrate-scores/main.go` exists with `parseScoreCSV` function
- [ ] 3 parseScoreCSV tests pass
- [ ] `go build ./cmd/titus-migrate-scores/` succeeds

---

## Task 2.2: Implement `applyScoresToRules` — YAML rewrite

**Files:**
- Create: `cmd/titus-migrate-scores/apply.go`
- Create: `cmd/titus-migrate-scores/apply_test.go`

**Step 1: Write the failing test**

File: `cmd/titus-migrate-scores/apply_test.go`
```go
package main

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestApplyScoresToRules_InsertsAfterID(t *testing.T) {
    tmp := t.TempDir()
    yamlPath := filepath.Join(tmp, "test.yml")
    content := `rules:

- name: Test Rule
  id: np.test.1

  pattern: 'foo'

  references:
  - https://example.com

  categories:
  - api
`
    if err := os.WriteFile(yamlPath, []byte(content), 0644); err != nil {
        t.Fatal(err)
    }

    scores := map[string]ScoreEntry{
        "np.test.1": {RuleID: "np.test.1", BaseScore: 75, Tier: "high"},
    }
    changed, missing, err := applyScoresToRules(tmp, scores, true)
    if err != nil {
        t.Fatal(err)
    }
    if changed != 1 {
        t.Errorf("expected 1 change, got %d", changed)
    }
    if len(missing) != 0 {
        t.Errorf("expected 0 missing, got %v", missing)
    }

    got, err := os.ReadFile(yamlPath)
    if err != nil {
        t.Fatal(err)
    }
    gotStr := string(got)
    if !strings.Contains(gotStr, "base_score: 75") {
        t.Errorf("expected 'base_score: 75' in output, got:\n%s", gotStr)
    }
    // base_score must appear AFTER id line
    idIdx := strings.Index(gotStr, "id: np.test.1")
    scoreIdx := strings.Index(gotStr, "base_score: 75")
    if scoreIdx < idIdx {
        t.Errorf("base_score appears before id line in output:\n%s", gotStr)
    }
}

func TestApplyScoresToRules_Idempotent(t *testing.T) {
    tmp := t.TempDir()
    yamlPath := filepath.Join(tmp, "test.yml")
    content := `rules:

- name: Test
  id: np.test.1
  base_score: 60
  pattern: 'foo'
`
    if err := os.WriteFile(yamlPath, []byte(content), 0644); err != nil {
        t.Fatal(err)
    }

    scores := map[string]ScoreEntry{"np.test.1": {RuleID: "np.test.1", BaseScore: 60}}
    changed1, _, err := applyScoresToRules(tmp, scores, true)
    if err != nil {
        t.Fatal(err)
    }
    if changed1 != 0 {
        t.Errorf("first run: expected 0 changes (already correct), got %d", changed1)
    }

    // Second run should also be no-op
    changed2, _, err := applyScoresToRules(tmp, scores, true)
    if err != nil {
        t.Fatal(err)
    }
    if changed2 != 0 {
        t.Errorf("second run: expected 0 changes, got %d", changed2)
    }
}

func TestApplyScoresToRules_UpdateExisting(t *testing.T) {
    tmp := t.TempDir()
    yamlPath := filepath.Join(tmp, "test.yml")
    content := `rules:

- name: Test
  id: np.test.1
  base_score: 50
  pattern: 'foo'
`
    if err := os.WriteFile(yamlPath, []byte(content), 0644); err != nil {
        t.Fatal(err)
    }

    // Update to 75
    scores := map[string]ScoreEntry{"np.test.1": {RuleID: "np.test.1", BaseScore: 75}}
    changed, _, err := applyScoresToRules(tmp, scores, true)
    if err != nil {
        t.Fatal(err)
    }
    if changed != 1 {
        t.Errorf("expected 1 change, got %d", changed)
    }

    got, _ := os.ReadFile(yamlPath)
    if !strings.Contains(string(got), "base_score: 75") {
        t.Errorf("expected updated to 75, got:\n%s", string(got))
    }
    if strings.Contains(string(got), "base_score: 50") {
        t.Errorf("old value 50 still present:\n%s", string(got))
    }
}

func TestApplyScoresToRules_ReportsMissing(t *testing.T) {
    tmp := t.TempDir()
    yamlPath := filepath.Join(tmp, "test.yml")
    content := `rules:

- name: Test
  id: np.test.1
  pattern: 'foo'

- name: Test2
  id: np.test.2
  pattern: 'bar'
`
    if err := os.WriteFile(yamlPath, []byte(content), 0644); err != nil {
        t.Fatal(err)
    }

    // Only score np.test.1 — np.test.2 should be reported as missing
    scores := map[string]ScoreEntry{"np.test.1": {RuleID: "np.test.1", BaseScore: 75}}
    _, missing, err := applyScoresToRules(tmp, scores, true)
    if err != nil {
        t.Fatal(err)
    }
    found := false
    for _, m := range missing {
        if m == "np.test.2" {
            found = true
            break
        }
    }
    if !found {
        t.Errorf("expected np.test.2 in missing list, got %v", missing)
    }
}

func TestApplyScoresToRules_DryRun(t *testing.T) {
    tmp := t.TempDir()
    yamlPath := filepath.Join(tmp, "test.yml")
    content := `rules:

- name: Test
  id: np.test.1
  pattern: 'foo'
`
    if err := os.WriteFile(yamlPath, []byte(content), 0644); err != nil {
        t.Fatal(err)
    }

    scores := map[string]ScoreEntry{"np.test.1": {RuleID: "np.test.1", BaseScore: 75}}
    changed, _, err := applyScoresToRules(tmp, scores, false) // apply=false
    if err != nil {
        t.Fatal(err)
    }
    if changed != 1 {
        t.Errorf("expected 1 reported change, got %d", changed)
    }

    // File must not be modified
    got, _ := os.ReadFile(yamlPath)
    if strings.Contains(string(got), "base_score") {
        t.Errorf("dry run modified file:\n%s", string(got))
    }
}
```

**Step 2: Run tests — should all fail**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus-migrate-scores/ -run TestApplyScoresToRules -v`
Expected: FAIL (stub returns error)

**Step 3: Implement**

File: `cmd/titus-migrate-scores/apply.go`

This uses a regex/line-based approach rather than round-tripping through a YAML library, to preserve existing comments, indentation, and formatting. The approach:

1. Walk the rules directory for `*.yml` files.
2. For each file, scan lines to identify rule blocks (each starting with `- name:` at column 0 or 2).
3. Within a rule block, find the `id:` line.
4. Check if a `base_score:` line already exists in the block.
5. If yes and value matches, no-op. If yes and value differs, replace. If no, insert after `id:` line.

```go
package main

import (
    "bufio"
    "bytes"
    "fmt"
    "io/fs"
    "os"
    "path/filepath"
    "regexp"
    "strings"
)

// ruleBlock represents the byte range of a single rule entry in a YAML file.
type ruleBlock struct {
    start int // line number (1-indexed) of "- name:" or "- id:"
    end   int // line number (inclusive) of last line of this rule
    id    string
}

var (
    // idLineRe matches "id: np.xxx" or "  id: np.xxx" with any leading whitespace.
    idLineRe = regexp.MustCompile(`^(\s*)id:\s*([a-zA-Z0-9._-]+)\s*$`)
    // baseScoreRe matches an existing "base_score: N" line.
    baseScoreRe = regexp.MustCompile(`^(\s*)base_score:\s*(\d+)\s*$`)
    // ruleStartRe matches the first line of a new rule: "- name:" or "- id:"
    ruleStartRe = regexp.MustCompile(`^(\s*)- (name|id):`)
)

// applyScoresToRules walks rulesDir, applies scores to matching rules, and
// returns (numChanged, missingRuleIDs, error). In dry-run mode (apply=false),
// no files are written but numChanged still reflects what would change.
func applyScoresToRules(rulesDir string, scores map[string]ScoreEntry, apply bool) (int, []string, error) {
    seen := map[string]bool{}
    totalChanged := 0

    err := filepath.WalkDir(rulesDir, func(path string, d fs.DirEntry, err error) error {
        if err != nil {
            return err
        }
        if d.IsDir() || filepath.Ext(path) != ".yml" {
            return nil
        }
        changed, err := applyToFile(path, scores, seen, apply)
        if err != nil {
            return fmt.Errorf("%s: %w", path, err)
        }
        totalChanged += changed
        return nil
    })
    if err != nil {
        return 0, nil, err
    }

    var missing []string
    for id := range scores {
        if !seen[id] {
            missing = append(missing, id)
        }
    }
    return totalChanged, missing, nil
}

func applyToFile(path string, scores map[string]ScoreEntry, seen map[string]bool, apply bool) (int, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return 0, err
    }

    // Parse into lines so we can reassemble with modifications.
    scanner := bufio.NewScanner(bytes.NewReader(data))
    scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
    var lines []string
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
    }
    if err := scanner.Err(); err != nil {
        return 0, err
    }

    // Pass 1: identify rule blocks (start line = "- name:" or "- id:" with 0 or 2 space indent)
    var blocks []ruleBlock
    var current *ruleBlock
    for i, line := range lines {
        if ruleStartRe.MatchString(line) {
            if current != nil {
                current.end = i - 1
                blocks = append(blocks, *current)
            }
            current = &ruleBlock{start: i, end: len(lines) - 1}
        }
        if current != nil && current.id == "" {
            if m := idLineRe.FindStringSubmatch(line); m != nil {
                current.id = m[2]
            }
        }
    }
    if current != nil {
        blocks = append(blocks, *current)
    }

    // Pass 2: for each block with an id in scores, insert or update base_score
    // We build a new lines slice, processing blocks in reverse so indices don't shift.
    changed := 0
    for i := len(blocks) - 1; i >= 0; i-- {
        b := blocks[i]
        entry, ok := scores[b.id]
        if !ok {
            continue
        }
        seen[b.id] = true

        // Look for existing base_score line within [b.start, b.end]
        existingIdx := -1
        var existingIndent string
        var existingValue int
        for j := b.start; j <= b.end; j++ {
            if m := baseScoreRe.FindStringSubmatch(lines[j]); m != nil {
                existingIdx = j
                existingIndent = m[1]
                existingValue, _ = strconv.Atoi(m[2])
                break
            }
        }

        if existingIdx >= 0 {
            if existingValue == entry.BaseScore {
                continue // idempotent
            }
            newLine := fmt.Sprintf("%sbase_score: %d", existingIndent, entry.BaseScore)
            lines[existingIdx] = newLine
            changed++
            continue
        }

        // No existing base_score — find the id line within the block and insert after
        idLineIdx := -1
        var idIndent string
        for j := b.start; j <= b.end; j++ {
            if m := idLineRe.FindStringSubmatch(lines[j]); m != nil {
                idLineIdx = j
                idIndent = m[1]
                break
            }
        }
        if idLineIdx < 0 {
            // Shouldn't happen — blocks were identified by having an id
            continue
        }

        newLine := fmt.Sprintf("%sbase_score: %d", idIndent, entry.BaseScore)
        newLines := make([]string, 0, len(lines)+1)
        newLines = append(newLines, lines[:idLineIdx+1]...)
        newLines = append(newLines, newLine)
        newLines = append(newLines, lines[idLineIdx+1:]...)
        lines = newLines
        changed++
    }

    if changed > 0 && apply {
        // Reassemble and write
        output := strings.Join(lines, "\n")
        // Preserve trailing newline if original had one
        if bytes.HasSuffix(data, []byte("\n")) && !strings.HasSuffix(output, "\n") {
            output += "\n"
        }
        if err := os.WriteFile(path, []byte(output), 0644); err != nil {
            return 0, err
        }
    }
    return changed, nil
}
```

Add `"strconv"` to imports.

**Step 4: Verify tests pass**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus-migrate-scores/ -v`
Expected: all 5 apply tests pass, plus the 3 parse tests

Run: `cd /tmp/titus-ci-fix && GOWORK=off go build ./cmd/titus-migrate-scores/`
Expected: exit 0

**Step 5: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f cmd/titus-migrate-scores/ && git commit -m "feat(migrate-scores): implement YAML rewrite with idempotency"
```

**Exit Criteria:**
- [ ] All 5 `TestApplyScoresToRules_*` tests pass
- [ ] Tool handles: insert-new, update-existing, idempotent-noop, dry-run, missing-rule-report

---

## Task 2.3: Add Makefile targets for the migration tool

**Files:**
- Modify: `Makefile` (add near other `build-*` targets)

**Step 1: Edit**

Add to `Makefile` after existing `build` target:
```makefile
# Build the score migration tool
build-migrate-scores:
	GOWORK=off CGO_ENABLED=0 go build -o dist/titus-migrate-scores ./cmd/titus-migrate-scores

# Run migration tool in dry-run mode (safe)
migrate-scores-dryrun: build-migrate-scores
	./dist/titus-migrate-scores -scores scores.csv -rules pkg/rule/rules/

# Apply score migration (writes to rule YAMLs)
migrate-scores-apply: build-migrate-scores
	./dist/titus-migrate-scores -scores scores.csv -rules pkg/rule/rules/ -apply
```

Also add `build-migrate-scores` to the `.PHONY` declaration at the top of the Makefile.

**Step 2: Verify build**

Run: `cd /tmp/titus-ci-fix && make build-migrate-scores`
Expected: creates `dist/titus-migrate-scores` binary

**Step 3: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f Makefile && git commit -m "build(migrate-scores): add Makefile targets for migration tool"
```

**Exit Criteria:**
- [ ] `make build-migrate-scores` produces a working binary
- [ ] `.PHONY` list includes `build-migrate-scores migrate-scores-dryrun migrate-scores-apply`

---

## Task 2.4: Smoke test against real rule YAML

**Files:**
- Create: `cmd/titus-migrate-scores/smoke_test.go`

**Step 1: Write the test**

```go
package main

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

// TestApplyScoresToRules_SmokeAgainstRealRules uses the actual project rules
// directory as a read-only source, copies one file to a temp dir, and applies
// a score. This catches formatting oddities present in real rules that wouldn't
// surface in synthetic tests.
func TestApplyScoresToRules_SmokeAgainstRealRules(t *testing.T) {
    realRulesDir := "../../pkg/rule/rules"
    if _, err := os.Stat(realRulesDir); os.IsNotExist(err) {
        t.Skip("real rules directory not found — test assumes go test is run from cmd/titus-migrate-scores/")
    }

    // Copy aws.yml to a temp dir
    src := filepath.Join(realRulesDir, "aws.yml")
    data, err := os.ReadFile(src)
    if err != nil {
        t.Fatalf("reading %s: %v", src, err)
    }

    tmp := t.TempDir()
    dst := filepath.Join(tmp, "aws.yml")
    if err := os.WriteFile(dst, data, 0644); err != nil {
        t.Fatal(err)
    }

    scores := map[string]ScoreEntry{
        "np.aws.1": {RuleID: "np.aws.1", BaseScore: 60}, // AWS identifier tier
    }
    changed, missing, err := applyScoresToRules(tmp, scores, true)
    if err != nil {
        t.Fatalf("applyScoresToRules: %v", err)
    }

    // It's OK to have other rules in aws.yml be "missing" from our small score map
    t.Logf("changed=%d missing=%d", changed, len(missing))

    got, err := os.ReadFile(dst)
    if err != nil {
        t.Fatal(err)
    }
    if !strings.Contains(string(got), "base_score: 60") {
        t.Errorf("expected base_score: 60 in modified aws.yml")
    }
    if changed == 0 {
        t.Error("expected at least 1 change")
    }
}
```

**Step 2: Run test**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus-migrate-scores/ -run TestApplyScoresToRules_SmokeAgainstRealRules -v`
Expected: PASS (or skip if path doesn't resolve from test working directory — if skip, adjust the relative path)

**Step 3: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f cmd/titus-migrate-scores/smoke_test.go && git commit -m "test(migrate-scores): smoke test against real rule YAML"
```

**Exit Criteria:**
- [ ] Smoke test passes against actual rule YAML

---

## Task 2.5: Phase 2 final verification

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus-migrate-scores/ -v && GOWORK=off go build ./...`
Expected: all tests pass, build succeeds

Sanity check the dry-run against the real rules directory with an empty scores file:

```bash
cd /tmp/titus-ci-fix
echo "rule_id,base_score,tier,reasoning" > /tmp/empty-scores.csv
./dist/titus-migrate-scores -scores /tmp/empty-scores.csv -rules pkg/rule/rules/ -allow-missing
```
Expected: reports ~500 rules as "missing from scores CSV" (every rule in the directory), exits 0 due to `-allow-missing`.

**Exit Criteria:**
- [ ] All Phase 2 tests pass
- [ ] Real rules directory scan reports correct missing count
- [ ] Commit history for Phase 2 is clean (4 commits: 2.1-2.4)

## Handoff

Phase 2 complete. Phase 3 (research campaign) can now begin — it produces the `scores.csv` file that feeds this tool.
