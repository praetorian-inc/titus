<!--
{
  "phase": 4,
  "title": "Loader enforcement, score-lint, test coverage, verification",
  "feature": "m1-finding-scoring-base",
  "linear": "LAB-2431",
  "depends_on": [0, 1, 3],
  "tasks": 8
}
-->

# Phase 4 — Enforcement, Tests, and Verification

> Final phase. Depends on Phases 0, 1, and 3. Activates the loader's hard-fail on missing `base_score`, adds the score-lint tool, builds out the full test suite, and runs final end-to-end verification.

## Entry criteria
- Phase 0 exit criteria met (foundation types + datastore)
- Phase 1 exit criteria met (output formats)
- Phase 3 exit criteria met (every rule has `base_score` in YAML)

## Exit criteria
- [ ] Loader rejects rules missing `base_score` (hard error)
- [ ] `cmd/titus-score-lint/` tool exists, flags missing fields and tier/naming mismatches
- [ ] Makefile `score-lint` target exists and passes
- [ ] All Milestone 1 acceptance tests pass: `TestAllRules_HaveBaseScore`, `TestCriticalTier_RulesExist`, `TestTierBoundaries`, `TestScoreJSON_SchemaStability`
- [ ] Full regression test passes: `go test ./...`
- [ ] Smoke test: `titus scan testdata/secrets/` produces scored findings in all three output formats

---

## Task 4.1: Loader hardens — `base_score` becomes required

**Files:**
- Modify: `pkg/rule/loader.go` — make `convertYAMLRule` return an error
- Modify: `pkg/rule/loader_test.go` — update `TestLoadRule_BaseScoreMissing_PhaseZero` to expect an error now

**Step 1: Write the failing test**

Update `pkg/rule/loader_test.go` — the Phase 0 permissive test must be renamed and inverted:

```go
// DELETE: TestLoadRule_BaseScoreMissing_PhaseZero (was Phase 0 permissive)
// REPLACE WITH:

func TestLoadRule_BaseScoreMissing_Rejected(t *testing.T) {
    loader := NewLoader()
    yaml := `rules:
  - name: Test Rule
    id: np.test.1
    pattern: 'test'
`
    _, err := loader.LoadRule([]byte(yaml))
    if err == nil {
        t.Error("expected error for rule missing base_score, got nil")
    }
    if err != nil && !strings.Contains(err.Error(), "base_score") {
        t.Errorf("error message does not mention base_score: %v", err)
    }
}

func TestLoadRule_BaseScoreOutOfRange(t *testing.T) {
    loader := NewLoader()
    yaml := `rules:
  - name: Test Rule
    id: np.test.1
    pattern: 'test'
    base_score: 150
`
    _, err := loader.LoadRule([]byte(yaml))
    if err == nil {
        t.Error("expected error for base_score 150 (out of range), got nil")
    }
}

func TestLoadRule_BaseScoreNegative(t *testing.T) {
    loader := NewLoader()
    yaml := `rules:
  - name: Test Rule
    id: np.test.1
    pattern: 'test'
    base_score: -5
`
    _, err := loader.LoadRule([]byte(yaml))
    if err == nil {
        t.Error("expected error for negative base_score, got nil")
    }
}

func TestLoadRule_BaseScoreValid(t *testing.T) {
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
```

Add `"strings"` import if not already present.

**Step 2: Run tests to verify they fail**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/rule/ -run TestLoadRule_BaseScore -v`
Expected: new tests FAIL because loader currently accepts missing/out-of-range base_score

**Step 3: Implement loader hardening**

Modify `pkg/rule/loader.go`. Change `convertYAMLRule` signature to return `(*types.Rule, error)`:

```go
// convertYAMLRule converts yamlRule to types.Rule and computes StructuralID.
// Returns an error if required fields (base_score in [0, 100]) are invalid.
func convertYAMLRule(yr yamlRule) (*types.Rule, error) {
    // NOTE: yamlRule.BaseScore defaults to 0. Since 0 is a valid "info-tier"
    // score, we cannot distinguish "unset" from "explicitly 0" purely from
    // the int value. To detect missing-field, switch to *int in yamlRule.
    // That refactor is in the next step — for now, treat 0 as unset.
    if yr.BaseScore < 0 || yr.BaseScore > 100 {
        return nil, fmt.Errorf("rule %s: base_score %d out of range [0, 100]", yr.ID, yr.BaseScore)
    }
    // Defer "missing field" detection to the pointer-type refactor below.
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
    if yr.PatternRequirements != nil {
        r.PatternRequirements = &types.PatternRequirements{
            MinDigits:        yr.PatternRequirements.MinDigits,
            MinUppercase:     yr.PatternRequirements.MinUppercase,
            MinLowercase:     yr.PatternRequirements.MinLowercase,
            MinSpecialChars:  yr.PatternRequirements.MinSpecialChars,
            SpecialChars:     yr.PatternRequirements.SpecialChars,
            IgnoreIfContains: yr.PatternRequirements.IgnoreIfContains,
        }
    }
    r.StructuralID = r.ComputeStructuralID()
    return r, nil
}
```

Now refactor `yamlRule.BaseScore` to `*int` to distinguish "unset" from "0":

Modify `pkg/rule/yaml.go`:
```go
type yamlRule struct {
    // ... existing fields ...
    BaseScore           *int                     `yaml:"base_score"`
}
```

Update `convertYAMLRule` to check the pointer:
```go
func convertYAMLRule(yr yamlRule) (*types.Rule, error) {
    if yr.BaseScore == nil {
        return nil, fmt.Errorf("rule %s: base_score is required", yr.ID)
    }
    score := *yr.BaseScore
    if score < 0 || score > 100 {
        return nil, fmt.Errorf("rule %s: base_score %d out of range [0, 100]", yr.ID, score)
    }
    r := &types.Rule{
        // ... existing fields ...
        BaseScore:        score,
    }
    // ...
    return r, nil
}
```

Propagate the error through `LoadRule`, `LoadBuiltinRules`:

`LoadRule` (line 34-48) — change:
```go
return convertYAMLRule(yamlFile.Rules[0]), nil
```
to:
```go
return convertYAMLRule(yamlFile.Rules[0])
```

`LoadBuiltinRules` (line 87-121) — change:
```go
for _, yr := range yamlFile.Rules {
    rules = append(rules, convertYAMLRule(yr))
}
```
to:
```go
for _, yr := range yamlFile.Rules {
    rule, err := convertYAMLRule(yr)
    if err != nil {
        return fmt.Errorf("loading %s: %w", path, err)
    }
    rules = append(rules, rule)
}
```

**Step 4: Fix Phase 0 permissive test**

Delete `TestLoadRule_BaseScoreMissing_PhaseZero` entirely (replaced by `TestLoadRule_BaseScoreMissing_Rejected` above).

Also update the Phase 0 `TestLoadRule_Valid` test to include `base_score`:
```go
validYAML := `rules:
  - name: AWS API Key
    id: np.aws.1
    pattern: |
      (?x)
      AKIA[A-Z0-9]{16}
    description: AWS access key ID
    base_score: 60
    references:
      - https://docs.aws.amazon.com/...
    ...
`
```
Any existing tests that load synthetic YAML without `base_score` must be updated to include it.

**Step 5: Verify**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/rule/ -v`
Expected: all pass including new Phase 4 tests

Run: `cd /tmp/titus-ci-fix && GOWORK=off go build ./... && GOWORK=off go test ./...`
Expected: full regression passes (all builtin rules now have base_score, so LoadBuiltinRules succeeds)

**Step 6: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f pkg/rule/ && git commit -m "feat(rule): enforce base_score as required field in loader"
```

**Exit Criteria:**
- [ ] Loader rejects missing/out-of-range `base_score` with clear error messages
- [ ] All existing tests pass after being updated to include `base_score: N`
- [ ] `LoadBuiltinRules` still succeeds (all rules have base_score from Phase 3)

---

## Task 4.2: `TestAllRules_HaveBaseScore` invariant test

**Files:**
- Create: `pkg/rule/base_score_test.go`

**Step 1: Write the test**

```go
package rule

import (
    "strings"
    "testing"
)

// TestAllRules_HaveBaseScore verifies every embedded rule has base_score > 0.
// A base_score of 0 is technically "info tier" but is also the Go zero value,
// so we use it as a sentinel for "researcher forgot to score this rule".
func TestAllRules_HaveBaseScore(t *testing.T) {
    loader := NewLoader()
    rules, err := loader.LoadBuiltinRules()
    if err != nil {
        t.Fatalf("LoadBuiltinRules: %v", err)
    }
    if len(rules) == 0 {
        t.Fatal("no rules loaded")
    }

    var missing []string
    for _, r := range rules {
        if r.BaseScore <= 0 {
            missing = append(missing, r.ID)
        }
    }
    if len(missing) > 0 {
        t.Errorf("%d rules have base_score <= 0:\n  %s",
            len(missing), strings.Join(missing, "\n  "))
    }
}

// TestCriticalTier_RulesExist ensures we have at least some critical-tier rules,
// catching accidental mass downgrades.
func TestCriticalTier_RulesExist(t *testing.T) {
    loader := NewLoader()
    rules, err := loader.LoadBuiltinRules()
    if err != nil {
        t.Fatal(err)
    }
    critical := 0
    for _, r := range rules {
        if r.BaseScore >= 80 {
            critical++
        }
    }
    if critical == 0 {
        t.Error("no rules in critical tier (base_score >= 80) — verify tier assignments")
    }
    t.Logf("Critical tier: %d rules", critical)
}

// TestTierBoundaries catches obvious mis-tiering by checking rule names against
// expected tier floors. A rule named "aws.*" or containing "private_key" should
// be at least tier "high" (60+).
func TestTierBoundaries(t *testing.T) {
    loader := NewLoader()
    rules, err := loader.LoadBuiltinRules()
    if err != nil {
        t.Fatal(err)
    }

    type requirement struct {
        idContains string
        minScore   int
        reason     string
    }
    requirements := []requirement{
        {idContains: "np.aws.", minScore: 60, reason: "AWS rules should be high-tier or above"},
        {idContains: "np.pem.", minScore: 80, reason: "PEM private keys are critical-tier"},
        {idContains: "np.stripe.", minScore: 80, reason: "Stripe keys move money"},
    }

    var violations []string
    for _, r := range rules {
        for _, req := range requirements {
            if strings.Contains(r.ID, req.idContains) && r.BaseScore < req.minScore {
                violations = append(violations,
                    r.ID+": base_score="+
                        itoa(r.BaseScore)+
                        " below required "+
                        itoa(req.minScore)+
                        " ("+req.reason+")")
            }
        }
    }
    if len(violations) > 0 {
        t.Errorf("tier boundary violations:\n  %s", strings.Join(violations, "\n  "))
    }
}

func itoa(n int) string {
    // simple int→string to avoid importing strconv for one use
    if n == 0 {
        return "0"
    }
    neg := n < 0
    if neg {
        n = -n
    }
    var buf [20]byte
    i := len(buf)
    for n > 0 {
        i--
        buf[i] = byte('0' + n%10)
        n /= 10
    }
    if neg {
        i--
        buf[i] = '-'
    }
    return string(buf[i:])
}
```

**Step 2: Run tests**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./pkg/rule/ -run 'TestAllRules_HaveBaseScore|TestCriticalTier_RulesExist|TestTierBoundaries' -v`
Expected: all PASS (Phase 3 has scored everything; Phase 4 Task 4.1 has hardened loader)

**Step 3: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f pkg/rule/base_score_test.go && git commit -m "test(rule): invariant tests for rule base_score coverage and tier boundaries"
```

**Exit Criteria:**
- [ ] Three new tests pass

---

## Task 4.3: Score JSON schema-stability golden test

**Files:**
- Already wired in Phase 1 Task 1.5
- This task ensures the golden file matches the final committed form

Re-run the golden test to confirm no drift:
```bash
cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus/ -run TestReport_JSON_ScoreRoundTrip_Golden -v
```
Expected: PASS

If it fails because the JSON field order changed (Go map iteration, e.g.), decide:
- If the change is intentional (schema evolution), update the golden with `UPDATE_GOLDEN=1 go test ...` and commit.
- If not, fix the source to produce stable output.

**Exit Criteria:**
- [ ] Golden test passes on a fresh run

---

## Task 4.4: Build the `titus-score-lint` tool

**Files:**
- Create: `cmd/titus-score-lint/main.go`
- Create: `cmd/titus-score-lint/main_test.go`

**Step 1: Write the test**

```go
package main

import (
    "os"
    "path/filepath"
    "testing"
)

func TestScoreLint_AllRulesValid(t *testing.T) {
    tmp := t.TempDir()
    yaml := `rules:
- name: Good
  id: np.good.1
  pattern: foo
  base_score: 50
`
    if err := os.WriteFile(filepath.Join(tmp, "good.yml"), []byte(yaml), 0644); err != nil {
        t.Fatal(err)
    }
    errs := lintDir(tmp)
    if len(errs) != 0 {
        t.Errorf("expected 0 errors, got: %v", errs)
    }
}

func TestScoreLint_FlagsMissing(t *testing.T) {
    tmp := t.TempDir()
    yaml := `rules:
- name: Missing
  id: np.bad.1
  pattern: foo
`
    if err := os.WriteFile(filepath.Join(tmp, "bad.yml"), []byte(yaml), 0644); err != nil {
        t.Fatal(err)
    }
    errs := lintDir(tmp)
    if len(errs) == 0 {
        t.Error("expected error for missing base_score")
    }
}

func TestScoreLint_FlagsOutOfRange(t *testing.T) {
    tmp := t.TempDir()
    yaml := `rules:
- name: Out of range
  id: np.bad.1
  pattern: foo
  base_score: 250
`
    if err := os.WriteFile(filepath.Join(tmp, "bad.yml"), []byte(yaml), 0644); err != nil {
        t.Fatal(err)
    }
    errs := lintDir(tmp)
    if len(errs) == 0 {
        t.Error("expected error for base_score 250")
    }
}

func TestScoreLint_FlagsNamingTierMismatch(t *testing.T) {
    tmp := t.TempDir()
    yaml := `rules:
- name: AWS Root Key
  id: np.aws.9
  pattern: foo
  base_score: 20
`
    if err := os.WriteFile(filepath.Join(tmp, "bad.yml"), []byte(yaml), 0644); err != nil {
        t.Fatal(err)
    }
    errs := lintDir(tmp)
    found := false
    for _, e := range errs {
        if contains(e, "naming suggests") {
            found = true
            break
        }
    }
    if !found {
        t.Errorf("expected naming-tier mismatch warning, got: %v", errs)
    }
}

func contains(s, sub string) bool {
    for i := 0; i+len(sub) <= len(s); i++ {
        if s[i:i+len(sub)] == sub {
            return true
        }
    }
    return false
}
```

**Step 2: Implement `main.go`**

```go
// Command titus-score-lint validates that every rule YAML under the rules
// directory has a base_score in [0, 100] and flags obvious mis-tierings.
//
// Usage:
//
//    titus-score-lint <rules-dir>
//
// Exits 0 on success, non-zero if any violations are found.
package main

import (
    "fmt"
    "io/fs"
    "os"
    "path/filepath"
    "strings"

    "github.com/praetorian-inc/titus/pkg/rule"
)

// Naming-tier rules: if the rule ID matches a prefix or contains a substring,
// its base_score should be at least the given minimum. These are soft warnings
// (lint level), not hard errors.
type namingRule struct {
    idContains string
    minScore   int
    reason     string
}

var namingRules = []namingRule{
    {idContains: "np.aws.", minScore: 60, reason: "AWS credentials should be tier high or above"},
    {idContains: "np.pem.", minScore: 80, reason: "PEM private keys are tier critical"},
    {idContains: "np.stripe.", minScore: 80, reason: "Stripe keys move money — tier critical"},
    {idContains: "np.gcp.", minScore: 60, reason: "GCP credentials should be tier high or above"},
    {idContains: "np.azure.", minScore: 60, reason: "Azure credentials should be tier high or above"},
}

func lintDir(dir string) []string {
    var errs []string

    loader := rule.NewLoaderWithFS(os.DirFS(dir))
    // Walk files explicitly — NewLoaderWithFS expects the "rules" subdir convention
    err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
        if err != nil {
            errs = append(errs, path+": walk error: "+err.Error())
            return nil
        }
        if d.IsDir() || filepath.Ext(path) != ".yml" {
            return nil
        }
        data, err := os.ReadFile(path)
        if err != nil {
            errs = append(errs, path+": read error: "+err.Error())
            return nil
        }
        // Use loader.LoadRule for single-rule files; for multi-rule, parse each
        r, err := loader.LoadRule(data)
        if err != nil {
            // Multi-rule file — iterate
            // For simplicity in M1, just use the loader's own error message
            errs = append(errs, path+": "+err.Error())
            return nil
        }
        // Check naming-tier rules
        for _, nr := range namingRules {
            if strings.Contains(r.ID, nr.idContains) && r.BaseScore < nr.minScore {
                errs = append(errs, fmt.Sprintf("%s [%s]: base_score=%d — naming suggests minimum %d (%s)",
                    r.ID, path, r.BaseScore, nr.minScore, nr.reason))
            }
        }
        return nil
    })
    _ = loader
    if err != nil {
        errs = append(errs, "walk error: "+err.Error())
    }
    return errs
}

func main() {
    if len(os.Args) != 2 {
        fmt.Fprintln(os.Stderr, "usage: titus-score-lint <rules-dir>")
        os.Exit(2)
    }
    dir := os.Args[1]
    errs := lintDir(dir)
    for _, e := range errs {
        fmt.Fprintln(os.Stderr, e)
    }
    if len(errs) > 0 {
        fmt.Fprintf(os.Stderr, "\n%d violation(s)\n", len(errs))
        os.Exit(1)
    }
    fmt.Println("score-lint: all rules valid")
}
```

**Note:** The multi-rule file case in `lintDir` above uses `loader.LoadRule` which fails for multi-rule files. A production version should iterate rules explicitly using the loader's builtin walker. For this milestone, an acceptable simplification is to use `loader.LoadBuiltinRules()` path-mapped approach. If multi-rule files are common (aws.yml has many), the implementation needs to parse each YAML file's rules array directly.

Refine with:
```go
// Simpler approach: load via builtin path
loader := rule.NewLoaderWithFS(os.DirFS(".")) // using current dir as root
// Actually just parse each YAML manually using yaml.v3 + iterate
```

If this gets complex, defer the multi-rule parsing to a small shim:
```go
type yamlRuleMinimal struct {
    ID        string `yaml:"id"`
    BaseScore *int   `yaml:"base_score"`
}
type yamlRulesFile struct {
    Rules []yamlRuleMinimal `yaml:"rules"`
}
```

**Step 3: Verify tests pass**

Run: `cd /tmp/titus-ci-fix && GOWORK=off go test ./cmd/titus-score-lint/ -v`
Expected: all 4 tests pass

Run real-directory lint:
```bash
cd /tmp/titus-ci-fix && go run ./cmd/titus-score-lint pkg/rule/rules/
```
Expected: `score-lint: all rules valid` (because Phase 3 applied correct scores)

**Step 4: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f cmd/titus-score-lint/ && git commit -m "feat(score-lint): tool to validate rule base_score values"
```

**Exit Criteria:**
- [ ] 4 score-lint tests pass
- [ ] Running against `pkg/rule/rules/` reports zero violations

---

## Task 4.5: Add `make score-lint` target

**Files:**
- Modify: `Makefile`

**Step 1: Edit**

Add `score-lint` to `.PHONY` list at top, and add target:
```makefile
# Score lint — validate every rule has a reasonable base_score
score-lint:
	GOWORK=off go run ./cmd/titus-score-lint pkg/rule/rules/
```

**Step 2: Verify**

Run: `cd /tmp/titus-ci-fix && make score-lint`
Expected: `score-lint: all rules valid`

**Step 3: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f Makefile && git commit -m "build: add make score-lint target"
```

**Exit Criteria:**
- [ ] `make score-lint` exits 0 on clean rules

---

## Task 4.6: End-to-end smoke test

**Files:**
- No new files. Manual-verification script committed as `scripts/smoke_test_scoring.sh` (optional).

**Step 1: Build everything**

```bash
cd /tmp/titus-ci-fix && make build && make build-migrate-scores
```

**Step 2: Run scan in three output formats**

```bash
cd /tmp/titus-ci-fix
rm -rf /tmp/m1-smoke.ds

# Human format
./dist/titus scan testdata/secrets --format=human --output=/tmp/m1-smoke.ds | tee /tmp/m1-smoke-human.txt
grep "Score:" /tmp/m1-smoke-human.txt || { echo "FAIL: no Score: line in human output"; exit 1; }

# JSON format via report
./dist/titus report --datastore=/tmp/m1-smoke.ds --format=json | tee /tmp/m1-smoke-report.json
grep '"Score"' /tmp/m1-smoke-report.json || { echo "FAIL: no Score field in report JSON"; exit 1; }

# SARIF format via report
./dist/titus report --datastore=/tmp/m1-smoke.ds --format=sarif | tee /tmp/m1-smoke-report.sarif
grep '"titus_score"' /tmp/m1-smoke-report.sarif || { echo "FAIL: no titus_score in SARIF properties"; exit 1; }
grep '"security-severity"' /tmp/m1-smoke-report.sarif || { echo "FAIL: no security-severity in SARIF properties"; exit 1; }
```

**Step 3: Final regression test run**

```bash
cd /tmp/titus-ci-fix && GOWORK=off go test ./... && GOWORK=off go build ./...
```

Expected: all pass, build succeeds.

**Exit Criteria:**
- [ ] Human scan output contains `Score:` lines
- [ ] Report JSON contains `Score` object
- [ ] Report SARIF contains `titus_score` and `security-severity` properties
- [ ] `go test ./...` passes with no failures

---

## Task 4.7: Review flagged LOW CONFIDENCE rules from Phase 3

**Files:**
- Review: `.claude/.output/plans/2026-04-22-162332-m1-finding-scoring-base/research/tier_distribution.md`
- Possibly modify: individual rule YAMLs under `pkg/rule/rules/`

For each rule flagged as `LOW CONFIDENCE` by Phase 3 research subagents, human maintainer:
1. Reads the rule's YAML, description, and references
2. Either confirms the score (write `CONFIRMED` in review log) or adjusts
3. Runs `make score-lint && go test ./pkg/rule/` to verify still clean

Commit any adjustments with clear rationale:
```bash
cd /tmp/titus-ci-fix && git add -f pkg/rule/rules/<modified>.yml && git commit -m "fix(rule): adjust base_score for <rule_id> after human review

Upgrade/downgrade to X (from Y). Rationale: <reason>."
```

**Exit Criteria:**
- [ ] Every LOW CONFIDENCE rule has either been confirmed or adjusted
- [ ] `make score-lint` still passes

---

## Task 4.8: Final Milestone 1 verification

**Run the full acceptance suite:**

```bash
cd /tmp/titus-ci-fix
make build
make test
make score-lint
./dist/titus scan testdata/secrets --format=human --output=/tmp/m1-final.ds
./dist/titus report --datastore=/tmp/m1-final.ds --format=json > /tmp/m1-final.json
./dist/titus report --datastore=/tmp/m1-final.ds --format=sarif > /tmp/m1-final.sarif

# Verify no missing base_scores
rules_count=$(awk '/^[[:space:]]*id:/' pkg/rule/rules/*.yml | wc -l | tr -d ' ')
scores_count=$(awk '/^[[:space:]]*base_score:/' pkg/rule/rules/*.yml | wc -l | tr -d ' ')
[ "$rules_count" = "$scores_count" ] || { echo "MISMATCH: $rules_count rules, $scores_count scores"; exit 1; }
echo "✓ All $rules_count rules scored"
```

**Exit criteria for the entire milestone:**
- [ ] `make build` exits 0
- [ ] `make test` exits 0 (all packages pass)
- [ ] `make score-lint` exits 0
- [ ] Rules count equals base_score count in YAML files
- [ ] Human scan output shows Score lines
- [ ] Report JSON contains Score objects
- [ ] Report SARIF contains titus_score and security-severity properties
- [ ] `TestAllRules_HaveBaseScore`, `TestCriticalTier_RulesExist`, `TestTierBoundaries`, `TestScoreJSON_SchemaStability` all pass

## Ready for PR

At this point `feat/finding-scoring-m1` is ready to open a PR against `main`:

```bash
cd /tmp/titus-ci-fix
git push -u origin feat/finding-scoring-m1
gh pr create --repo praetorian-inc/titus \
  --title "feat: Milestone 1 — base scoring for findings (LAB-2431)" \
  --body "$(cat <<'EOF'
Implements Milestone 1 of LAB-2430 / LAB-14: every detection rule has a
researched `base_score`, every finding carries a `Score` object through
the datastore and all three output formats.

## What changed

- `types.Score` / `types.ScoreModifier` with tier helper
- `Rule.BaseScore int` required field with loader enforcement
- `Finding.Score *Score` persisted through SQLite datastore
- `titus report --format=json` includes full `Score` object
- `titus report --format=sarif` maps score → `level` band and emits
  `properties.security-severity` + `properties.titus_score`
- `titus report --format=human` shows colored `Score: N/100 (tier)` badge
- `cmd/titus-migrate-scores` one-shot tool (for applying scores from CSV)
- `cmd/titus-score-lint` + `make score-lint` to validate coverage
- Researched base scores for every existing rule (parallel-subagent campaign)

## Out of scope (Milestones 2-4)
- Modifier engine, YAML scorer schema, `--score-scope` flag, Go scorers

Closes LAB-2431.
EOF
)"
```

## Milestone done.
