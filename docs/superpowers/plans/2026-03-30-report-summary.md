# Report Summary Subcommand Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `titus report summary` subcommand that shows total secret counts and per-rule-type breakdown from a scan datastore.

**Architecture:** New `summaryCmd` registered as child of `reportCmd` in `report.go`, following existing subcommand patterns (`rulesCmd`/`rulesListCmd`). Reuses `buildFindingMatchMap()` for match association. Aggregation by RuleID with sort by finding count descending.

**Tech Stack:** Go, cobra, fatih/color (existing dependencies)

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `cmd/titus/report.go` | Modify | Add `summaryCmd`, `runSummary()`, `outputSummaryHuman()`, `outputSummaryJSON()` |
| `cmd/titus/report_test.go` | Modify | Add tests for aggregation, human output, JSON output, empty datastore |

---

### Task 1: Register the summary subcommand and add the format flag

**Files:**
- Modify: `cmd/titus/report.go:17-21` (add `summaryFormat` var)
- Modify: `cmd/titus/report.go:67-78` (add `summaryCmd`, register in `init()`)

- [ ] **Step 1: Add the summaryFormat variable and summaryCmd definition**

In `cmd/titus/report.go`, add to the `var` block at line 17:

```go
var (
	reportDatastore string
	reportFormat    string
	reportColor     string
	summaryFormat   string
)
```

Then add the `summaryCmd` after the existing `reportCmd` definition (after line 72):

```go
var summaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Show a summary of findings by rule type",
	Long:  "Display total counts and per-rule breakdown of findings and matches",
	RunE:  runSummary,
}
```

- [ ] **Step 2: Register summaryCmd under reportCmd in init()**

In the existing `init()` function, add registration and the format flag:

```go
func init() {
	reportCmd.Flags().StringVar(&reportDatastore, "datastore", "titus.ds", "Path to datastore directory or file")
	reportCmd.Flags().StringVar(&reportFormat, "format", "human", "Output format: human, json, sarif")
	reportCmd.Flags().StringVar(&reportColor, "color", "auto", "Color output: auto, always, never")

	reportCmd.AddCommand(summaryCmd)
	summaryCmd.Flags().StringVar(&summaryFormat, "format", "human", "Output format: human, json")
}
```

- [ ] **Step 3: Add a stub runSummary function**

Add at the bottom of `report.go`, before the helpers section:

```go
func runSummary(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("not yet implemented")
}
```

- [ ] **Step 4: Verify it compiles and the subcommand is registered**

Run: `cd /Users/carterross/Tools/titus && go build ./cmd/titus/`
Expected: Compiles with no errors.

Run: `cd /Users/carterross/Tools/titus && go run ./cmd/titus/ report summary --help`
Expected: Shows help text with "Show a summary of findings by rule type" and the `--format` flag.

- [ ] **Step 5: Commit**

```bash
git add cmd/titus/report.go
git commit -m "feat(report): register summary subcommand with format flag"
```

---

### Task 2: Implement the summary aggregation type and runSummary function

**Files:**
- Modify: `cmd/titus/report.go` (replace `runSummary` stub, add `ruleSummary` type and `aggregateSummary` function)

- [ ] **Step 1: Write the test for aggregation logic**

In `cmd/titus/report_test.go`, add:

```go
func TestAggregateSummary_MultipleRules(t *testing.T) {
	findings := []*types.Finding{
		{ID: "f1", RuleID: "rule-a", Groups: [][]byte{[]byte("secret1")}},
		{ID: "f2", RuleID: "rule-a", Groups: [][]byte{[]byte("secret2")}},
		{ID: "f3", RuleID: "rule-a", Groups: [][]byte{[]byte("secret3")}},
		{ID: "f4", RuleID: "rule-b", Groups: [][]byte{[]byte("token1")}},
		{ID: "f5", RuleID: "rule-c", Groups: [][]byte{[]byte("key1")}},
		{ID: "f6", RuleID: "rule-c", Groups: [][]byte{[]byte("key2")}},
	}

	// 2 matches per finding for rule-a, 3 for rule-b, 1 for rule-c
	matchesByFinding := map[string][]*types.Match{
		"f1": {{RuleID: "rule-a"}, {RuleID: "rule-a"}},
		"f2": {{RuleID: "rule-a"}, {RuleID: "rule-a"}},
		"f3": {{RuleID: "rule-a"}, {RuleID: "rule-a"}},
		"f4": {{RuleID: "rule-b"}, {RuleID: "rule-b"}, {RuleID: "rule-b"}},
		"f5": {{RuleID: "rule-c"}},
		"f6": {{RuleID: "rule-c"}},
	}

	ruleMap := map[string]*types.Rule{
		"rule-a": {ID: "rule-a", Name: "AWS API Key"},
		"rule-b": {ID: "rule-b", Name: "GitHub Token"},
		"rule-c": {ID: "rule-c", Name: "Slack Webhook"},
	}

	summary := aggregateSummary(findings, matchesByFinding, ruleMap)

	// Check totals
	if summary.TotalFindings != 6 {
		t.Errorf("Expected 6 total findings, got %d", summary.TotalFindings)
	}
	if summary.TotalMatches != 11 {
		t.Errorf("Expected 11 total matches, got %d", summary.TotalMatches)
	}

	// Check sorted by finding count descending
	if len(summary.Rules) != 3 {
		t.Fatalf("Expected 3 rules, got %d", len(summary.Rules))
	}
	if summary.Rules[0].RuleName != "AWS API Key" {
		t.Errorf("Expected first rule to be 'AWS API Key', got %q", summary.Rules[0].RuleName)
	}
	if summary.Rules[0].Findings != 3 {
		t.Errorf("Expected 3 findings for AWS API Key, got %d", summary.Rules[0].Findings)
	}
	if summary.Rules[0].Matches != 6 {
		t.Errorf("Expected 6 matches for AWS API Key, got %d", summary.Rules[0].Matches)
	}
	if summary.Rules[1].RuleName != "Slack Webhook" {
		t.Errorf("Expected second rule to be 'Slack Webhook', got %q", summary.Rules[1].RuleName)
	}
	if summary.Rules[2].RuleName != "GitHub Token" {
		t.Errorf("Expected third rule to be 'GitHub Token', got %q", summary.Rules[2].RuleName)
	}
}

func TestAggregateSummary_Empty(t *testing.T) {
	summary := aggregateSummary(nil, nil, nil)

	if summary.TotalFindings != 0 {
		t.Errorf("Expected 0 total findings, got %d", summary.TotalFindings)
	}
	if summary.TotalMatches != 0 {
		t.Errorf("Expected 0 total matches, got %d", summary.TotalMatches)
	}
	if len(summary.Rules) != 0 {
		t.Errorf("Expected 0 rules, got %d", len(summary.Rules))
	}
}

func TestAggregateSummary_UnknownRule(t *testing.T) {
	findings := []*types.Finding{
		{ID: "f1", RuleID: "unknown-rule", Groups: [][]byte{[]byte("secret1")}},
	}
	matchesByFinding := map[string][]*types.Match{
		"f1": {{RuleID: "unknown-rule"}},
	}
	// ruleMap does not contain "unknown-rule"
	ruleMap := map[string]*types.Rule{}

	summary := aggregateSummary(findings, matchesByFinding, ruleMap)

	if len(summary.Rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(summary.Rules))
	}
	// Should fall back to raw RuleID as display name
	if summary.Rules[0].RuleName != "unknown-rule" {
		t.Errorf("Expected rule name fallback to 'unknown-rule', got %q", summary.Rules[0].RuleName)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/carterross/Tools/titus && go test ./cmd/titus/ -run TestAggregateSummary -v`
Expected: FAIL — `aggregateSummary` undefined.

- [ ] **Step 3: Add the summary types and aggregateSummary function**

In `cmd/titus/report.go`, add these types and the aggregation function after the `summaryCmd` definition:

```go
// summaryResult holds the aggregated summary data for output.
type summaryResult struct {
	TotalFindings int            `json:"total_findings"`
	TotalMatches  int            `json:"total_matches"`
	Rules         []ruleSummary  `json:"rules"`
}

// ruleSummary holds per-rule aggregated counts.
type ruleSummary struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Findings int    `json:"findings"`
	Matches  int    `json:"matches"`
}

// aggregateSummary builds per-rule summary stats from findings and their matches.
func aggregateSummary(findings []*types.Finding, matchesByFinding map[string][]*types.Match, ruleMap map[string]*types.Rule) summaryResult {
	type stats struct {
		name     string
		findings int
		matches  int
	}
	statsMap := make(map[string]*stats)

	for _, f := range findings {
		if _, exists := statsMap[f.RuleID]; !exists {
			name := f.RuleID
			if r, ok := ruleMap[f.RuleID]; ok {
				name = r.Name
			}
			statsMap[f.RuleID] = &stats{name: name}
		}
		statsMap[f.RuleID].findings++
		statsMap[f.RuleID].matches += len(matchesByFinding[f.ID])
	}

	// Build sorted slice
	result := summaryResult{}
	for ruleID, s := range statsMap {
		result.Rules = append(result.Rules, ruleSummary{
			RuleID:   ruleID,
			RuleName: s.name,
			Findings: s.findings,
			Matches:  s.matches,
		})
		result.TotalFindings += s.findings
		result.TotalMatches += s.matches
	}

	sort.Slice(result.Rules, func(i, j int) bool {
		return result.Rules[i].Findings > result.Rules[j].Findings
	})

	return result
}
```

Add `"sort"` to the import block.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/carterross/Tools/titus && go test ./cmd/titus/ -run TestAggregateSummary -v`
Expected: All 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/titus/report.go cmd/titus/report_test.go
git commit -m "feat(report): add summary aggregation logic with tests"
```

---

### Task 3: Implement outputSummaryHuman

**Files:**
- Modify: `cmd/titus/report.go` (add `outputSummaryHuman` function)
- Modify: `cmd/titus/report_test.go` (add test)

- [ ] **Step 1: Write the test for human output**

In `cmd/titus/report_test.go`, add:

```go
func TestOutputSummaryHuman(t *testing.T) {
	summary := summaryResult{
		TotalFindings: 6,
		TotalMatches:  11,
		Rules: []ruleSummary{
			{RuleID: "rule-a", RuleName: "AWS API Key", Findings: 3, Matches: 6},
			{RuleID: "rule-c", RuleName: "Slack Webhook", Findings: 2, Matches: 2},
			{RuleID: "rule-b", RuleName: "GitHub Token", Findings: 1, Matches: 3},
		},
	}

	var buf bytes.Buffer
	err := outputSummaryHuman(&buf, summary, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Check total line
	if !strings.Contains(output, "Total: 6 findings, 11 matches") {
		t.Errorf("Expected total line, got:\n%s", output)
	}

	// Check all rule names appear
	for _, name := range []string{"AWS API Key", "Slack Webhook", "GitHub Token"} {
		if !strings.Contains(output, name) {
			t.Errorf("Expected output to contain %q, got:\n%s", name, output)
		}
	}

	// Check header row
	if !strings.Contains(output, "Rule") || !strings.Contains(output, "Findings") || !strings.Contains(output, "Matches") {
		t.Errorf("Expected table headers, got:\n%s", output)
	}

	// Check separator line
	if !strings.Contains(output, "─") {
		t.Errorf("Expected separator line with box-drawing chars, got:\n%s", output)
	}
}

func TestOutputSummaryHuman_Empty(t *testing.T) {
	summary := summaryResult{}

	var buf bytes.Buffer
	err := outputSummaryHuman(&buf, summary, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No findings") {
		t.Errorf("Expected 'No findings' message, got:\n%s", output)
	}
}
```

Add `"bytes"` to the test file's import block if not already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/carterross/Tools/titus && go test ./cmd/titus/ -run TestOutputSummaryHuman -v`
Expected: FAIL — `outputSummaryHuman` undefined.

- [ ] **Step 3: Implement outputSummaryHuman**

In `cmd/titus/report.go`, add:

```go
func outputSummaryHuman(out io.Writer, summary summaryResult, colorEnabled bool) error {
	if summary.TotalFindings == 0 {
		fmt.Fprintf(out, "No findings.\n")
		return nil
	}

	s := newStyles(colorEnabled)

	fmt.Fprintf(out, "%s %d findings, %d matches\n\n",
		s.heading.Sprint("Total:"), summary.TotalFindings, summary.TotalMatches)

	// Find longest rule name for column width
	maxNameLen := len("Rule")
	for _, r := range summary.Rules {
		if len(r.RuleName) > maxNameLen {
			maxNameLen = len(r.RuleName)
		}
	}

	// Print header
	fmt.Fprintf(out, " %-*s   Findings   Matches \n", maxNameLen, "Rule")

	// Print separator line
	separatorLen := maxNameLen + 3 + 10 + 3 + 8
	fmt.Fprintf(out, "%s\n", strings.Repeat("─", separatorLen))

	// Print data rows
	for _, r := range summary.Rules {
		fmt.Fprintf(out, " %-*s   %8d   %7d \n",
			maxNameLen, r.RuleName, r.Findings, r.Matches)
	}

	return nil
}
```

Add `"io"` and `"strings"` to the import block (if `"strings"` not already present — it is already imported via `strings.Repeat` usage in the existing codebase, but verify).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/carterross/Tools/titus && go test ./cmd/titus/ -run TestOutputSummaryHuman -v`
Expected: All 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/titus/report.go cmd/titus/report_test.go
git commit -m "feat(report): implement human-readable summary output"
```

---

### Task 4: Implement outputSummaryJSON

**Files:**
- Modify: `cmd/titus/report.go` (add `outputSummaryJSON` function)
- Modify: `cmd/titus/report_test.go` (add test)

- [ ] **Step 1: Write the test for JSON output**

In `cmd/titus/report_test.go`, add:

```go
func TestOutputSummaryJSON(t *testing.T) {
	summary := summaryResult{
		TotalFindings: 4,
		TotalMatches:  10,
		Rules: []ruleSummary{
			{RuleID: "rule-a", RuleName: "AWS API Key", Findings: 3, Matches: 7},
			{RuleID: "rule-b", RuleName: "GitHub Token", Findings: 1, Matches: 3},
		},
	}

	var buf bytes.Buffer
	err := outputSummaryJSON(&buf, summary)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse the output as JSON
	var parsed summaryResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v\nOutput:\n%s", err, buf.String())
	}

	if parsed.TotalFindings != 4 {
		t.Errorf("Expected total_findings=4, got %d", parsed.TotalFindings)
	}
	if parsed.TotalMatches != 10 {
		t.Errorf("Expected total_matches=10, got %d", parsed.TotalMatches)
	}
	if len(parsed.Rules) != 2 {
		t.Fatalf("Expected 2 rules, got %d", len(parsed.Rules))
	}
	if parsed.Rules[0].RuleID != "rule-a" {
		t.Errorf("Expected first rule_id='rule-a', got %q", parsed.Rules[0].RuleID)
	}
	if parsed.Rules[0].RuleName != "AWS API Key" {
		t.Errorf("Expected first rule_name='AWS API Key', got %q", parsed.Rules[0].RuleName)
	}
}
```

Add `"encoding/json"` to the test file's import block if not already present.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/carterross/Tools/titus && go test ./cmd/titus/ -run TestOutputSummaryJSON -v`
Expected: FAIL — `outputSummaryJSON` undefined.

- [ ] **Step 3: Implement outputSummaryJSON**

In `cmd/titus/report.go`, add:

```go
func outputSummaryJSON(out io.Writer, summary summaryResult) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/carterross/Tools/titus && go test ./cmd/titus/ -run TestOutputSummaryJSON -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/titus/report.go cmd/titus/report_test.go
git commit -m "feat(report): implement JSON summary output"
```

---

### Task 5: Wire up runSummary to open the store and call output functions

**Files:**
- Modify: `cmd/titus/report.go` (replace `runSummary` stub with full implementation)

- [ ] **Step 1: Replace the runSummary stub**

Replace the stub `runSummary` function with the full implementation:

```go
func runSummary(cmd *cobra.Command, args []string) error {
	// Determine store path (inherited from parent report command)
	storePath := reportDatastore

	if storePath == ":memory:" {
		return fmt.Errorf("cannot report from in-memory store")
	}

	info, err := os.Stat(storePath)
	if err != nil {
		return fmt.Errorf("datastore not found: %s", storePath)
	}
	if info.IsDir() {
		storePath = filepath.Join(storePath, "datastore.db")
	}

	s, err := store.New(store.Config{
		Path: storePath,
	})
	if err != nil {
		return fmt.Errorf("opening datastore: %w", err)
	}
	defer s.Close()

	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}

	matches, err := s.GetAllMatches()
	if err != nil {
		return fmt.Errorf("retrieving matches: %w", err)
	}

	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}
	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	matchesByFinding := buildFindingMatchMap(findings, matches, ruleMap)
	summary := aggregateSummary(findings, matchesByFinding, ruleMap)

	// Determine color setting (inherited from parent)
	switch reportColor {
	case "always":
		color.NoColor = false
	case "never":
		color.NoColor = true
	default:
		if !term.IsTerminal(int(os.Stdout.Fd())) || os.Getenv("NO_COLOR") != "" {
			color.NoColor = true
		} else {
			color.NoColor = false
		}
	}

	switch summaryFormat {
	case "json":
		return outputSummaryJSON(cmd.OutOrStdout(), summary)
	case "human":
		return outputSummaryHuman(cmd.OutOrStdout(), summary, !color.NoColor)
	default:
		return fmt.Errorf("unknown output format: %s", summaryFormat)
	}
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /Users/carterross/Tools/titus && go build ./cmd/titus/`
Expected: Compiles with no errors.

- [ ] **Step 3: Run all report tests**

Run: `cd /Users/carterross/Tools/titus && go test ./cmd/titus/ -run "TestAggregateSummary|TestOutputSummary" -v`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add cmd/titus/report.go
git commit -m "feat(report): wire up runSummary with store loading and format dispatch"
```

---

### Task 6: End-to-end verification

**Files:** None (verification only)

- [ ] **Step 1: Run the full test suite**

Run: `cd /Users/carterross/Tools/titus && go test ./cmd/titus/ -v`
Expected: All existing tests PASS, plus all new summary tests PASS.

- [ ] **Step 2: Run a quick manual smoke test**

If a `titus.ds` datastore exists from a prior scan, run:

```bash
cd /Users/carterross/Tools/titus && go run ./cmd/titus/ report summary
```

If no datastore exists, verify the error message:

```bash
cd /Users/carterross/Tools/titus && go run ./cmd/titus/ report summary --datastore nonexistent
```

Expected: `Error: datastore not found: nonexistent`

- [ ] **Step 3: Verify JSON output format**

```bash
cd /Users/carterross/Tools/titus && go run ./cmd/titus/ report summary --format json 2>/dev/null || echo "OK - no datastore (expected)"
```

- [ ] **Step 4: Verify help text**

Run: `cd /Users/carterross/Tools/titus && go run ./cmd/titus/ report summary --help`
Expected: Shows usage with `--format` and `--datastore` flags.

Run: `cd /Users/carterross/Tools/titus && go run ./cmd/titus/ report --help`
Expected: Shows `summary` listed as an available subcommand.
