// Command titus-migrate-scores applies researched base_score values to rule YAMLs.
//
// Input: a CSV file with header "rule_id,base_score,tier,reasoning" produced
// by the Phase 3 research campaign. For each row, the tool locates the
// referenced rule's YAML file and inserts `base_score: N` into the rule block.
//
// Usage:
//
//	titus-migrate-scores -scores docs/scores.csv -rules pkg/rule/rules/ -apply
//
// Flags:
//
//	-scores PATH      path to CSV file with scores (required)
//	-rules PATH       path to rules directory (default: pkg/rule/rules)
//	-apply            apply changes (default: false = dry-run / diff output)
//	-allow-missing    do not error when rules are missing from CSV
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

// ScoreEntry holds parsed data from one row in the scores CSV.
type ScoreEntry struct {
	RuleID    string
	BaseScore int
	Tier      string
	Reasoning string
}

// parseScoreCSV reads a CSV file with header "rule_id,base_score,tier,reasoning"
// and returns a map of rule ID to ScoreEntry. Validates that scores are in [0,100]
// and that rule IDs are non-empty.
func parseScoreCSV(path string) (map[string]ScoreEntry, error) {
	// #nosec G304 -- path comes from -scores CLI flag; this is a dev-only migration tool.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening scores csv: %w", err)
	}
	defer func() { _ = f.Close() }()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1 // allow variable number of fields

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
