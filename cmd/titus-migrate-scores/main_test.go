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
