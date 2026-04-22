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
