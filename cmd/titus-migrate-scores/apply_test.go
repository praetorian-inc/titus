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
