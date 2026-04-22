package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScoreLint_AllRulesValid(t *testing.T) {
	tmp := t.TempDir()
	yaml := `rules:
- name: Good
  id: np.good.1
  pattern: foo
  base_score: 50
`
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "good.yml"), []byte(yaml), 0644))

	errs := lintDir(tmp)
	assert.Empty(t, errs, "expected 0 errors for valid rule, got: %v", errs)
}

func TestScoreLint_FlagsMissing(t *testing.T) {
	tmp := t.TempDir()
	yaml := `rules:
- name: Missing
  id: np.bad.1
  pattern: foo
`
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "bad.yml"), []byte(yaml), 0644))

	errs := lintDir(tmp)
	assert.NotEmpty(t, errs, "expected error for missing base_score")
}

func TestScoreLint_FlagsOutOfRange(t *testing.T) {
	tmp := t.TempDir()
	yaml := `rules:
- name: Out of range
  id: np.bad.1
  pattern: foo
  base_score: 250
`
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "bad.yml"), []byte(yaml), 0644))

	errs := lintDir(tmp)
	assert.NotEmpty(t, errs, "expected error for base_score 250")
}

func TestScoreLint_FlagsNamingTierMismatch(t *testing.T) {
	tmp := t.TempDir()
	// np.pem. rules require base_score >= 80; score of 20 is a mismatch.
	yaml := `rules:
- name: PEM Private Key Low Score
  id: np.pem.99
  pattern: foo
  base_score: 20
`
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "bad.yml"), []byte(yaml), 0644))

	errs := lintDir(tmp)
	found := false
	for _, e := range errs {
		if contains(e, "naming suggests") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected naming-tier mismatch warning, got: %v", errs)
}

func TestScoreLint_MultiRuleFile(t *testing.T) {
	tmp := t.TempDir()
	yaml := `rules:
- name: Rule One
  id: np.multi.1
  pattern: foo
  base_score: 40
- name: Rule Two
  id: np.multi.2
  pattern: bar
  base_score: 60
`
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "multi.yml"), []byte(yaml), 0644))

	errs := lintDir(tmp)
	assert.Empty(t, errs, "expected 0 errors for valid multi-rule file, got: %v", errs)
}

func TestScoreLint_MultiRuleFileMissingOne(t *testing.T) {
	tmp := t.TempDir()
	yaml := `rules:
- name: Rule One
  id: np.multi.1
  pattern: foo
  base_score: 40
- name: Rule Two No Score
  id: np.multi.2
  pattern: bar
`
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "multi.yml"), []byte(yaml), 0644))

	errs := lintDir(tmp)
	assert.Len(t, errs, 1, "expected exactly 1 error for the rule missing base_score")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
