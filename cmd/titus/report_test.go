//go:build cgo

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)
// newReportCmd creates a fresh report command for testing
func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate report from scan results",
		RunE:  runReport,
	}
	cmd.Flags().StringVar(&reportDatastore, "datastore", "titus.db", "Path to Titus datastore")
	cmd.Flags().StringVar(&reportFormat, "format", "human", "Output format: human, json, sarif")
	return cmd
}



func TestReportCommand_HumanFormat(t *testing.T) {
	// Setup: Create test database with findings
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := store.New(store.Config{Path: dbPath})
	require.NoError(t, err)

	// Add test findings
	finding1 := &types.Finding{
		ID:     "finding1",
		RuleID: "np.aws.1",
		Groups: [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")},
	}
	finding2 := &types.Finding{
		ID:     "finding2",
		RuleID: "np.github.1",
		Groups: [][]byte{[]byte("ghp_1234567890abcdef")},
	}
	finding3 := &types.Finding{
		ID:     "finding3",
		RuleID: "np.generic.1",
		Groups: [][]byte{[]byte("secret123")},
	}

	require.NoError(t, s.AddFinding(finding1))
	require.NoError(t, s.AddFinding(finding2))
	require.NoError(t, s.AddFinding(finding3))
	require.NoError(t, s.Close())

	// Execute: Run report command
	var stdout bytes.Buffer
	cmd := newReportCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{ "--datastore", dbPath, "--format", "human"})

	err = cmd.Execute()
	require.NoError(t, err)

	// Verify: Check output contains summary
	output := stdout.String()
	assert.Contains(t, output, "=== Titus Report ===")
	assert.Contains(t, output, "Datastore: "+dbPath)
	assert.Contains(t, output, "Total findings: 3")
	assert.Contains(t, output, "np.aws.1")
	assert.Contains(t, output, "np.github.1")
	assert.Contains(t, output, "np.generic.1")
}

func TestReportCommand_JSONFormat(t *testing.T) {
	// Setup: Create test database with findings
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := store.New(store.Config{Path: dbPath})
	require.NoError(t, err)

	finding := &types.Finding{
		ID:     "finding1",
		RuleID: "np.aws.1",
		Groups: [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")},
	}
	require.NoError(t, s.AddFinding(finding))
	require.NoError(t, s.Close())

	// Execute: Run report command
	var stdout bytes.Buffer
	cmd := newReportCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{ "--datastore", dbPath, "--format", "json"})

	err = cmd.Execute()
	require.NoError(t, err)

	// Verify: Check JSON output is valid
	output := stdout.String()
	assert.Contains(t, output, `"ID"`)
	assert.Contains(t, output, `"RuleID"`)
	assert.Contains(t, output, `"np.aws.1"`)
	assert.Contains(t, output, "finding1")
}

func TestReportCommand_SARIFFormat(t *testing.T) {
	// Setup: Create test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := store.New(store.Config{Path: dbPath})
	require.NoError(t, err)
	require.NoError(t, s.Close())

	// Execute: Run report command with SARIF format
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newReportCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{ "--datastore", dbPath, "--format", "sarif"})

	err = cmd.Execute()

	// Verify: SARIF not yet implemented
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SARIF output not yet implemented")
}

func TestReportCommand_EmptyDatastore(t *testing.T) {
	// Setup: Create empty database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "empty.db")

	s, err := store.New(store.Config{Path: dbPath})
	require.NoError(t, err)
	require.NoError(t, s.Close())

	// Execute: Run report command
	var stdout bytes.Buffer
	cmd := newReportCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{ "--datastore", dbPath, "--format", "human"})

	err = cmd.Execute()
	require.NoError(t, err)

	// Verify: Should handle empty database gracefully
	output := stdout.String()
	assert.Contains(t, output, "Total findings: 0")
}

func TestReportCommand_DefaultDatastore(t *testing.T) {
	// Setup: Create database at default path
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(origDir)

	require.NoError(t, os.Chdir(tmpDir))

	s, err := store.New(store.Config{Path: "titus.db"})
	require.NoError(t, err)

	finding := &types.Finding{
		ID:     "finding1",
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("test")},
	}
	require.NoError(t, s.AddFinding(finding))
	require.NoError(t, s.Close())

	// Execute: Run report without --datastore flag (should use default)
	var stdout bytes.Buffer
	cmd := newReportCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{ "--format", "human"})

	err = cmd.Execute()
	require.NoError(t, err)

	// Verify: Should read from default titus.db
	output := stdout.String()
	assert.Contains(t, output, "Total findings: 1")
	assert.Contains(t, output, "np.test.1")
}

func TestReportCommand_NonexistentDatastore(t *testing.T) {
	// Execute: Run report with nonexistent database
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newReportCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{ "--datastore", "/nonexistent/path.db"})

	err := cmd.Execute()

	// Verify: Should fail gracefully
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "no such file") || strings.Contains(err.Error(), "unable to open"))
}

func TestReportCommand_ByRuleSummary(t *testing.T) {
	// Setup: Create database with multiple findings from same rule
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := store.New(store.Config{Path: dbPath})
	require.NoError(t, err)

	// Add multiple findings with same rule
	for i := 0; i < 4; i++ {
		finding := &types.Finding{
			ID:     string(rune(i)),
			RuleID: "np.aws.1",
			Groups: [][]byte{[]byte("test")},
		}
		require.NoError(t, s.AddFinding(finding))
	}

	// Add findings with different rule
	for i := 0; i < 2; i++ {
		finding := &types.Finding{
			ID:     string(rune(100 + i)),
			RuleID: "np.github.1",
			Groups: [][]byte{[]byte("test")},
		}
		require.NoError(t, s.AddFinding(finding))
	}
	require.NoError(t, s.Close())

	// Execute: Run report command
	var stdout bytes.Buffer
	cmd := newReportCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{ "--datastore", dbPath, "--format", "human"})

	err = cmd.Execute()
	require.NoError(t, err)

	// Verify: Check by-rule summary
	output := stdout.String()
	assert.Contains(t, output, "By Rule:")
	assert.Contains(t, output, "np.aws.1")
	assert.Contains(t, output, "4 findings")
	assert.Contains(t, output, "np.github.1")
	assert.Contains(t, output, "2 findings")
}

func TestReportCommand_JSONFormat_IncludesValidationResults(t *testing.T) {
	// Setup: Create test database with match containing validation result
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := store.New(store.Config{Path: dbPath})
	require.NoError(t, err)

	// Add blob
	blobID := types.ComputeBlobID([]byte("test content"))
	err = s.AddBlob(blobID, 12)
	require.NoError(t, err)

	// Use real rule structural ID computation
	ruleStructuralID := "test-rule-structural-id"
	groups := [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")}
	findingID := types.ComputeFindingID(ruleStructuralID, groups)

	// Create match with validation result
	validationResult := types.NewValidationResult(
		types.StatusUndetermined,
		0.0,
		"cannot validate: partial credentials: np.aws.1 only contains access key ID",
	)

	match := &types.Match{
		BlobID:           blobID,
		StructuralID:     "location-based-structural-id", // Different from finding ID
		RuleID:           "np.aws.1",
		RuleName:         "AWS API Key",
		Location:         types.Location{Offset: types.OffsetSpan{Start: 0, End: 20}},
		Groups:           groups,
		Snippet:          types.Snippet{Matching: []byte("AKIAIOSFODNN7EXAMPLE")},
		ValidationResult: validationResult,
	}
	err = s.AddMatch(match)
	require.NoError(t, err)

	// Add finding with content-based ID
	finding := &types.Finding{
		ID:     findingID,
		RuleID: "np.aws.1",
		Groups: groups,
	}
	err = s.AddFinding(finding)
	require.NoError(t, err)

	require.NoError(t, s.Close())

	// Execute: Run report command with JSON format
	var stdout bytes.Buffer
	cmd := newReportCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--datastore", dbPath, "--format", "json"})

	err = cmd.Execute()
	require.NoError(t, err)

	// Verify: Check JSON output contains validation results
	output := stdout.String()
	assert.Contains(t, output, `"validation_result"`, "JSON should contain validation_result field")
	assert.Contains(t, output, `"status"`, "validation_result should contain status")
	assert.Contains(t, output, `"undetermined"`, "status should be undetermined")
	assert.Contains(t, output, `only contains access key ID`, "message should be present")
	assert.Contains(t, output, `"Matches"`, "Finding should contain Matches array")
}

func TestReportCommand_HumanFormat_ShowsValidationSummary(t *testing.T) {
	// Setup: Create test database with matches containing validation results
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := store.New(store.Config{Path: dbPath})
	require.NoError(t, err)

	// Add blob
	blobID := types.ComputeBlobID([]byte("test content"))
	err = s.AddBlob(blobID, 12)
	require.NoError(t, err)

	ruleStructuralID := "test-rule-structural-id"

	// Create multiple matches with different validation statuses
	groups1 := [][]byte{[]byte("AKIATEST12345678")}
	match1 := &types.Match{
		BlobID:       blobID,
		StructuralID: "structural-id-1",
		RuleID:       "np.aws.6",
		RuleName:     "AWS API Key",
		Location:     types.Location{Offset: types.OffsetSpan{Start: 0, End: 16}},
		Groups:       groups1,
		Snippet:      types.Snippet{Matching: []byte("AKIATEST12345678")},
		ValidationResult: types.NewValidationResult(
			types.StatusValid,
			1.0,
			"valid AWS credentials",
		),
	}

	groups2 := [][]byte{[]byte("AKIATEST87654321")}
	match2 := &types.Match{
		BlobID:       blobID,
		StructuralID: "structural-id-2",
		RuleID:       "np.aws.6",
		RuleName:     "AWS API Key",
		Location:     types.Location{Offset: types.OffsetSpan{Start: 20, End: 36}},
		Groups:       groups2,
		Snippet:      types.Snippet{Matching: []byte("AKIATEST87654321")},
		ValidationResult: types.NewValidationResult(
			types.StatusInvalid,
			0.9,
			"invalid AWS credentials",
		),
	}

	groups3 := [][]byte{[]byte("AKIATEST11111111")}
	match3 := &types.Match{
		BlobID:       blobID,
		StructuralID: "structural-id-3",
		RuleID:       "np.aws.6",
		RuleName:     "AWS API Key",
		Location:     types.Location{Offset: types.OffsetSpan{Start: 40, End: 56}},
		Groups:       groups3,
		Snippet:      types.Snippet{Matching: []byte("AKIATEST11111111")},
		ValidationResult: types.NewValidationResult(
			types.StatusUndetermined,
			0.0,
			"cannot validate",
		),
	}

	err = s.AddMatch(match1)
	require.NoError(t, err)
	err = s.AddMatch(match2)
	require.NoError(t, err)
	err = s.AddMatch(match3)
	require.NoError(t, err)

	// Add findings
	finding1 := &types.Finding{
		ID:     types.ComputeFindingID(ruleStructuralID, groups1),
		RuleID: "np.aws.6",
		Groups: groups1,
	}
	finding2 := &types.Finding{
		ID:     types.ComputeFindingID(ruleStructuralID, groups2),
		RuleID: "np.aws.6",
		Groups: groups2,
	}
	finding3 := &types.Finding{
		ID:     types.ComputeFindingID(ruleStructuralID, groups3),
		RuleID: "np.aws.6",
		Groups: groups3,
	}

	err = s.AddFinding(finding1)
	require.NoError(t, err)
	err = s.AddFinding(finding2)
	require.NoError(t, err)
	err = s.AddFinding(finding3)
	require.NoError(t, err)

	require.NoError(t, s.Close())

	// Execute: Run report command with human format
	var stdout bytes.Buffer
	cmd := newReportCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--datastore", dbPath, "--format", "human"})

	err = cmd.Execute()
	require.NoError(t, err)

	// Verify: Check validation summary is present
	output := stdout.String()
	assert.Contains(t, output, "Validation Summary:", "should show validation summary")
	assert.Contains(t, output, "Valid: 1", "should count valid")
	assert.Contains(t, output, "Invalid: 1", "should count invalid")
	assert.Contains(t, output, "Undetermined: 1", "should count undetermined")

	// Verify: Check validation status shown in findings list
	assert.Contains(t, output, "[valid]", "should show validation status")
	assert.Contains(t, output, "valid AWS credentials", "should show validation message")
}

func TestReportCommand_HumanFormat_ShowsValidationInFindingsList(t *testing.T) {
	// Setup: Create test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := store.New(store.Config{Path: dbPath})
	require.NoError(t, err)

	// Add blob
	blobID := types.ComputeBlobID([]byte("test content"))
	err = s.AddBlob(blobID, 12)
	require.NoError(t, err)

	ruleStructuralID := "test-rule-structural-id"
	groups := [][]byte{[]byte("AKIATEST12345678")}
	findingID := types.ComputeFindingID(ruleStructuralID, groups)

	// Create match with validation
	match := &types.Match{
		BlobID:       blobID,
		StructuralID: "structural-id-1",
		RuleID:       "np.aws.6",
		RuleName:     "AWS API Key",
		Location:     types.Location{Offset: types.OffsetSpan{Start: 0, End: 16}},
		Groups:       groups,
		Snippet:      types.Snippet{Matching: []byte("AKIATEST12345678")},
		ValidationResult: types.NewValidationResult(
			types.StatusValid,
			1.0,
			"valid AWS credentials for account 411435703965...",
		),
	}

	err = s.AddMatch(match)
	require.NoError(t, err)

	// Add finding
	finding := &types.Finding{
		ID:     findingID,
		RuleID: "np.aws.6",
		Groups: groups,
	}

	err = s.AddFinding(finding)
	require.NoError(t, err)

	require.NoError(t, s.Close())

	// Execute: Run report command
	var stdout bytes.Buffer
	cmd := newReportCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--datastore", dbPath, "--format", "human"})

	err = cmd.Execute()
	require.NoError(t, err)

	// Verify: Check validation shown in findings list
	output := stdout.String()
	assert.Contains(t, output, "Recent Findings:", "should show findings section")
	assert.Contains(t, output, "Rule: np.aws.6", "should show rule")
	assert.Contains(t, output, "Validation: [valid]", "should show validation status")
	assert.Contains(t, output, "valid AWS credentials for account 411435703965...", "should show validation message")
}
