// cmd/titus/scan_test.go
package main

import (
	"os"
	"testing"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanFlags_Validate(t *testing.T) {
	// Verify default values
	assert.False(t, scanValidate, "validate should be disabled by default")
	assert.Equal(t, 4, scanValidateWorkers, "default workers should be 4")
}

func TestFindingID_ContentBased(t *testing.T) {
	// Test that finding ID is computed from rule + groups (content)
	// NOT from blob ID + offset (location)

	// Create a rule
	rule := &types.Rule{
		ID:      "test-rule",
		Pattern: "secret-[0-9]{4}",
	}
	rule.StructuralID = rule.ComputeStructuralID()

	// Create two matches with SAME secret but DIFFERENT locations
	match1 := &types.Match{
		RuleID: "test-rule",
		BlobID: types.BlobID{1, 2, 3}, // blob A
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 100, End: 112}, // offset 100
		},
		Groups:       [][]byte{[]byte("secret-1234")},
		StructuralID: "different-structural-id-1", // Location-based
	}

	match2 := &types.Match{
		RuleID: "test-rule",
		BlobID: types.BlobID{4, 5, 6}, // blob B (different!)
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 200, End: 212}, // offset 200 (different!)
		},
		Groups:       [][]byte{[]byte("secret-1234")},
		StructuralID: "different-structural-id-2", // Location-based (different!)
	}

	// Compute content-based finding IDs
	findingID1 := types.ComputeFindingID(rule.StructuralID, match1.Groups)
	findingID2 := types.ComputeFindingID(rule.StructuralID, match2.Groups)

	// Finding IDs should be IDENTICAL (same rule + same secret content)
	assert.Equal(t, findingID1, findingID2,
		"Finding IDs should be identical for same secret in different locations")

	// Finding IDs should be DIFFERENT from structural IDs (which are location-based)
	assert.NotEqual(t, match1.StructuralID, findingID1,
		"Finding ID should differ from location-based structural ID")
	assert.NotEqual(t, match2.StructuralID, findingID2,
		"Finding ID should differ from location-based structural ID")
}

func TestFindingID_DifferentSecrets(t *testing.T) {
	// Test that different secrets produce different finding IDs

	rule := &types.Rule{
		ID:      "test-rule",
		Pattern: "secret-[0-9]{4}",
	}
	rule.StructuralID = rule.ComputeStructuralID()

	match1 := &types.Match{
		RuleID: "test-rule",
		Groups: [][]byte{[]byte("secret-1234")},
	}

	match2 := &types.Match{
		RuleID: "test-rule",
		Groups: [][]byte{[]byte("secret-5678")}, // Different secret!
	}

	findingID1 := types.ComputeFindingID(rule.StructuralID, match1.Groups)
	findingID2 := types.ComputeFindingID(rule.StructuralID, match2.Groups)

	// Finding IDs should be DIFFERENT (different secret content)
	assert.NotEqual(t, findingID1, findingID2,
		"Finding IDs should differ for different secrets")
}

func TestLoadRules_CreatesRuleMap(t *testing.T) {
	// Test that rules can be loaded and looked up by ID
	rules, err := loadRules("", "", "")
	require.NoError(t, err)
	require.NotEmpty(t, rules, "Should load builtin rules")

	// Verify we can create a map from rules
	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	// Verify map is populated
	assert.NotEmpty(t, ruleMap, "Rule map should be populated")

	// Verify we can look up rules by ID
	for _, r := range rules {
		found, ok := ruleMap[r.ID]
		assert.True(t, ok, "Should find rule by ID: %s", r.ID)
		assert.Equal(t, r, found, "Retrieved rule should match original")
	}
}

func TestScan_DeduplicatesSameSecretAcrossFiles(t *testing.T) {
	// Integration test: Same secret in multiple files should create
	// ONE finding with multiple matches (not multiple findings)

	// This test verifies the fix for content-based finding IDs.
	// Before fix: Same secret in File A and File B created 2 findings
	// After fix: Same secret in File A and File B creates 1 finding with 2 matches

	// Create temporary directory with test files containing the same secret
	tmpDir := t.TempDir()

	// File 1 with secret
	file1 := tmpDir + "/file1.txt"
	err := os.WriteFile(file1, []byte("AWS API Key: AKIAIOSFODNN7EXAMPLE\n"), 0644)
	require.NoError(t, err)

	// File 2 with SAME secret (different location)
	file2 := tmpDir + "/file2.txt"
	err = os.WriteFile(file2, []byte("Config: AKIAIOSFODNN7EXAMPLE\n"), 0644)
	require.NoError(t, err)

	// Create temporary database
	tmpDB := tmpDir + "/test.db"

	// Set scan flags
	scanOutputPath = tmpDB
	scanRulesInclude = "aws"
	scanRulesExclude = ""
	scanRulesPath = ""
	scanGit = false
	scanIncremental = false
	scanContextLines = 3
	scanMaxFileSize = 10 * 1024 * 1024
	scanIncludeHidden = false
	scanValidate = false
	scanValidateWorkers = 4
	scanOutputFormat = "human"

	// Run scan
	err = runScan(scanCmd, []string{tmpDir})
	require.NoError(t, err)

	// Open store to verify results
	s, err := store.New(store.Config{Path: tmpDB})
	require.NoError(t, err)
	defer s.Close()

	// Get all matches
	matches, err := s.GetAllMatches()
	require.NoError(t, err)

	// Should have 2 matches (same secret in 2 different files)
	assert.Equal(t, 2, len(matches), "Should have 2 matches (same secret in 2 files)")

	// Get findings
	findings, err := s.GetFindings()
	require.NoError(t, err)

	// CRITICAL: Should have 1 finding (deduplicated by content)
	// This proves the fix works - before the fix, this would be 2 findings
	assert.Equal(t, 1, len(findings), "Should have 1 finding (same secret deduplicated)")

	// Verify both matches have the same content-based finding ID
	rules, err := loadRules("", "aws", "")
	require.NoError(t, err)
	require.NotEmpty(t, rules)

	var rule *types.Rule
	for _, r := range rules {
		if r.ID == matches[0].RuleID {
			rule = r
			break
		}
	}
	require.NotNil(t, rule, "Should find rule for match")

	// Compute finding IDs for both matches
	findingID1 := types.ComputeFindingID(rule.StructuralID, matches[0].Groups)
	findingID2 := types.ComputeFindingID(rule.StructuralID, matches[1].Groups)

	// Both matches should have the SAME finding ID (content-based)
	assert.Equal(t, findingID1, findingID2, "Both matches should have same content-based finding ID")

	// The finding ID should match what's stored
	assert.Equal(t, findingID1, findings[0].ID, "Stored finding ID should match computed finding ID")
}
