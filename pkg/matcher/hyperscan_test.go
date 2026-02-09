//go:build !wasm && cgo && hyperscan

package matcher

import (
	"testing"

	"github.com/flier/gohs/hyperscan"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// computeRuleStructuralID is a test helper to compute StructuralID for a rule pattern.
func computeRuleStructuralID(pattern string) string {
	r := &types.Rule{Pattern: pattern}
	return r.ComputeStructuralID()
}

func TestNewHyperscan_NoRules(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	m, err := NewHyperscan(nil, 0)
	require.Error(t, err)
	assert.Nil(t, m)
	assert.Contains(t, err.Error(), "no rules")
}

func TestNewHyperscan_SingleRule(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	rules := []*types.Rule{
		{
			ID:      "test.1",
			Name:    "Test Pattern",
			Pattern: `test\d+`,
		},
	}

	m, err := NewHyperscan(rules, 0)
	require.NoError(t, err)
	require.NotNil(t, m)
	defer m.Close()

	assert.NotNil(t, m.db)
	assert.NotNil(t, m.scratch)
	assert.Len(t, m.rules, 1)
}

func TestNewHyperscan_InvalidPattern(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	rules := []*types.Rule{
		{
			ID:      "test.1",
			Name:    "Invalid",
			Pattern: `[invalid(`, // malformed regex
		},
	}

	m, err := NewHyperscan(rules, 0)
	require.Error(t, err)
	assert.Nil(t, m)
	assert.Contains(t, err.Error(), "compile")
}

func TestHyperscanMatcher_Match_NoMatches(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "AWS Key",
			Pattern:      `AKIA[0-9A-Z]{16}`,
			StructuralID: computeRuleStructuralID(`AKIA[0-9A-Z]{16}`),
		},
	}

	m, err := NewHyperscan(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	content := []byte("No API keys here!")
	matches, err := m.Match(content)

	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestHyperscanMatcher_Match_SingleMatch(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "AWS Key",
			Pattern:      `AKIA[0-9A-Z]{16}`,
			StructuralID: computeRuleStructuralID(`AKIA[0-9A-Z]{16}`),
		},
	}

	m, err := NewHyperscan(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	content := []byte("My key is AKIAIOSFODNN7EXAMPLE here")
	matches, err := m.Match(content)

	require.NoError(t, err)
	require.Len(t, matches, 1)

	match := matches[0]
	assert.Equal(t, "test.1", match.RuleID)
	assert.Equal(t, "AWS Key", match.RuleName)
	assert.Equal(t, int64(10), match.Location.Offset.Start)
	assert.Equal(t, int64(30), match.Location.Offset.End)
	assert.Equal(t, []byte("AKIAIOSFODNN7EXAMPLE"), match.Snippet.Matching)
	assert.NotEmpty(t, match.StructuralID)
}

func TestHyperscanMatcher_Match_WithCaptureGroups(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "Email",
			Pattern:      `(?P<user>[a-zA-Z0-9]+)@(?P<domain>[a-zA-Z0-9.]+)`,
			StructuralID: computeRuleStructuralID(`(?P<user>[a-zA-Z0-9]+)@(?P<domain>[a-zA-Z0-9.]+)`),
		},
	}

	m, err := NewHyperscan(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	content := []byte("Contact: user@example.com")
	matches, err := m.Match(content)

	require.NoError(t, err)
	require.Len(t, matches, 1)

	match := matches[0]
	assert.Equal(t, "test.1", match.RuleID)

	// Verify positional groups (deprecated but still populated for backwards compatibility)
	assert.Len(t, match.Groups, 2)
	assert.Equal(t, []byte("user"), match.Groups[0])
	assert.Equal(t, []byte("example.com"), match.Groups[1])

	// Verify named groups (preferred way to access captures)
	assert.NotNil(t, match.NamedGroups)
	assert.Equal(t, []byte("user"), match.NamedGroups["user"])
	assert.Equal(t, []byte("example.com"), match.NamedGroups["domain"])
}

func TestHyperscanMatcher_Match_MultipleRules(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "AWS Key",
			Pattern:      `AKIA[0-9A-Z]{16}`,
			StructuralID: computeRuleStructuralID(`AKIA[0-9A-Z]{16}`),
		},
		{
			ID:           "test.2",
			Name:         "Email",
			Pattern:      `[a-zA-Z0-9]+@[a-zA-Z0-9.]+`,
			StructuralID: computeRuleStructuralID(`[a-zA-Z0-9]+@[a-zA-Z0-9.]+`),
		},
	}

	m, err := NewHyperscan(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	content := []byte("Key: AKIAIOSFODNN7EXAMPLE, Email: user@example.com")
	matches, err := m.Match(content)

	require.NoError(t, err)
	assert.Len(t, matches, 2)

	// Check we found both patterns
	foundRules := make(map[string]bool)
	for _, match := range matches {
		foundRules[match.RuleID] = true
	}
	assert.True(t, foundRules["test.1"])
	assert.True(t, foundRules["test.2"])
}

func TestHyperscanMatcher_MatchWithBlobID(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "Test",
			Pattern:      `test\d+`,
			StructuralID: computeRuleStructuralID(`test\d+`),
		},
	}

	m, err := NewHyperscan(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	content := []byte("test123")
	blobID := types.ComputeBlobID(content)

	matches, err := m.MatchWithBlobID(content, blobID)

	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, blobID, matches[0].BlobID)
}

func TestHyperscanMatcher_Deduplication(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "Pattern",
			Pattern:      `test`,
			StructuralID: computeRuleStructuralID(`test`),
		},
	}

	m, err := NewHyperscan(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	// Same content scanned twice should deduplicate
	content := []byte("test")
	matches1, err := m.Match(content)
	require.NoError(t, err)

	matches2, err := m.Match(content)
	require.NoError(t, err)

	// Each scan should find the match, but internal deduplication within each scan
	require.Len(t, matches1, 1)
	require.Len(t, matches2, 1)

	// Structural IDs should be identical (same content, same location)
	assert.Equal(t, matches1[0].StructuralID, matches2[0].StructuralID)
}

func TestHyperscanMatcher_Close(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	rules := []*types.Rule{
		{
			ID:      "test.1",
			Name:    "Test",
			Pattern: `test`,
		},
	}

	m, err := NewHyperscan(rules, 0)
	require.NoError(t, err)

	err = m.Close()
	assert.NoError(t, err)

	// Verify resources were freed
	assert.Nil(t, m.scratch)
	assert.Nil(t, m.db)
}

func TestMatcher_New(t *testing.T) {
	if !hyperscanAvailable() {
		t.Skip("Hyperscan not available")
	}

	cfg := Config{
		Rules: []*types.Rule{
			{
				ID:      "test.1",
				Name:    "Test",
				Pattern: `test`,
			},
		},
		MaxMatchesPerBlob: 100,
	}

	m, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, m)
	defer m.Close()

	// Verify it's a Hyperscan matcher
	_, ok := m.(*HyperscanMatcher)
	assert.True(t, ok)
}
