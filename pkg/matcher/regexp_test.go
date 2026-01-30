//go:build wasm

package matcher

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// computeRuleStructuralID is a test helper to compute StructuralID for a rule pattern.
func computeRuleStructuralID(pattern string) string {
	r := &types.Rule{Pattern: pattern}
	return r.ComputeStructuralID()
}

func TestNewRegexp_NoRules(t *testing.T) {
	m, err := NewRegexp(nil, 0)
	require.Error(t, err)
	assert.Nil(t, m)
	assert.Contains(t, err.Error(), "no rules")
}

func TestNewRegexp_SingleRule(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test.1",
			Name:    "Test Pattern",
			Pattern: `test\d+`,
		},
	}

	m, err := NewRegexp(rules, 0)
	require.NoError(t, err)
	require.NotNil(t, m)

	assert.Len(t, m.rules, 1)
	assert.Len(t, m.regexCache, 1)
	assert.NotNil(t, m.regexCache[`test\d+`])
}

func TestNewRegexp_InvalidPattern(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test.1",
			Name:    "Invalid",
			Pattern: `[invalid(`, // malformed regex
		},
	}

	m, err := NewRegexp(rules, 0)
	require.Error(t, err)
	assert.Nil(t, m)
	assert.Contains(t, err.Error(), "compile")
}

func TestRegexpMatcher_Match_NoMatches(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "AWS Key",
			Pattern:      `AKIA[0-9A-Z]{16}`,
			StructuralID: computeRuleStructuralID(`AKIA[0-9A-Z]{16}`),
		},
	}

	m, err := NewRegexp(rules, 0)
	require.NoError(t, err)

	content := []byte("No API keys here!")
	matches, err := m.Match(content)

	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestRegexpMatcher_Match_SingleMatch(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "AWS Key",
			Pattern:      `AKIA[0-9A-Z]{16}`,
			StructuralID: computeRuleStructuralID(`AKIA[0-9A-Z]{16}`),
		},
	}

	m, err := NewRegexp(rules, 0)
	require.NoError(t, err)

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

func TestRegexpMatcher_Match_WithCaptureGroups(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "Email",
			Pattern:      `(?P<user>[a-zA-Z0-9]+)@(?P<domain>[a-zA-Z0-9.]+)`,
			StructuralID: computeRuleStructuralID(`(?P<user>[a-zA-Z0-9]+)@(?P<domain>[a-zA-Z0-9.]+)`),
		},
	}

	m, err := NewRegexp(rules, 0)
	require.NoError(t, err)

	content := []byte("Contact: user@example.com")
	matches, err := m.Match(content)

	require.NoError(t, err)
	require.Len(t, matches, 1)

	match := matches[0]
	assert.Equal(t, "test.1", match.RuleID)
	assert.Len(t, match.Groups, 2)
	assert.Equal(t, []byte("user"), match.Groups[0])
	assert.Equal(t, []byte("example.com"), match.Groups[1])
}

func TestRegexpMatcher_Match_MultipleRules(t *testing.T) {
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

	m, err := NewRegexp(rules, 0)
	require.NoError(t, err)

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

func TestRegexpMatcher_MatchWithBlobID(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "Test",
			Pattern:      `test\d+`,
			StructuralID: computeRuleStructuralID(`test\d+`),
		},
	}

	m, err := NewRegexp(rules, 0)
	require.NoError(t, err)

	content := []byte("test123")
	blobID := types.ComputeBlobID(content)

	matches, err := m.MatchWithBlobID(content, blobID)

	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, blobID, matches[0].BlobID)
}

func TestRegexpMatcher_Deduplication(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "Pattern",
			Pattern:      `test`,
			StructuralID: computeRuleStructuralID(`test`),
		},
	}

	m, err := NewRegexp(rules, 0)
	require.NoError(t, err)

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

func TestRegexpMatcher_Close(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test.1",
			Name:    "Test",
			Pattern: `test`,
		},
	}

	m, err := NewRegexp(rules, 0)
	require.NoError(t, err)

	// Close should be a no-op but return no error
	err = m.Close()
	assert.NoError(t, err)
}

func TestRegexpMatcher_Context_NoContext(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "Pattern",
			Pattern:      `test`,
			StructuralID: computeRuleStructuralID(`test`),
		},
	}

	m, err := NewRegexp(rules, 0) // 0 context lines
	require.NoError(t, err)

	content := []byte("before\ntest\nafter")
	matches, err := m.Match(content)

	require.NoError(t, err)
	require.Len(t, matches, 1)

	match := matches[0]
	assert.Empty(t, match.Snippet.Before)
	assert.Empty(t, match.Snippet.After)
	assert.Equal(t, []byte("test"), match.Snippet.Matching)
}

func TestRegexpMatcher_Context_WithContext(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "Pattern",
			Pattern:      `test`,
			StructuralID: computeRuleStructuralID(`test`),
		},
	}

	m, err := NewRegexp(rules, 1) // 1 context line
	require.NoError(t, err)

	content := []byte("before\ntest\nafter")
	matches, err := m.Match(content)

	require.NoError(t, err)
	require.Len(t, matches, 1)

	match := matches[0]
	assert.Equal(t, []byte("before\n"), match.Snippet.Before)
	assert.Equal(t, []byte("test"), match.Snippet.Matching)
	assert.Equal(t, []byte("\nafter"), match.Snippet.After)
}

func TestRegexpMatcher_MultipleMatches_SameRule(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "Pattern",
			Pattern:      `test\d+`,
			StructuralID: computeRuleStructuralID(`test\d+`),
		},
	}

	m, err := NewRegexp(rules, 0)
	require.NoError(t, err)

	content := []byte("test1 and test2 and test3")
	matches, err := m.Match(content)

	require.NoError(t, err)
	require.Len(t, matches, 3)

	// Verify each match
	assert.Equal(t, []byte("test1"), matches[0].Snippet.Matching)
	assert.Equal(t, []byte("test2"), matches[1].Snippet.Matching)
	assert.Equal(t, []byte("test3"), matches[2].Snippet.Matching)

	// All should have the same rule ID
	for _, match := range matches {
		assert.Equal(t, "test.1", match.RuleID)
	}
}

func TestRegexpMatcher_EmptyContent(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:           "test.1",
			Name:         "Pattern",
			Pattern:      `test`,
			StructuralID: computeRuleStructuralID(`test`),
		},
	}

	m, err := NewRegexp(rules, 0)
	require.NoError(t, err)

	content := []byte("")
	matches, err := m.Match(content)

	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestMatcher_New_WASM(t *testing.T) {
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

	// Verify it's a Regexp matcher (in WASM builds)
	_, ok := m.(*RegexpMatcher)
	assert.True(t, ok)
}
