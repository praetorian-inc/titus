package main

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveAccessibility_ExplicitFlags(t *testing.T) {
	assert.Equal(t, AccessibilityPublic, ResolveAccessibility("public", "/any", ""))
	assert.Equal(t, AccessibilityPublic, ResolveAccessibility("PUBLIC", "/any", ""))
	assert.Equal(t, AccessibilityPrivate, ResolveAccessibility("private", "/any", ""))
	assert.Equal(t, AccessibilityPrivate, ResolveAccessibility("PRIVATE", "/any", ""))
}

func TestResolveAccessibility_AutoFallsBackToPrivate(t *testing.T) {
	// /tmp is not a git repo — auto should fall back to private
	got := ResolveAccessibility("auto", "/tmp", "")
	assert.Equal(t, AccessibilityPrivate, got)
}

func TestGithubRepoPattern(t *testing.T) {
	cases := []struct {
		url         string
		owner       string
		repo        string
		shouldMatch bool
	}{
		{"https://github.com/praetorian-inc/titus.git", "praetorian-inc", "titus", true},
		{"git@github.com:praetorian-inc/titus.git", "praetorian-inc", "titus", true},
		{"https://github.com/octocat/Hello-World", "octocat", "Hello-World", true},
		{"https://gitlab.com/owner/repo", "", "", false},
		{"not-a-url", "", "", false},
	}
	for _, c := range cases {
		m := githubRepoPattern.FindStringSubmatch(c.url)
		if c.shouldMatch {
			require.NotNil(t, m, "expected match for %q", c.url)
			assert.Equal(t, c.owner, m[1])
			assert.Equal(t, c.repo, m[2])
		} else {
			assert.Nil(t, m, "expected no match for %q", c.url)
		}
	}
}

func TestApplyAccessibilityModifier_AppliesPenalty(t *testing.T) {
	score := &types.Score{
		Final:             80,
		Base:              80,
		SuggestedSeverity: "critical",
		Applied:           []types.ScoreModifier{},
	}
	ApplyAccessibilityModifier(score)
	assert.Equal(t, 55, score.Final, "80 + (-25) = 55")
	assert.Equal(t, "medium", score.SuggestedSeverity)
	require.Len(t, score.Applied, 1)
	assert.Equal(t, AccessibilityModifierName, score.Applied[0].Name)
	assert.Equal(t, AccessibilityPenalty, score.Applied[0].Value)
}

func TestApplyAccessibilityModifier_ClampsToZero(t *testing.T) {
	score := &types.Score{Final: 10, Applied: []types.ScoreModifier{}}
	ApplyAccessibilityModifier(score)
	assert.Equal(t, 0, score.Final, "10 + (-25) clamps to 0")
}

func TestApplyAccessibilityModifier_NilSafe(t *testing.T) {
	assert.NotPanics(t, func() { ApplyAccessibilityModifier(nil) })
}
