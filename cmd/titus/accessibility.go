package main

import (
	"github.com/praetorian-inc/titus/pkg/accessibility"
	"github.com/praetorian-inc/titus/pkg/types"
)

// Accessibility is the CLI-level type alias for accessibility.Accessibility.
type Accessibility = accessibility.Accessibility

// Accessibility constants used by the CLI flags and scan logic.
const (
	AccessibilityAuto    = accessibility.Auto
	AccessibilityPublic  = accessibility.Public
	AccessibilityPrivate = accessibility.Private
)

// AccessibilityPenalty and AccessibilityModifierName are re-exported for
// CLI-local test compatibility.
const (
	AccessibilityPenalty      = accessibility.Penalty
	AccessibilityModifierName = accessibility.ModifierName
)

// githubRepoPattern is re-exported for CLI-local tests that inspect it directly.
var githubRepoPattern = accessibility.GitHubRepoPattern()

// ResolveAccessibility delegates to pkg/accessibility.Resolve.
func ResolveAccessibility(flag, target, token string) Accessibility {
	return accessibility.Resolve(flag, target, token)
}

// ApplyAccessibilityModifier delegates to pkg/accessibility.Apply.
func ApplyAccessibilityModifier(score *types.Score) {
	accessibility.Apply(score)
}
