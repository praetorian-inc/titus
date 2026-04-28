package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Accessibility represents the determined or user-specified visibility of the code
// being scanned. Private code receives a score penalty because a secret found in
// private code is not world-readable and therefore less immediately dangerous.
type Accessibility int

const (
	AccessibilityAuto    Accessibility = iota // determine at startup; defaults to Private on failure
	AccessibilityPublic                       // code is world-readable; no score penalty
	AccessibilityPrivate                      // code is NOT world-readable; score penalty applied
)

// AccessibilityPenalty is the delta applied to all finding scores when the code
// is determined to be private. Negative means the score is reduced.
const AccessibilityPenalty = -25

// AccessibilityModifierName is the audit-trail name shown in Score.Applied.
const AccessibilityModifierName = "code-accessibility"

// githubRepoPattern matches "github.com/owner/repo" (with or without .git suffix).
var githubRepoPattern = regexp.MustCompile(`github\.com[:/]([^/]+)/([^/.]+?)(?:\.git)?$`)

// ResolveAccessibility determines actual code accessibility given the user's flag
// value and the scan target directory. For "auto", it tries to detect via the git
// remote URL and (optionally) the GitHub API. Always returns Public or Private.
func ResolveAccessibility(flag, target, token string) Accessibility {
	switch strings.ToLower(flag) {
	case "public":
		return AccessibilityPublic
	case "private":
		return AccessibilityPrivate
	}
	// "auto": try to detect
	return detectAccessibility(target, token)
}

// detectAccessibility inspects the git remote of target to determine visibility.
// Falls back to Private on any error (conservative default).
func detectAccessibility(target, token string) Accessibility {
	remoteURL, err := gitRemoteURL(target)
	if err != nil {
		// Not a git repo or no remote — assume private
		return AccessibilityPrivate
	}

	m := githubRepoPattern.FindStringSubmatch(remoteURL)
	if m == nil {
		// Not a GitHub remote — can't auto-detect, assume private
		return AccessibilityPrivate
	}

	owner, repo := m[1], m[2]
	isPrivate, err := githubRepoIsPrivate(owner, repo, token)
	if err != nil {
		// API call failed — conservative default
		fmt.Fprintf(os.Stderr, "[info] could not determine repo accessibility via GitHub API (%v); assuming private (use --accessibility to override)\n", err)
		return AccessibilityPrivate
	}

	if isPrivate {
		return AccessibilityPrivate
	}
	return AccessibilityPublic
}

// gitRemoteURL returns the URL of the git remote named "origin" for the given
// directory, or an error if the directory is not a git repo or has no remote.
func gitRemoteURL(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "config", "--get", "remote.origin.url")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git remote: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// githubRepoIsPrivate queries the GitHub REST API to check whether the given
// repo is private. An empty token causes an unauthenticated request (works for
// public repos; private repos will return 404 — treated conservatively as private).
func githubRepoIsPrivate(owner, repo, token string) (bool, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return true, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return true, fmt.Errorf("GitHub API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// 404 without auth = private repo (or doesn't exist); either way, private
		return true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return true, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var payload struct {
		Private bool `json:"private"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return true, fmt.Errorf("GitHub API response: %w", err)
	}
	return payload.Private, nil
}

// ApplyAccessibilityModifier applies the private-code score penalty to a finding's
// Score in-place. It appends a ScoreModifier entry to the audit trail and
// re-clamps the Final score.
//
// Call this AFTER engine.Score() so the accessibility modifier appears at the end
// of the Applied slice, after any rule-specific modifiers.
func ApplyAccessibilityModifier(score *types.Score) {
	if score == nil {
		return
	}
	score.Applied = append(score.Applied, types.ScoreModifier{
		Name:     AccessibilityModifierName,
		Scorer:   "scan-context",
		Kind:     "delta",
		Value:    AccessibilityPenalty,
		Priority: 0,
	})
	score.Final += AccessibilityPenalty
	if score.Final < 0 {
		score.Final = 0
	}
	if score.Final > 100 {
		score.Final = 100
	}
	score.SuggestedSeverity = types.SeverityForScore(score.Final)
}
