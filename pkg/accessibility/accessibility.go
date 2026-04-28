// Package accessibility resolves and applies code-visibility modifiers to
// finding scores. It is shared between the CLI (cmd/titus) and the
// programmatic API (titus.go).
package accessibility

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

// Accessibility represents the determined or user-specified visibility of the
// code being scanned. Private code receives a score penalty because a secret
// found there is not world-readable and therefore less immediately dangerous.
type Accessibility int

const (
	Auto    Accessibility = iota // detect at startup; defaults to Private on failure
	Public                       // code is world-readable; no score penalty
	Private                      // code is NOT world-readable; score penalty applied
)

// Penalty is the delta applied to all finding scores when code is private.
const Penalty = -25

// ModifierName is the audit-trail name shown in Score.Applied.
const ModifierName = "code-accessibility"

// githubRepoPattern matches "github.com/owner/repo" (with or without .git suffix).
var githubRepoPattern = regexp.MustCompile(`github\.com[:/]([^/]+)/([^/.]+?)(?:\.git)?$`)

// GitHubRepoPattern returns the compiled regular expression used to extract
// owner and repo from a GitHub remote URL. Exported for CLI wrapper use.
func GitHubRepoPattern() *regexp.Regexp {
	return githubRepoPattern
}

// Resolve returns the actual Public or Private value given the mode string
// ("public", "private", "auto"), target directory, and optional GitHub token.
// Always returns Public or Private (never Auto).
func Resolve(mode, target, token string) Accessibility {
	switch strings.ToLower(mode) {
	case "public":
		return Public
	case "private":
		return Private
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
		return Private
	}

	m := githubRepoPattern.FindStringSubmatch(remoteURL)
	if m == nil {
		// Not a GitHub remote — can't auto-detect, assume private
		return Private
	}

	owner, repo := m[1], m[2]
	isPrivate, err := githubRepoIsPrivate(owner, repo, token)
	if err != nil {
		// API call failed — conservative default
		fmt.Fprintf(os.Stderr, "[info] could not determine repo accessibility via GitHub API (%v); assuming private (use --accessibility to override)\n", err)
		return Private
	}

	if isPrivate {
		return Private
	}
	return Public
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

// Apply applies the private-code score penalty to a finding's Score in-place.
// It appends a ScoreModifier entry and re-clamps the Final score.
// Must be called AFTER engine.Score() so it appears last in Applied.
func Apply(score *types.Score) {
	if score == nil {
		return
	}
	score.Applied = append(score.Applied, types.ScoreModifier{
		Name:     ModifierName,
		Scorer:   "scan-context",
		Kind:     "delta",
		Value:    Penalty,
		Priority: 0,
	})
	score.Final += Penalty
	if score.Final < 0 {
		score.Final = 0
	}
	if score.Final > 100 {
		score.Final = 100
	}
	score.SuggestedSeverity = types.SeverityForScore(score.Final)
}
