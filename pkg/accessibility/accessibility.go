// Package accessibility resolves and applies code-visibility modifiers to
// finding scores. It is shared between the CLI (cmd/titus) and the
// programmatic API (titus.go).
package accessibility

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

// API base URLs — overridable in tests.
var (
	gitlabAPIBase    = "https://gitlab.com/api/v4"
	bitbucketAPIBase = "https://api.bitbucket.org/2.0"
)

// githubRepoPattern matches "github.com/owner/repo" (with or without .git suffix).
var githubRepoPattern = regexp.MustCompile(`github\.com[:/]([^/]+)/([^/.]+?)(?:\.git)?$`)

// gitlabRepoPattern matches "gitlab.com/owner/repo" or nested groups like
// "gitlab.com/group/subgroup/repo" (with or without .git suffix).
var gitlabRepoPattern = regexp.MustCompile(`gitlab\.com[:/](.+?)(?:\.git)?$`)

// bitbucketRepoPattern matches "bitbucket.org/workspace/repo" (with or without .git suffix).
var bitbucketRepoPattern = regexp.MustCompile(`bitbucket\.org[:/]([^/]+)/([^/.]+?)(?:\.git)?$`)

// GitHubRepoPattern returns the compiled regular expression used to extract
// owner and repo from a GitHub remote URL. Exported for CLI wrapper use.
func GitHubRepoPattern() *regexp.Regexp {
	return githubRepoPattern
}

// Resolve returns the actual Public or Private value given the mode string
// ("public", "private", "auto"), target directory, and optional SCM token.
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
// Detection is attempted in order: GitHub → GitLab → Bitbucket.
func detectAccessibility(target, token string) Accessibility {
	remoteURL, err := gitRemoteURL(target)
	if err != nil {
		// Not a git repo or no remote — assume private
		return Private
	}

	// GitHub
	if m := githubRepoPattern.FindStringSubmatch(remoteURL); m != nil {
		tok := token
		if tok == "" {
			tok = os.Getenv("GITHUB_TOKEN")
		}
		isPrivate, err := githubRepoIsPrivate(m[1], m[2], tok)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[info] could not determine repo accessibility via GitHub API (%v); assuming private\n", err)
			return Private
		}
		if isPrivate {
			return Private
		}
		return Public
	}

	// GitLab
	if m := gitlabRepoPattern.FindStringSubmatch(remoteURL); m != nil {
		tok := token
		if tok == "" {
			tok = os.Getenv("GITLAB_TOKEN")
		}
		isPrivate, err := gitlabRepoIsPrivate(m[1], tok)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[info] could not determine repo accessibility via GitLab API (%v); assuming private\n", err)
			return Private
		}
		if isPrivate {
			return Private
		}
		return Public
	}

	// Bitbucket
	if m := bitbucketRepoPattern.FindStringSubmatch(remoteURL); m != nil {
		tok := token
		if tok == "" {
			tok = os.Getenv("BITBUCKET_TOKEN")
		}
		isPrivate, err := bitbucketRepoIsPrivate(m[1], m[2], tok)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[info] could not determine repo accessibility via Bitbucket API (%v); assuming private\n", err)
			return Private
		}
		if isPrivate {
			return Private
		}
		return Public
	}

	// Unknown hosting platform — assume private
	return Private
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

// gitlabRepoIsPrivate queries the GitLab REST API to check whether the given
// repo path (e.g. "group/subgroup/repo") is private. An empty token causes an
// unauthenticated request. "internal" visibility is treated as private because
// it is only visible to authenticated GitLab members, not the public.
// 401 Unauthorized is also treated as private.
func gitlabRepoIsPrivate(repoPath, token string) (bool, error) {
	// URL-encode the path: "group/subgroup/repo" → "group%2Fsubgroup%2Frepo"
	// We must use url.URL with RawPath to prevent Go's HTTP transport from
	// normalizing %2F back to / before sending the request.
	cleanPath := strings.TrimPrefix(repoPath, "/")
	encoded := strings.ReplaceAll(cleanPath, "/", "%2F")
	rawPath := "/projects/" + encoded
	// Path uses the decoded form so url.URL is internally consistent.
	decodedPath := "/projects/" + strings.ReplaceAll(cleanPath, "/", "/")

	base, err := url.Parse(gitlabAPIBase)
	if err != nil {
		return true, fmt.Errorf("GitLab API base URL: %w", err)
	}
	base.Path = decodedPath
	base.RawPath = rawPath

	req, err := http.NewRequest(http.MethodGet, base.String(), nil)
	if err != nil {
		return true, err
	}
	// Restore RawPath after NewRequest parses the URL (NewRequest may clear it).
	req.URL.Path = decodedPath
	req.URL.RawPath = rawPath
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return true, fmt.Errorf("GitLab API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized {
		// not found or forbidden = private
		return true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return true, fmt.Errorf("GitLab API returned %d", resp.StatusCode)
	}

	var payload struct {
		Visibility string `json:"visibility"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return true, fmt.Errorf("GitLab API response: %w", err)
	}
	// "internal" = only GitLab members, not truly public → treat as private
	return payload.Visibility != "public", nil
}

// bitbucketRepoIsPrivate queries the Bitbucket REST API to check whether the
// given workspace/repoSlug is private. An empty token causes an unauthenticated
// request. 403 Forbidden is treated as private.
func bitbucketRepoIsPrivate(workspace, repoSlug, token string) (bool, error) {
	url := fmt.Sprintf("%s/repositories/%s/%s", bitbucketAPIBase, workspace, repoSlug)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return true, err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return true, fmt.Errorf("Bitbucket API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		return true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return true, fmt.Errorf("Bitbucket API returned %d", resp.StatusCode)
	}

	var payload struct {
		IsPrivate bool `json:"is_private"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return true, fmt.Errorf("Bitbucket API response: %w", err)
	}
	return payload.IsPrivate, nil
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
