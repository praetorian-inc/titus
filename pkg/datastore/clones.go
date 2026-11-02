package datastore

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/titus/pkg/repoid"
)

// GetOrClone returns path to cached bare clone, cloning if needed.
// For remote URLs (https://..., git@...), clones to cache.
// For local paths, returns the path unchanged (no caching).
func (c *CloneCache) GetOrClone(repoURL string) (string, error) {
	if repoURL == "" {
		return "", fmt.Errorf("repository URL is required")
	}

	// Check if this is a local path
	if isLocalPath(repoURL) {
		// For local paths, return as-is (no caching)
		return repoURL, nil
	}

	// For remote URLs, use cache
	cachePath, err := c.clonePath(repoURL)
	if err != nil {
		return "", fmt.Errorf("determining clone path: %w", err)
	}

	// Check if clone already exists
	if c.Exists(repoURL) {
		return cachePath, nil
	}

	// Create parent directory
	if err := os.MkdirAll(filepath.Dir(cachePath), 0755); err != nil {
		return "", fmt.Errorf("creating clone directory: %w", err)
	}

	// Clone as bare repository
	cmd := exec.Command("git", "clone", "--bare", repoURL, cachePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		// git may echo the URL; keep userinfo out of the error.
		out := strings.ReplaceAll(string(output), repoURL, repoid.RedactUserinfo(repoURL))
		return "", fmt.Errorf("cloning repository: %w (output: %s)", err, out)
	}

	return cachePath, nil
}

// Update fetches latest refs for a cached clone.
func (c *CloneCache) Update(repoURL string) error {
	if repoURL == "" {
		return fmt.Errorf("repository URL is required")
	}

	// Local paths don't need updating
	if isLocalPath(repoURL) {
		return nil
	}

	// Get cache path
	cachePath, err := c.clonePath(repoURL)
	if err != nil {
		return fmt.Errorf("determining clone path: %w", err)
	}

	// Check if clone exists
	if !c.Exists(repoURL) {
		return fmt.Errorf("clone does not exist: %s", cachePath)
	}

	// Fetch all refs
	cmd := exec.Command("git", "-C", cachePath, "fetch", "--all")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("fetching updates: %w (output: %s)", err, string(output))
	}

	return nil
}

// Exists checks if a clone is cached.
func (c *CloneCache) Exists(repoURL string) bool {
	if repoURL == "" {
		return false
	}

	// Local paths always "exist" if they're local
	if isLocalPath(repoURL) {
		_, err := os.Stat(repoURL)
		return err == nil
	}

	// Check if cached clone exists
	cachePath, err := c.clonePath(repoURL)
	if err != nil {
		return false
	}

	// Check if directory exists and contains a valid git repository
	info, err := os.Stat(cachePath)
	if err != nil {
		return false
	}

	if !info.IsDir() {
		return false
	}

	// Verify it's a valid git repository by checking for refs directory
	refsPath := filepath.Join(cachePath, "refs")
	if _, err := os.Stat(refsPath); err != nil {
		return false
	}

	return true
}

// clonePath returns the cache path for a repo URL.
// Maps URL to path: https://github.com/org/repo -> clones/github.com/org/repo.git
func (c *CloneCache) clonePath(repoURL string) (string, error) {
	if repoURL == "" {
		return "", fmt.Errorf("repository URL is required")
	}

	// Errors report the redacted URL so userinfo (user:token@) never leaks.
	redacted := repoid.RedactUserinfo(repoURL)
	var host, path string

	// Handle git@host:path format (SSH)
	if strings.HasPrefix(repoURL, "git@") {
		// git@github.com:org/repo.git -> github.com/org/repo
		parts := strings.SplitN(strings.TrimPrefix(repoURL, "git@"), ":", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid SSH URL format: %s", redacted)
		}
		host = parts[0]
		path = parts[1]
	} else {
		// Handle https:// or http:// format
		parsed, err := url.Parse(repoURL)
		if err != nil {
			// *url.Error embeds the raw URL; report only its cause.
			var uerr *url.Error
			if errors.As(err, &uerr) {
				err = uerr.Err
			}
			return "", fmt.Errorf("parsing repository URL %s: %w", redacted, err)
		}

		if parsed.Host == "" {
			return "", fmt.Errorf("invalid repository URL (missing host): %s", redacted)
		}

		host = parsed.Host
		path = strings.TrimPrefix(parsed.Path, "/")
	}

	if err := validateCloneHost(host); err != nil {
		return "", err
	}
	// Backslash is a separator on Windows; reject it on every OS.
	if strings.Contains(path, `\`) {
		return "", fmt.Errorf("invalid repository URL (backslash in path): %s", redacted)
	}
	for seg := range strings.SplitSeq(path, "/") {
		if seg == ".." {
			return "", fmt.Errorf("invalid repository URL (path traversal): %s", redacted)
		}
	}

	// Strip .git suffix if present
	path = strings.TrimSuffix(path, ".git")

	// Add .git suffix to cache directory name
	path = path + ".git"

	// Construct full cache path
	cachePath := filepath.Join(c.Root, host, path)
	// Contain within the host directory so one host cannot alias another's cache.
	if !isStrictlyWithin(filepath.Join(c.Root, host), cachePath) {
		return "", fmt.Errorf("invalid repository URL (escapes clone cache): %s", redacted)
	}

	return cachePath, nil
}

// validateCloneHost rejects hosts that would steer the cache path outside its host directory.
func validateCloneHost(host string) error {
	if host == "" || host == "." || host == ".." || strings.ContainsAny(host, `/\`) {
		return fmt.Errorf("invalid repository host: %q", host)
	}
	return nil
}

// isStrictlyWithin reports whether target is inside root and is not root itself.
func isStrictlyWithin(root, target string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || rel == "." || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// isLocalPath checks if the path is a local filesystem path.
func isLocalPath(path string) bool {
	if path == "" {
		return false
	}

	// Absolute paths starting with / or drive letter (Windows)
	if filepath.IsAbs(path) {
		return true
	}

	// Relative paths starting with ./ or ../
	if strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
		return true
	}

	// Check if it looks like a URL (has :// or starts with git@)
	if strings.Contains(path, "://") || strings.HasPrefix(path, "git@") {
		return false
	}

	// If it doesn't look like a URL, treat as local path
	// This handles relative paths without ./ prefix
	return true
}
