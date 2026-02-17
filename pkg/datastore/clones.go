package datastore

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		return "", fmt.Errorf("cloning repository: %w (output: %s)", err, string(output))
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

	var host, path string

	// Handle git@host:path format (SSH)
	if strings.HasPrefix(repoURL, "git@") {
		// git@github.com:org/repo.git -> github.com/org/repo
		parts := strings.SplitN(strings.TrimPrefix(repoURL, "git@"), ":", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid SSH URL format: %s", repoURL)
		}
		host = parts[0]
		path = parts[1]
	} else {
		// Handle https:// or http:// format
		parsed, err := url.Parse(repoURL)
		if err != nil {
			return "", fmt.Errorf("parsing repository URL: %w", err)
		}

		if parsed.Host == "" {
			return "", fmt.Errorf("invalid repository URL (missing host): %s", repoURL)
		}

		host = parsed.Host
		path = strings.TrimPrefix(parsed.Path, "/")
	}

	// Strip .git suffix if present
	path = strings.TrimSuffix(path, ".git")

	// Add .git suffix to cache directory name
	path = path + ".git"

	// Construct full cache path
	cachePath := filepath.Join(c.Root, host, path)

	return cachePath, nil
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
