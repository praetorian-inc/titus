package matcher

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	// CacheDirEnv overrides the standard per-user Titus cache directory.
	CacheDirEnv = "TITUS_CACHE_DIR"
)

// RulesCacheDir returns the directory where Titus caches compiled rule
// databases. It follows the operating system's per-user cache convention
// unless TITUS_CACHE_DIR is set.
func RulesCacheDir() (string, error) {
	if dir := os.Getenv(CacheDirEnv); dir != "" {
		return filepath.Join(dir, "rules"), nil
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve user cache directory: %w", err)
	}
	return filepath.Join(dir, "titus", "rules"), nil
}
