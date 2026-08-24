package matcher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// CacheDirEnv overrides the standard per-user Titus cache directory.
	CacheDirEnv = "TITUS_CACHE_DIR"
)

// ErrHyperscanDatabaseUnavailable is returned by builds without the native
// Vectorscan/Hyperscan matcher.
var ErrHyperscanDatabaseUnavailable = errors.New("serialized Hyperscan databases require a cgo vectorscan build")

// RulesCacheDir returns the directory used by `titus rules compile` and by
// subsequent scanner instances. It follows the operating system's per-user
// cache convention unless TITUS_CACHE_DIR is set.
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
