//go:build !wasm

package store

import "fmt"

// New creates a SQLite-based store for native builds.
func New(cfg Config) (Store, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	return NewSQLite(cfg.Path)
}
