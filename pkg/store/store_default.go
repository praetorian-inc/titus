//go:build !wasm

package store

import "fmt"

// New creates a store for native builds using modernc.org/sqlite (pure Go, no CGO).
func New(cfg Config) (Store, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("path is required")
	}

	// Memory store
	if cfg.Path == ":memory:" {
		return NewMemory(), nil
	}

	// File-based storage using modernc.org/sqlite
	return NewSQLite(cfg.Path)
}
