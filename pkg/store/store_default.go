//go:build !wasm && cgo

package store

import "fmt"

// New creates a store for native builds.
// By default, uses MemoryStore (no CGO required).
// For ":memory:" paths, returns MemoryStore.
// For file paths, returns SQLite (requires CGO).
func New(cfg Config) (Store, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("path is required")
	}

	// Use MemoryStore for :memory: paths (no CGO)
	if cfg.Path == ":memory:" {
		return NewMemory(), nil
	}

	// Use SQLite for file paths (requires CGO - user must build with CGO_ENABLED=1)
	return NewSQLite(cfg.Path)
}
