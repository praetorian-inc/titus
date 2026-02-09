//go:build !wasm

package store

import "fmt"

// New creates a store for native builds (pure Go, no CGO).
// Only MemoryStore is supported. SQLite support has been removed.
// For persistent storage needs, use the memory store with external serialization.
func New(cfg Config) (Store, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("path is required")
	}

	// Only memory store supported (pure Go)
	if cfg.Path == ":memory:" {
		return NewMemory(), nil
	}

	// File-based storage (SQLite) removed - pure Go only
	return nil, fmt.Errorf("file-based storage not supported (SQLite removed). Use :memory: for pure Go builds")
}
