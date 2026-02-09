//go:build !wasm && !cgo

package store

import "fmt"

// New creates a store for native builds without CGO.
// Only MemoryStore is available (SQLite requires CGO).
func New(cfg Config) (Store, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("path is required")
	}

	// Only MemoryStore is available without CGO
	if cfg.Path != ":memory:" {
		return nil, fmt.Errorf("SQLite requires CGO (build with CGO_ENABLED=1). For non-CGO builds, use :memory: path")
	}

	return NewMemory(), nil
}
