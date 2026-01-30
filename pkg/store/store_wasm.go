//go:build wasm

package store

// New creates an in-memory store for WASM builds.
// The cfg.Path is ignored since WASM doesn't have filesystem access.
func New(cfg Config) (Store, error) {
	return NewMemory(), nil
}
