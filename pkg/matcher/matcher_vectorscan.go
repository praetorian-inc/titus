//go:build !wasm && cgo && vectorscan

package matcher

// New creates a new Matcher using the Vectorscan/Hyperscan engine.
// This is the high-performance implementation that requires CGO and
// the Hyperscan/Vectorscan C library installed on the system.
//
// Build with: go build -tags vectorscan
//
// This file is only compiled when:
// - Not building for WASM
// - CGO is enabled
// - The "vectorscan" build tag is specified
func New(cfg Config) (Matcher, error) {
	return NewVectorscan(cfg.Rules, cfg.ContextLines)
}
