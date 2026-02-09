//go:build !wasm

package matcher

// New creates a regexp-based matcher (no CGO required).
// This uses the portable regexp2 implementation which is:
// - No CGO dependency (can build with CGO_ENABLED=0)
// - Finds more secrets (additional patterns detected in validation tests)
// - Comparable performance on small files, 3-5x slower on large files (see benchmarks)
//
// For maximum performance on large files, use NewHyperscan() with CGO_ENABLED=1 and -tags=hyperscan.
func New(cfg Config) (Matcher, error) {
	return NewPortableRegexp(cfg.Rules, cfg.ContextLines)
}
