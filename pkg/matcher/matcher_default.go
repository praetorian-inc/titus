//go:build !wasm

package matcher

// New creates a Hyperscan-based matcher for native builds.
func New(cfg Config) (Matcher, error) {
	return NewHyperscan(cfg.Rules, cfg.ContextLines)
}
