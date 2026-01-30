//go:build wasm

package matcher

// New creates a regexp-based matcher for WASM builds.
func New(cfg Config) (Matcher, error) {
	return NewRegexp(cfg.Rules, cfg.ContextLines)
}
