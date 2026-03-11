//go:build wasm

package matcher

// New creates a regexp-based matcher for WASM builds.
func New(cfg Config) (Matcher, error) {
	inner, err := NewRegexp(cfg.Rules, cfg.ContextLines)
	if err != nil {
		return nil, err
	}
	filtered := newFilteringMatcher(inner, cfg.Rules)
	return newDedupMatcher(filtered, cfg.Rules), nil
}
