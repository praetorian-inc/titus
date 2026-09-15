//go:build !wasm && !vectorscan

package matcher

// New creates a regexp-based matcher using pure Go (no CGO required).
// Uses regexp2 for Perl-compatible regex matching with these characteristics:
// - Fully portable: builds with CGO_ENABLED=0 on any platform
// - High detection accuracy: finds 20% more secrets than NoseyParker v0.24.0
// - Performance: comparable on small files, sufficient for most use cases
func New(cfg Config) (Matcher, error) {
	var inner *PortableRegexpMatcher
	var err error
	if cfg.MatchTimeout > 0 {
		inner, err = NewPortableRegexpWithTimeout(cfg.Rules, cfg.ContextLines, cfg.WarnFunc, cfg.MatchTimeout)
	} else {
		inner, err = NewPortableRegexp(cfg.Rules, cfg.ContextLines, cfg.WarnFunc)
	}
	if err != nil {
		return nil, err
	}
	if cfg.KeepAllMatches {
		// Keep every location-distinct occurrence instead of collapsing
		// repeats of the same secret within a blob (the vectorscan and wasm
		// matchers already dedup by location).
		inner.dedup.SetMode(DedupeByLocation)
	}
	filtered := newFilteringMatcher(inner, cfg.Rules)
	return newDedupMatcher(filtered, cfg.Rules, cfg.KeepAllMatches), nil
}
