package matcher

import "github.com/praetorian-inc/titus/pkg/types"

// filteringMatcher wraps a Matcher and applies post-match filtering based on
// min_entropy and pattern_requirements from rule definitions, then drops
// matches from hidden rules (visible: false). It sits below the cross-rule
// dedup wrapper, so a hidden helper match can never be the one a cluster keeps
// in place of a reportable match.
type filteringMatcher struct {
	inner  Matcher
	rules  map[string]*types.Rule
	hidden map[string]bool // IDs of hidden rules; empty when none are loaded
}

// newFilteringMatcher wraps a matcher with post-match filtering.
func newFilteringMatcher(inner Matcher, rules []*types.Rule) *filteringMatcher {
	ruleMap := make(map[string]*types.Rule, len(rules))
	hidden := make(map[string]bool)
	for _, r := range rules {
		ruleMap[r.ID] = r
		if r.Hidden {
			hidden[r.ID] = true
		}
	}
	return &filteringMatcher{inner: inner, rules: ruleMap, hidden: hidden}
}

func (f *filteringMatcher) Match(content []byte) ([]*types.Match, error) {
	matches, err := f.inner.Match(content)
	if err != nil {
		return nil, err
	}
	return f.filter(matches), nil
}

func (f *filteringMatcher) MatchWithBlobID(content []byte, blobID types.BlobID) ([]*types.Match, error) {
	matches, err := f.inner.MatchWithBlobID(content, blobID)
	if err != nil {
		return nil, err
	}
	return f.filter(matches), nil
}

func (f *filteringMatcher) DrainTimedOut() ([]*types.Match, error) {
	matches, err := f.inner.DrainTimedOut()
	if err != nil {
		return nil, err
	}
	return f.filter(matches), nil
}

func (f *filteringMatcher) Close() error {
	return f.inner.Close()
}

// filter applies the post-filters, then removes hidden-rule matches in place.
func (f *filteringMatcher) filter(matches []*types.Match) []*types.Match {
	matches = filterMatches(matches, f.rules)
	if len(f.hidden) == 0 {
		return matches
	}
	out := matches[:0]
	for _, m := range matches {
		if !f.hidden[m.RuleID] {
			out = append(out, m)
		}
	}
	return out
}
