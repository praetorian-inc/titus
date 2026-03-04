package matcher

import "github.com/praetorian-inc/titus/pkg/types"

// filteringMatcher wraps a Matcher and applies post-match filtering
// based on min_entropy and pattern_requirements from rule definitions.
type filteringMatcher struct {
	inner Matcher
	rules map[string]*types.Rule
}

// newFilteringMatcher wraps a matcher with post-match filtering.
func newFilteringMatcher(inner Matcher, rules []*types.Rule) *filteringMatcher {
	ruleMap := make(map[string]*types.Rule, len(rules))
	for _, r := range rules {
		ruleMap[r.ID] = r
	}
	return &filteringMatcher{inner: inner, rules: ruleMap}
}

func (f *filteringMatcher) Match(content []byte) ([]*types.Match, error) {
	matches, err := f.inner.Match(content)
	if err != nil {
		return nil, err
	}
	return filterMatches(matches, f.rules), nil
}

func (f *filteringMatcher) MatchWithBlobID(content []byte, blobID types.BlobID) ([]*types.Match, error) {
	matches, err := f.inner.MatchWithBlobID(content, blobID)
	if err != nil {
		return nil, err
	}
	return filterMatches(matches, f.rules), nil
}

func (f *filteringMatcher) Close() error {
	return f.inner.Close()
}
