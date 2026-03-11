package matcher

import "github.com/praetorian-inc/titus/pkg/types"

// dedupMatcher wraps a Matcher and applies cross-rule deduplication
// to suppress redundant matches from different rules detecting the same secret.
type dedupMatcher struct {
	inner Matcher
	dedup *CrossRuleDeduplicator
}

// newDedupMatcher wraps a matcher with cross-rule deduplication.
func newDedupMatcher(inner Matcher, rules []*types.Rule) *dedupMatcher {
	ruleMap := make(map[string]*types.Rule, len(rules))
	for _, r := range rules {
		ruleMap[r.ID] = r
	}
	return &dedupMatcher{
		inner: inner,
		dedup: NewCrossRuleDeduplicator(ruleMap, nil),
	}
}

func (d *dedupMatcher) Match(content []byte) ([]*types.Match, error) {
	matches, err := d.inner.Match(content)
	if err != nil {
		return nil, err
	}
	return d.dedup.Deduplicate(matches), nil
}

func (d *dedupMatcher) MatchWithBlobID(content []byte, blobID types.BlobID) ([]*types.Match, error) {
	matches, err := d.inner.MatchWithBlobID(content, blobID)
	if err != nil {
		return nil, err
	}
	return d.dedup.Deduplicate(matches), nil
}

func (d *dedupMatcher) Close() error {
	return d.inner.Close()
}

// SetCanValidate upgrades the deduplicator in a matcher chain with validator awareness.
// If the matcher doesn't contain a dedupMatcher, this is a no-op.
func SetCanValidate(m Matcher, fn func(ruleID string) bool) {
	if dm, ok := m.(*dedupMatcher); ok {
		dm.dedup.SetCanValidate(fn)
	}
}
