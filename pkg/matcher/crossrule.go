package matcher

import (
	"github.com/praetorian-inc/titus/pkg/types"
)

// CrossRuleDeduplicator suppresses redundant matches across different rules
// within the same blob when they detect the same underlying secret.
//
// When multiple rules (e.g., np.aws.1, np.aws.2, np.aws.6) match overlapping
// credential data in the same file, only the most informative match is kept.
// Matches are clustered by shared captured group values, then scored.
type CrossRuleDeduplicator struct {
	rules       map[string]*types.Rule
	canValidate func(ruleID string) bool
}

// NewCrossRuleDeduplicator creates a deduplicator with rule metadata and
// validator awareness.
func NewCrossRuleDeduplicator(
	rules map[string]*types.Rule,
	canValidate func(ruleID string) bool,
) *CrossRuleDeduplicator {
	return &CrossRuleDeduplicator{
		rules:       rules,
		canValidate: canValidate,
	}
}

// SetCanValidate updates the validator awareness function after construction.
// Passing nil disables validator-based scoring (all rules treated equally).
func (d *CrossRuleDeduplicator) SetCanValidate(fn func(ruleID string) bool) {
	d.canValidate = fn
}

// Deduplicate takes all matches from a single blob and returns only the
// non-redundant subset. Matches are clustered by shared captured group values,
// then for each cluster the most informative match is kept.
func (d *CrossRuleDeduplicator) Deduplicate(matches []*types.Match) []*types.Match {
	if len(matches) <= 1 {
		return matches
	}

	clusters := d.clusterBySharedValues(matches)

	result := make([]*types.Match, 0, len(matches))
	for _, cluster := range clusters {
		if len(cluster) == 1 {
			result = append(result, cluster[0])
			continue
		}
		winner := d.pickWinner(cluster)
		result = append(result, winner)
	}
	return result
}

// clusterBySharedValues groups matches whose captured group values overlap.
// Uses union-find: if match A and match B share any exact group value,
// they belong to the same cluster.
func (d *CrossRuleDeduplicator) clusterBySharedValues(matches []*types.Match) [][]*types.Match {
	n := len(matches)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}

	find := func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]] // path compression
			x = parent[x]
		}
		return x
	}

	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}

	// Map: group value → index of first match that has it
	valueIndex := make(map[string]int)

	for i, m := range matches {
		for _, g := range m.Groups {
			val := string(g)
			if val == "" {
				continue
			}
			if prev, exists := valueIndex[val]; exists {
				union(i, prev)
			} else {
				valueIndex[val] = i
			}
		}
	}

	// Collect clusters by root
	clusterMap := make(map[int][]*types.Match)
	for i, m := range matches {
		root := find(i)
		clusterMap[root] = append(clusterMap[root], m)
	}

	clusters := make([][]*types.Match, 0, len(clusterMap))
	for _, c := range clusterMap {
		clusters = append(clusters, c)
	}
	return clusters
}

// pickWinner selects the most informative match from a cluster.
// Priority: has validator > group count > total captured length > pattern length.
func (d *CrossRuleDeduplicator) pickWinner(cluster []*types.Match) *types.Match {
	best := 0
	bestScore := d.score(cluster[0])
	for i := 1; i < len(cluster); i++ {
		s := d.score(cluster[i])
		if s.Better(bestScore) {
			best = i
			bestScore = s
		}
	}
	return cluster[best]
}

// score computes the ranking criteria for a match.
func (d *CrossRuleDeduplicator) score(m *types.Match) matchScore {
	hasValidator := false
	if d.canValidate != nil {
		hasValidator = d.canValidate(m.RuleID)
	}

	groupsLen := 0
	for _, g := range m.Groups {
		groupsLen += len(g)
	}

	patternLen := 0
	if r, ok := d.rules[m.RuleID]; ok {
		patternLen = len(r.Pattern)
	}

	return matchScore{
		hasValidator: hasValidator,
		groupCount:   len(m.Groups),
		groupsLen:    groupsLen,
		patternLen:   patternLen,
	}
}

// matchScore captures the ranking criteria for comparing matches.
type matchScore struct {
	hasValidator bool
	groupCount   int
	groupsLen    int
	patternLen   int
}

// Better returns true if s is ranked higher than other.
func (s matchScore) Better(other matchScore) bool {
	if s.hasValidator != other.hasValidator {
		return s.hasValidator
	}
	if s.groupCount != other.groupCount {
		return s.groupCount > other.groupCount
	}
	if s.groupsLen != other.groupsLen {
		return s.groupsLen > other.groupsLen
	}
	return s.patternLen > other.patternLen
}
