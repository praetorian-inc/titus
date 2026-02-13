package prefilter

import (
	"github.com/cloudflare/ahocorasick"
	"github.com/praetorian-inc/titus/pkg/types"
)

// Prefilter uses Aho-Corasick for efficient keyword matching.
type Prefilter struct {
	matcher        *ahocorasick.Matcher
	keywords       []string              // keyword at each index
	keywordRules   map[string][]*types.Rule // keyword -> rules needing it
	noKeywordRules []*types.Rule         // rules without keywords (always checked)
}

// New creates a prefilter from rules.
func New(rules []*types.Rule) *Prefilter {
	pf := &Prefilter{
		keywordRules:   make(map[string][]*types.Rule),
		noKeywordRules: make([]*types.Rule, 0),
	}

	// Collect all keywords and build mapping
	keywordSet := make(map[string]bool)
	for _, rule := range rules {
		if len(rule.Keywords) == 0 {
			// No keywords = always check this rule
			pf.noKeywordRules = append(pf.noKeywordRules, rule)
		} else {
			// Map each keyword to this rule
			for _, keyword := range rule.Keywords {
				if !keywordSet[keyword] {
					keywordSet[keyword] = true
					pf.keywords = append(pf.keywords, keyword)
				}
				pf.keywordRules[keyword] = append(pf.keywordRules[keyword], rule)
			}
		}
	}

	// Build Aho-Corasick matcher if we have keywords
	if len(pf.keywords) > 0 {
		pf.matcher = ahocorasick.NewStringMatcher(pf.keywords)
	}

	return pf
}

// Filter returns rules that might match content (keywords found OR no keywords defined).
func (pf *Prefilter) Filter(content []byte) []*types.Rule {
	// Always include rules without keywords
	result := make([]*types.Rule, 0, len(pf.noKeywordRules))
	result = append(result, pf.noKeywordRules...)

	// If no Aho-Corasick matcher, return only no-keyword rules
	if pf.matcher == nil {
		return result
	}

	// Find all keyword matches in content
	hits := pf.matcher.Match(content)

	// Collect unique rules that have matching keywords
	seenRules := make(map[*types.Rule]bool)
	for _, rule := range pf.noKeywordRules {
		seenRules[rule] = true
	}

	for _, hit := range hits {
		keyword := pf.keywords[hit]
		for _, rule := range pf.keywordRules[keyword] {
			if !seenRules[rule] {
				seenRules[rule] = true
				result = append(result, rule)
			}
		}
	}

	return result
}
