package rule

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

// FilterConfig specifies include and exclude patterns for rule filtering.
type FilterConfig struct {
	Include []string // Regex patterns - only matching rules included
	Exclude []string // Regex patterns - matching rules excluded
}

// ParsePatterns splits a comma-separated string into individual patterns.
// Patterns are trimmed of whitespace.
func ParsePatterns(patterns string) []string {
	if patterns == "" {
		return []string{}
	}

	parts := strings.Split(patterns, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// Filter applies include and exclude patterns to rules.
// Include is applied first, then exclude.
// Empty include means "include all".
// Returns error if any pattern is invalid regex.
func Filter(rules []*types.Rule, config FilterConfig) ([]*types.Rule, error) {
	if len(rules) == 0 {
		return rules, nil
	}

	// Compile include patterns
	var includeRegexes []*regexp.Regexp
	for _, pattern := range config.Include {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
		}
		includeRegexes = append(includeRegexes, re)
	}

	// Compile exclude patterns
	var excludeRegexes []*regexp.Regexp
	for _, pattern := range config.Exclude {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
		}
		excludeRegexes = append(excludeRegexes, re)
	}

	// Apply include filter
	filtered := rules
	if len(includeRegexes) > 0 {
		filtered = applyInclude(rules, includeRegexes)
	}

	// Apply exclude filter
	if len(excludeRegexes) > 0 {
		filtered = applyExclude(filtered, excludeRegexes)
	}

	return filtered, nil
}

// =============================================================================
// HELPERS
// =============================================================================

func applyInclude(rules []*types.Rule, regexes []*regexp.Regexp) []*types.Rule {
	result := make([]*types.Rule, 0)
	for _, rule := range rules {
		if matchesAny(rule.ID, regexes) {
			result = append(result, rule)
		}
	}
	return result
}

func applyExclude(rules []*types.Rule, regexes []*regexp.Regexp) []*types.Rule {
	result := make([]*types.Rule, 0)
	for _, rule := range rules {
		if !matchesAny(rule.ID, regexes) {
			result = append(result, rule)
		}
	}
	return result
}

func matchesAny(ruleID string, regexes []*regexp.Regexp) bool {
	for _, re := range regexes {
		if re.MatchString(ruleID) {
			return true
		}
	}
	return false
}
