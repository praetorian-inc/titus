package matcher

import (
	"strings"
	"unicode"

	"github.com/praetorian-inc/titus/pkg/types"
)

// defaultSpecialChars is the set of characters considered "special" when
// evaluating min_special_chars requirements.
const defaultSpecialChars = "!@#$%^&*()_+-=[]{}|;:'\",.<>?/\\`~"

// SecretCapture selects the capture that holds the secret, in order:
//  1. the rule's secret_group
//  2. a group named "token" (case-insensitive)
//  3. the only named group, when the pattern has exactly one
//  4. Groups[1], then Groups[0] (positional rules; index 0 is the first
//     capture, not the full match -- both backends strip the full match)
//
// Rules with several named groups must declare secret_group (the loader
// enforces it), so step 4 is only reached by positional rules. Exported so
// downstream post-filters (e.g. the ML denoiser) score the same bytes the
// entropy and pattern-requirement checks do.
func SecretCapture(m *types.Match, secretGroup string) []byte {
	if v, ok := m.NamedGroups[secretGroup]; ok && secretGroup != "" {
		return v
	}
	for k, v := range m.NamedGroups {
		if strings.EqualFold(k, "token") {
			return v
		}
	}
	if len(m.NamedGroups) == 1 {
		for _, v := range m.NamedGroups {
			return v
		}
	}
	if len(m.Groups) > 1 {
		return m.Groups[1]
	}
	if len(m.Groups) > 0 {
		return m.Groups[0]
	}
	return nil
}

// passesEntropyCheck returns true if minEntropy is 0 (disabled) or the
// calculated entropy of secretBytes is strictly greater than minEntropy.
// Matches with entropy <= minEntropy are rejected (Kingfisher behavior).
func passesEntropyCheck(secretBytes []byte, minEntropy float64) bool {
	if minEntropy == 0 {
		return true
	}
	return shannonEntropy(secretBytes) > minEntropy
}

// passesPatternRequirements checks character-class and content constraints.
func passesPatternRequirements(text []byte, reqs *types.PatternRequirements) bool {
	if reqs == nil {
		return true
	}

	// Check ignore_if_contains (case-insensitive substring match)
	lower := strings.ToLower(string(text))
	for _, sub := range reqs.IgnoreIfContains {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return false
		}
	}

	// Character class counts
	var digits, uppercase, lowercase, special int
	specialChars := reqs.SpecialChars
	if specialChars == "" {
		specialChars = defaultSpecialChars
	}

	for _, r := range string(text) {
		switch {
		case unicode.IsDigit(r):
			digits++
		case unicode.IsUpper(r):
			uppercase++
		case unicode.IsLower(r):
			lowercase++
		case strings.ContainsRune(specialChars, r):
			special++
		}
	}

	if digits < reqs.MinDigits {
		return false
	}
	if uppercase < reqs.MinUppercase {
		return false
	}
	if lowercase < reqs.MinLowercase {
		return false
	}
	if special < reqs.MinSpecialChars {
		return false
	}

	return true
}

// filterMatches iterates matches, looks up each rule, applies entropy and
// pattern_requirements checks, and returns only the passing matches.
func filterMatches(matches []*types.Match, rules map[string]*types.Rule) []*types.Match {
	if len(matches) == 0 {
		return matches
	}

	out := matches[:0:len(matches)]
	for _, m := range matches {
		rule, ok := rules[m.RuleID]
		if !ok {
			// Unknown rule — pass through (no filtering possible)
			out = append(out, m)
			continue
		}

		secret := SecretCapture(m, rule.SecretGroup)

		if !passesEntropyCheck(secret, rule.MinEntropy) {
			continue
		}
		if !passesPatternRequirements(secret, rule.PatternRequirements) {
			continue
		}

		out = append(out, m)
	}
	return out
}
