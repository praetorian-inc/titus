package matcher

import (
	"strings"
	"unicode"

	"github.com/praetorian-inc/titus/pkg/types"
)

// defaultSpecialChars is the set of characters considered "special" when
// evaluating min_special_chars requirements.
const defaultSpecialChars = "!@#$%^&*()_+-=[]{}|;:'\",.<>?/\\`~"

// findSecretCapture selects which capture group represents the secret value.
// Priority (matching Kingfisher):
//  1. Named capture called "TOKEN" (case-insensitive)
//  2. First named capture in NamedGroups
//  3. Groups[1] (first positional capture)
//  4. Groups[0] (full match)
func findSecretCapture(m *types.Match) []byte {
	// 1. Named capture called "TOKEN" (case-insensitive)
	for k, v := range m.NamedGroups {
		if strings.EqualFold(k, "token") {
			return v
		}
	}

	// 2. First named capture in NamedGroups (map iteration order is random,
	//    but we just need any named group when TOKEN isn't present)
	for _, v := range m.NamedGroups {
		return v
	}

	// 3. Groups[1] (first positional capture)
	if len(m.Groups) > 1 {
		return m.Groups[1]
	}

	// 4. Groups[0] (full match)
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

		secret := findSecretCapture(m)

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
