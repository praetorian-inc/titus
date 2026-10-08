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
//  2. Highest-entropy named capture in NamedGroups
//  3. Groups[1] (second positional capture — index 0 is the first capture,
//     NOT the full match; both backends strip the full match at index 0)
//  4. Groups[0] (first positional capture)
//
// For rules with 3+ captures that lack named groups, step 3 picks the SECOND
// capture, which is often a username or context field rather than the secret.
// Fix: name the secret capture "token" so step 1 selects it. See LAB-6101.
func findSecretCapture(m *types.Match) []byte {
	// 1. Named capture called "TOKEN" (case-insensitive)
	for k, v := range m.NamedGroups {
		if strings.EqualFold(k, "token") {
			return v
		}
	}

	// 2. Select the named group with the highest Shannon entropy — deterministic
	//    (max entropy + alphabetical tiebreaker on equal entropy) and semantically
	//    correct: we want the most-secret-like value for the entropy threshold check.
	if len(m.NamedGroups) > 0 {
		var bestKey string
		bestEntropy := -1.0
		for k, v := range m.NamedGroups {
			e := shannonEntropy(v)
			if e > bestEntropy || (e == bestEntropy && (bestKey == "" || k < bestKey)) {
				bestEntropy = e
				bestKey = k
			}
		}
		if bestKey != "" {
			return m.NamedGroups[bestKey]
		}
	}

	// 3. Groups[1] (second positional capture)
	if len(m.Groups) > 1 {
		return m.Groups[1]
	}

	// 4. Groups[0] (first positional capture)
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

	if reqs.Luhn && !luhnValid(text) {
		return false
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

func luhnValid(text []byte) bool {
	var digits [19]byte
	n := 0
	for _, b := range text {
		switch {
		case b == ' ' || b == '-':
			continue
		case b < '0' || b > '9' || n == len(digits):
			return false
		}
		digits[n] = b - '0'
		n++
	}
	return n >= 13 && luhnSum(digits[:n])%10 == 0
}

// luhnSum adds the digits right to left, doubling every second one. doubled
// holds the digit sums of 0*2 .. 9*2 (e.g. 7*2 = 14 -> 1+4 = 5).
func luhnSum(digits []byte) int {
	doubled := [10]int{0, 2, 4, 6, 8, 1, 3, 5, 7, 9}
	sum := 0
	for i := range digits {
		d := digits[len(digits)-1-i]
		if i%2 == 1 {
			sum += doubled[d]
		} else {
			sum += int(d)
		}
	}
	return sum
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
