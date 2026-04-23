package types

import (
	"crypto/sha1" // #nosec G505 -- SHA1 is required for compatibility with NoseyParker rule structural IDs; not used as a cryptographic primitive.
	"encoding/hex"
	"regexp"
)

// PatternRequirements specifies minimum character-class counts that a captured
// value must satisfy. Reduces false positives for patterns matching generic strings.
type PatternRequirements struct {
	MinDigits        int      `json:"min_digits,omitempty"`
	MinUppercase     int      `json:"min_uppercase,omitempty"`
	MinLowercase     int      `json:"min_lowercase,omitempty"`
	MinSpecialChars  int      `json:"min_special_chars,omitempty"`
	SpecialChars     string   `json:"special_chars,omitempty"`
	IgnoreIfContains []string `json:"ignore_if_contains,omitempty"`
}

// Rule is a detection rule with pattern and metadata.
type Rule struct {
	ID               string   // e.g., "np.aws.1"
	Name             string   // human-readable name
	Pattern          string   // regex pattern
	StructuralID     string   // SHA-1 of pattern (computed)
	Description      string   // optional
	Examples         []string // positive test cases
	NegativeExamples []string // negative test cases
	References       []string // documentation URLs
	Categories       []string // classification tags
	Keywords         []string // keywords for Aho-Corasick prefiltering

	// MinEntropy is the minimum Shannon entropy (bits/char) the secret capture
	// group must have. Matches with entropy <= MinEntropy are rejected.
	// A value of 0 disables the entropy check.
	MinEntropy float64

	// PatternRequirements specifies character-class and content constraints
	// for the captured value. nil means no requirements.
	PatternRequirements *PatternRequirements

	// BaseScore is the inherent severity of this rule's secret class,
	// ranging 0-100. Assigned via research per rule. Required.
	BaseScore int
}

// namedGroupRe matches named capture groups like (?P<name>...) and replaces
// them with plain unnamed groups (...) for NoseyParker-compatible hashing.
var namedGroupRe = regexp.MustCompile(`\(\?P<[^>]+>`)

// ComputeStructuralID computes SHA-1 of pattern, normalizing named capture
// groups to unnamed groups for compatibility with NoseyParker's structural IDs.
func (r *Rule) ComputeStructuralID() string {
	normalized := namedGroupRe.ReplaceAllString(r.Pattern, "(")
	// #nosec G401 -- SHA1 is used for content-addressing, not cryptographic integrity. Required for NoseyParker datastore compatibility.
	h := sha1.New()
	h.Write([]byte(normalized))
	return hex.EncodeToString(h.Sum(nil))
}

// Ruleset groups rules together.
type Ruleset struct {
	ID          string
	Name        string
	Description string
	RuleIDs     []string
}
