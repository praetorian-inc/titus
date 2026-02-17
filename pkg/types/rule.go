package types

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
)

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
}

// namedGroupRe matches named capture groups like (?P<name>...) and replaces
// them with plain unnamed groups (...) for NoseyParker-compatible hashing.
var namedGroupRe = regexp.MustCompile(`\(\?P<[^>]+>`)

// ComputeStructuralID computes SHA-1 of pattern, normalizing named capture
// groups to unnamed groups for compatibility with NoseyParker's structural IDs.
func (r *Rule) ComputeStructuralID() string {
	normalized := namedGroupRe.ReplaceAllString(r.Pattern, "(")
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
