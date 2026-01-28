package types

import (
	"crypto/sha1"
	"encoding/hex"
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
}

// ComputeStructuralID computes SHA-1 of pattern.
func (r *Rule) ComputeStructuralID() string {
	h := sha1.New()
	h.Write([]byte(r.Pattern))
	return hex.EncodeToString(h.Sum(nil))
}

// Ruleset groups rules together.
type Ruleset struct {
	ID          string
	Name        string
	Description string
	RuleIDs     []string
}
