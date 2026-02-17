package types

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

// Match is a single detection result.
type Match struct {
	BlobID           BlobID
	StructuralID     string // SHA-1(rule_structural_id + '\0' + blob_id + '\0' + start + '\0' + end)
	FindingID        string // SHA-1(rule_structural_id + '\0' + json(groups)) — content-based dedup ID
	RuleID           string // e.g., "np.aws.1"
	RuleName         string // e.g., "AWS API Key"
	Location         Location
	Groups           [][]byte          // regex capture groups (positional, deprecated - use NamedGroups)
	NamedGroups      map[string][]byte // named capture groups from regex (?P<name>...)
	Snippet          Snippet
	ValidationResult *ValidationResult `json:"validation_result,omitempty"`
}

// ComputeStructuralID computes content-based unique ID.
// Format: SHA-1(rule_structural_id + '\0' + blob_id + '\0' + start + '\0' + end)
func (m *Match) ComputeStructuralID(ruleStructuralID string) string {
	h := sha1.New()

	// rule_structural_id
	h.Write([]byte(ruleStructuralID))
	h.Write([]byte{0}) // null byte separator

	// blob_id
	h.Write(m.BlobID[:])
	h.Write([]byte{0})

	// start offset
	startStr := fmt.Sprintf("%d", m.Location.Offset.Start)
	h.Write([]byte(startStr))
	h.Write([]byte{0})

	// end offset
	endStr := fmt.Sprintf("%d", m.Location.Offset.End)
	h.Write([]byte(endStr))

	return hex.EncodeToString(h.Sum(nil))
}
