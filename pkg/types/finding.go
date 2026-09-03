package types

import (
	"crypto/sha1" // #nosec G505 -- SHA1 is required for compatibility with NoseyParker finding IDs; not used as a cryptographic primitive.
	"encoding/hex"
	"encoding/json"
)

// Finding groups matches with same (rule, groups) for deduplication.
type Finding struct {
	ID      string   // SHA-1(rule_structural_id + '\0' + json(groups))
	RuleID  string
	Groups  [][]byte
	Matches []*Match // matches belonging to this finding
	// Score is the computed severity score for this finding. Nil indicates
	// the finding predates scoring (legacy datastores) or scoring was skipped.
	Score *Score
	// Owner identifies who owns or created the credential. Nil when
	// owner resolution was not performed or the API did not return identity data.
	Owner *OwnerInfo `json:"owner,omitempty"`
}

// ComputeFindingID computes content-based finding ID.
// Format: SHA-1(rule_structural_id + '\0' + json(groups))
func ComputeFindingID(ruleStructuralID string, groups [][]byte) string {
	// #nosec G401 -- SHA1 is used for content-addressing, not cryptographic integrity. Required for NoseyParker datastore compatibility.
	h := sha1.New()

	// rule_structural_id
	h.Write([]byte(ruleStructuralID))
	h.Write([]byte{0}) // null byte separator

	// JSON-encode groups for consistent representation
	// Note: json.Marshal sorts object keys, making this deterministic
	groupsJSON, _ := json.Marshal(groups)
	h.Write(groupsJSON)

	return hex.EncodeToString(h.Sum(nil))
}
