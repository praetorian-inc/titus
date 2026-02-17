package types

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
)

// Finding groups matches with same (rule, groups) for deduplication.
type Finding struct {
	ID      string   // SHA-1(rule_structural_id + '\0' + json(groups))
	RuleID  string
	Groups  [][]byte
	Matches []*Match // matches belonging to this finding
}

// ComputeFindingID computes content-based finding ID.
// Format: SHA-1(rule_structural_id + '\0' + json(groups))
func ComputeFindingID(ruleStructuralID string, groups [][]byte) string {
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
