package scoring

import (
	"github.com/praetorian-inc/titus/pkg/types"
)

// extractAWSCredentials extracts the key ID and secret access key from a
// match's NamedGroups. Returns (keyID, secretKey, true) on success.
// Both named groups must be non-empty.
func extractAWSCredentials(m *types.Match) (keyID, secretKey string, ok bool) {
	if m == nil {
		return "", "", false
	}
	kid, hasKey := m.NamedGroups["key_id"]
	sec, hasSecret := m.NamedGroups["secret_key"]
	if !hasKey || !hasSecret || len(kid) == 0 || len(sec) == 0 {
		return "", "", false
	}
	return string(kid), string(sec), true
}
