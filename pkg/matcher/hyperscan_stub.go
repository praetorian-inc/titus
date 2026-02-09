//go:build !wasm && (!cgo || !hyperscan)

package matcher

import (
	"fmt"

	"github.com/praetorian-inc/titus/pkg/types"
)

// NewHyperscan stub for builds without Hyperscan (non-CGO or missing hyperscan tag).
// Returns an error indicating Hyperscan requires CGO.
func NewHyperscan(rules []*types.Rule, contextLines int) (Matcher, error) {
	return nil, fmt.Errorf("Hyperscan requires CGO (build with CGO_ENABLED=1 and -tags=hyperscan)")
}
