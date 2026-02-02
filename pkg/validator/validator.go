// pkg/validator/validator.go
package validator

import (
	"context"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Validator validates detected secrets against their source APIs.
type Validator interface {
	// Name returns a human-readable name for this validator.
	Name() string

	// CanValidate returns true if this validator handles the given rule ID.
	CanValidate(ruleID string) bool

	// Validate checks if the detected secret is valid/active.
	Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error)
}
