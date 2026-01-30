// pkg/validator/http.go
package validator

import (
	"context"
	"net/http"

	"github.com/praetorian-inc/titus/pkg/types"
)

// HTTPValidator validates secrets via HTTP requests defined in YAML.
type HTTPValidator struct {
	def    ValidatorDef
	client *http.Client
}

// NewHTTPValidator creates a validator from a YAML definition.
func NewHTTPValidator(def ValidatorDef, client *http.Client) *HTTPValidator {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPValidator{
		def:    def,
		client: client,
	}
}

// Name returns the validator name.
func (v *HTTPValidator) Name() string {
	return v.def.Name
}

// CanValidate returns true if this validator handles the given rule ID.
func (v *HTTPValidator) CanValidate(ruleID string) bool {
	for _, rid := range v.def.RuleIDs {
		if rid == ruleID {
			return true
		}
	}
	return false
}

// Validate performs HTTP validation (implemented in next task).
func (v *HTTPValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	return types.NewValidationResult(types.StatusUndetermined, 0, "not implemented"), nil
}
