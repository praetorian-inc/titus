// pkg/validator/http.go
package validator

import (
	"context"
	"fmt"
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

// Validate performs HTTP validation against the configured endpoint.
func (v *HTTPValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract secret from match
	secret, err := v.extractSecret(match)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, err.Error()), nil
	}

	// Build request
	req, err := http.NewRequestWithContext(ctx, v.def.HTTP.Method, v.def.HTTP.URL, nil)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to create request: %v", err)), nil
	}

	// Apply auth
	if err := v.applyAuth(req, secret); err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, err.Error()), nil
	}

	// Apply custom headers
	for _, h := range v.def.HTTP.Headers {
		req.Header.Set(h.Name, h.Value)
	}

	// Execute request
	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("request failed: %v", err)), nil
	}
	defer resp.Body.Close()

	// Check response code
	return v.evaluateResponse(resp.StatusCode), nil
}

func (v *HTTPValidator) extractSecret(match *types.Match) (string, error) {
	group := v.def.HTTP.Auth.SecretGroup
	if group >= len(match.Groups) {
		return "", fmt.Errorf("secret_group %d out of range (have %d groups)", group, len(match.Groups))
	}
	return string(match.Groups[group]), nil
}

func (v *HTTPValidator) applyAuth(req *http.Request, secret string) error {
	switch v.def.HTTP.Auth.Type {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+secret)
	default:
		return fmt.Errorf("unsupported auth type: %s", v.def.HTTP.Auth.Type)
	}
	return nil
}

func (v *HTTPValidator) evaluateResponse(statusCode int) *types.ValidationResult {
	// Check success codes
	for _, code := range v.def.HTTP.SuccessCodes {
		if statusCode == code {
			return types.NewValidationResult(types.StatusValid, 1.0, fmt.Sprintf("HTTP %d - credentials accepted", statusCode))
		}
	}

	// Check failure codes
	for _, code := range v.def.HTTP.FailureCodes {
		if statusCode == code {
			return types.NewValidationResult(types.StatusInvalid, 1.0, fmt.Sprintf("HTTP %d - credentials rejected", statusCode))
		}
	}

	// Unknown status code
	return types.NewValidationResult(types.StatusUndetermined, 0.5, fmt.Sprintf("HTTP %d - unexpected status code", statusCode))
}
