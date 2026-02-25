// pkg/validator/branchio.go
package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Pre-compiled patterns for extracting Branch.io secret from snippet context.
// Branch secrets are 40-64 character alphanumeric strings.
var branchSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)BRANCH_SECRET\s*[=:]\s*["']?([A-Za-z0-9]{40,64})["']?`),
	regexp.MustCompile(`(?i)branch_secret\s*[=:]\s*["']?([A-Za-z0-9]{40,64})["']?`),
	regexp.MustCompile(`(?i)BRANCH_KEY_SECRET\s*[=:]\s*["']?([A-Za-z0-9]{40,64})["']?`),
}

// BranchIOValidator validates Branch.io credentials using the app API.
type BranchIOValidator struct {
	client *http.Client
}

// NewBranchIOValidator creates a new Branch.io credential validator.
func NewBranchIOValidator() *BranchIOValidator {
	return &BranchIOValidator{client: http.DefaultClient}
}

// NewBranchIOValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewBranchIOValidatorWithClient(client *http.Client) *BranchIOValidator {
	return &BranchIOValidator{client: client}
}

// Name returns the validator name.
func (v *BranchIOValidator) Name() string {
	return "branchio"
}

// CanValidate returns true for Branch.io live key rule IDs.
func (v *BranchIOValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.branchio.1"
}

// Validate checks Branch.io credentials against the API.
func (v *BranchIOValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials
	key, secret, err := v.extractCredentials(match)
	if err != nil {
		// Partial credentials - return undetermined
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	// Build request to Branch.io API
	url := fmt.Sprintf("https://api2.branch.io/v1/app/%s?branch_secret=%s", key, secret)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to create request: %v", err),
		), nil
	}

	// Execute request
	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("request failed: %v", err),
		), nil
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	// Evaluate response
	switch resp.StatusCode {
	case http.StatusOK:
		return types.NewValidationResult(
			types.StatusValid,
			1.0,
			fmt.Sprintf("valid Branch.io credentials for key %s", key),
		), nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest:
		return types.NewValidationResult(
			types.StatusInvalid,
			1.0,
			fmt.Sprintf("credentials rejected: HTTP %d", resp.StatusCode),
		), nil
	default:
		return types.NewValidationResult(
			types.StatusUndetermined,
			0.5,
			fmt.Sprintf("unexpected status code: HTTP %d", resp.StatusCode),
		), nil
	}
}

// extractCredentials extracts Branch.io credentials from match.
// Expects key from NamedGroups (key_live_xxx token), searches snippet for branch secret.
func (v *BranchIOValidator) extractCredentials(match *types.Match) (key, secret string, err error) {
	// Extract key from named groups
	if match.NamedGroups == nil {
		return "", "", fmt.Errorf("no named capture groups in match")
	}

	keyBytes, hasKey := match.NamedGroups["key"]
	if !hasKey || len(keyBytes) == 0 {
		return "", "", fmt.Errorf("key not found in named groups")
	}
	key = string(keyBytes)

	// Search for branch secret in snippet context
	snippetParts := [][]byte{
		match.Snippet.Before,
		match.Snippet.Matching,
		match.Snippet.After,
	}

	for _, pattern := range branchSecretPatterns {
		for _, part := range snippetParts {
			if matches := pattern.FindSubmatch(part); len(matches) >= 2 {
				return key, string(matches[1]), nil
			}
		}
	}

	return "", "", fmt.Errorf("partial credentials: found key but branch secret not in context")
}
