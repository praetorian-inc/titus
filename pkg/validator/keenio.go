// pkg/validator/keenio.go
package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Pre-compiled patterns for extracting Keen.io project ID from snippet context.
// Keen.io project IDs are 24-character hex strings.
var keenProjectIDPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)KEEN_PROJECT_ID\s*[=:]\s*["']?([a-f0-9]{24})["']?`),
	regexp.MustCompile(`(?i)keen_project_id\s*[=:]\s*["']?([a-f0-9]{24})["']?`),
	regexp.MustCompile(`(?i)PROJECT_ID\s*[=:]\s*["']?([a-f0-9]{24})["']?`),
	regexp.MustCompile(`(?i)project_id\s*[=:]\s*["']?([a-f0-9]{24})["']?`),
}

// KeenIOValidator validates Keen.io API Key credentials using the events API.
type KeenIOValidator struct {
	client *http.Client
}

// NewKeenIOValidator creates a new Keen.io credential validator.
func NewKeenIOValidator() *KeenIOValidator {
	return &KeenIOValidator{client: http.DefaultClient}
}

// NewKeenIOValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewKeenIOValidatorWithClient(client *http.Client) *KeenIOValidator {
	return &KeenIOValidator{client: client}
}

// Name returns the validator name.
func (v *KeenIOValidator) Name() string {
	return "keenio"
}

// CanValidate returns true for Keen.io-related rule IDs.
func (v *KeenIOValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.keenio.1"
}

// Validate checks Keen.io credentials against the API.
func (v *KeenIOValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials
	apiKey, projectID, err := v.extractCredentials(match)
	if err != nil {
		// Partial credentials - return undetermined
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	// Build request to Keen.io API
	url := fmt.Sprintf("https://api.keen.io/3.0/projects/%s/events?api_key=%s", projectID, apiKey)
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
			fmt.Sprintf("valid Keen.io credentials for project %s", projectID),
		), nil
	case http.StatusUnauthorized, http.StatusForbidden:
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

// extractCredentials extracts Keen.io credentials from match.
// Expects key from NamedGroups, searches snippet for project ID.
func (v *KeenIOValidator) extractCredentials(match *types.Match) (apiKey, projectID string, err error) {
	// Extract API key from named groups
	if match.NamedGroups == nil {
		return "", "", fmt.Errorf("no named capture groups in match")
	}

	apiKeyBytes, hasKey := match.NamedGroups["key"]
	if !hasKey || len(apiKeyBytes) == 0 {
		return "", "", fmt.Errorf("key not found in named groups")
	}
	apiKey = string(apiKeyBytes)

	// Search for project ID in snippet context
	snippetParts := [][]byte{
		match.Snippet.Before,
		match.Snippet.Matching,
		match.Snippet.After,
	}

	for _, pattern := range keenProjectIDPatterns {
		for _, part := range snippetParts {
			if matches := pattern.FindSubmatch(part); len(matches) >= 2 {
				return apiKey, string(matches[1]), nil
			}
		}
	}

	return "", "", fmt.Errorf("partial credentials: found API key but project ID not in context")
}
