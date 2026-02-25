// pkg/validator/wpengine.go
package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Pre-compiled patterns for extracting WPEngine account name from snippet context.
var wpengineAccountPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:WPE_ACCOUNT_NAME|WPENGINE_ACCOUNT|wpengine_account_name|wpengine_account)\s*[=:]\s*["']?([a-z0-9][a-z0-9-]+)["']?`),
	regexp.MustCompile(`(?i)account_name\s*[=:]\s*["']?([a-z0-9][a-z0-9-]+)["']?`),
}

// WPEngineValidator validates WPEngine API keys using the site API.
// WPEngine authentication requires both an account name and an API key.
// The regex captures the key; the validator searches snippet context for the account name.
type WPEngineValidator struct {
	client *http.Client
}

// NewWPEngineValidator creates a new WPEngine credential validator.
func NewWPEngineValidator() *WPEngineValidator {
	return &WPEngineValidator{client: http.DefaultClient}
}

// NewWPEngineValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewWPEngineValidatorWithClient(client *http.Client) *WPEngineValidator {
	return &WPEngineValidator{client: client}
}

// Name returns the validator name.
func (v *WPEngineValidator) Name() string {
	return "wpengine"
}

// CanValidate returns true for WPEngine-related rule IDs.
func (v *WPEngineValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.wpengine.1"
}

// Validate checks WPEngine credentials against the API.
func (v *WPEngineValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials
	accountName, apiKey, err := v.extractCredentials(match)
	if err != nil {
		// Partial credentials - return undetermined
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	// Build request to WPEngine API
	url := fmt.Sprintf("https://api.wpengine.com/1.2/?method=site&account_name=%s&wpe_apikey=%s", accountName, apiKey)
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
			fmt.Sprintf("valid WPEngine credentials for account %s", accountName),
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

// extractCredentials extracts WPEngine credentials from match.
// Expects key from NamedGroups, searches snippet for account name.
func (v *WPEngineValidator) extractCredentials(match *types.Match) (accountName, apiKey string, err error) {
	// Extract key from named groups
	if match.NamedGroups == nil {
		return "", "", fmt.Errorf("no named capture groups in match")
	}

	keyBytes, hasKey := match.NamedGroups["key"]
	if !hasKey || len(keyBytes) == 0 {
		return "", "", fmt.Errorf("key not found in named groups")
	}
	apiKey = string(keyBytes)

	// Search for account name in snippet context
	snippetParts := [][]byte{
		match.Snippet.Before,
		match.Snippet.Matching,
		match.Snippet.After,
	}

	for _, pattern := range wpengineAccountPatterns {
		for _, part := range snippetParts {
			if matches := pattern.FindSubmatch(part); len(matches) >= 2 {
				return string(matches[1]), apiKey, nil
			}
		}
	}

	return "", "", fmt.Errorf("partial credentials: found API key but account name not in context")
}
