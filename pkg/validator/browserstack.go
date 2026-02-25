// pkg/validator/browserstack.go
package validator

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Pre-compiled pattern for extracting BrowserStack username from snippet context.
var browserstackUsernamePattern = regexp.MustCompile(`(?i)(?:BROWSERSTACK_USERNAME|BROWSERSTACK_USER|browserstack[._-]?user(?:name)?)\s*[=:]\s*["']?([a-zA-Z0-9_-]+)["']?`)

// BrowserStackValidator validates BrowserStack credentials using the Automate API.
type BrowserStackValidator struct {
	client *http.Client
}

// NewBrowserStackValidator creates a new BrowserStack credential validator.
func NewBrowserStackValidator() *BrowserStackValidator {
	return &BrowserStackValidator{client: http.DefaultClient}
}

// NewBrowserStackValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewBrowserStackValidatorWithClient(client *http.Client) *BrowserStackValidator {
	return &BrowserStackValidator{client: client}
}

// Name returns the validator name.
func (v *BrowserStackValidator) Name() string {
	return "browserstack"
}

// CanValidate returns true for BrowserStack-related rule IDs.
func (v *BrowserStackValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.browserstack.1"
}

// Validate checks BrowserStack credentials against the API.
func (v *BrowserStackValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials
	username, accessKey, err := v.extractCredentials(match)
	if err != nil {
		// Partial credentials - return undetermined
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	// Build request to BrowserStack API
	// Using automate/plan.json which requires auth and is read-only
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.browserstack.com/automate/plan.json", nil)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to create request: %v", err),
		), nil
	}

	// Set Basic Auth header
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + accessKey))
	req.Header.Set("Authorization", "Basic "+auth)

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
			fmt.Sprintf("valid BrowserStack credentials for user %s", username),
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

// extractCredentials extracts BrowserStack credentials from match.
// Expects access_key from NamedGroups, searches snippet for username.
func (v *BrowserStackValidator) extractCredentials(match *types.Match) (username, accessKey string, err error) {
	// Extract access_key from named groups
	if match.NamedGroups == nil {
		return "", "", fmt.Errorf("no named capture groups in match")
	}

	accessKeyBytes, hasAccessKey := match.NamedGroups["access_key"]
	if !hasAccessKey || len(accessKeyBytes) == 0 {
		return "", "", fmt.Errorf("access_key not found in named groups")
	}
	accessKey = string(accessKeyBytes)

	// Search for BROWSERSTACK_USERNAME in snippet context
	usernamePattern := browserstackUsernamePattern

	// Check snippet.Before
	if matches := usernamePattern.FindSubmatch(match.Snippet.Before); len(matches) >= 2 {
		return string(matches[1]), accessKey, nil
	}

	// Check snippet.After
	if matches := usernamePattern.FindSubmatch(match.Snippet.After); len(matches) >= 2 {
		return string(matches[1]), accessKey, nil
	}

	// Check snippet.Matching (in case both are on same line)
	if matches := usernamePattern.FindSubmatch(match.Snippet.Matching); len(matches) >= 2 {
		return string(matches[1]), accessKey, nil
	}

	return "", "", fmt.Errorf("partial credentials: found access_key but BROWSERSTACK_USERNAME not in context")
}
