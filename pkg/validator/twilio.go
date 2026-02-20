// pkg/validator/twilio.go
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

// Pre-compiled patterns for extracting Twilio secrets from snippet context.
var (
	twilioSecretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)TWILIO_API_SECRET\s*[=:]\s*["']?([a-zA-Z0-9]{32})["']?`),
		regexp.MustCompile(`(?i)TWILIO_AUTH_TOKEN\s*[=:]\s*["']?([a-zA-Z0-9]{32})["']?`),
		regexp.MustCompile(`(?i)API_KEY_SECRET\s*[=:]\s*["']?([a-zA-Z0-9]{32})["']?`),
		regexp.MustCompile(`(?i)twilio.?Api.?Key.?Secret\s*[=:]\s*["']?([a-zA-Z0-9]{32})["']?`),
		regexp.MustCompile(`(?i)secret\s*[=:]\s*["']?([a-zA-Z0-9]{32})["']?`),
		regexp.MustCompile(`(?i)auth.?token\s*[=:]\s*["']?([a-zA-Z0-9]{32})["']?`),
	}
)

// TwilioValidator validates Twilio API Key credentials using the Accounts API.
// Twilio authentication requires both API Key SID (SK...) and API Key Secret.
// The regex captures the SID; the validator searches snippet context for the secret.
type TwilioValidator struct {
	client *http.Client
}

// NewTwilioValidator creates a new Twilio credential validator.
func NewTwilioValidator() *TwilioValidator {
	return &TwilioValidator{client: http.DefaultClient}
}

// NewTwilioValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewTwilioValidatorWithClient(client *http.Client) *TwilioValidator {
	return &TwilioValidator{client: client}
}

// Name returns the validator name.
func (v *TwilioValidator) Name() string {
	return "twilio"
}

// CanValidate returns true for Twilio-related rule IDs.
func (v *TwilioValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.twilio.1"
}

// Validate checks Twilio credentials against the API.
func (v *TwilioValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials
	keySID, keySecret, err := v.extractCredentials(match)
	if err != nil {
		// Partial credentials - return undetermined
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	// Build request to Twilio API
	// Using Accounts.json which requires auth and is read-only
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.twilio.com/2010-04-01/Accounts.json", nil)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to create request: %v", err),
		), nil
	}

	// Set Basic Auth header (API Key SID : API Key Secret)
	auth := base64.StdEncoding.EncodeToString([]byte(keySID + ":" + keySecret))
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
			fmt.Sprintf("valid Twilio credentials for API Key %s", keySID),
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

// extractCredentials extracts Twilio credentials from match.
// Expects key_sid from NamedGroups, searches snippet for key secret.
func (v *TwilioValidator) extractCredentials(match *types.Match) (keySID, keySecret string, err error) {
	// Extract key_sid from named groups
	if match.NamedGroups == nil {
		return "", "", fmt.Errorf("no named capture groups in match")
	}

	keySIDBytes, hasKeySID := match.NamedGroups["key_sid"]
	if !hasKeySID || len(keySIDBytes) == 0 {
		return "", "", fmt.Errorf("key_sid not found in named groups")
	}
	keySID = string(keySIDBytes)

	// Search for API Key Secret in snippet context
	// Twilio API Key Secrets are 32 alphanumeric characters
	// Common patterns: TWILIO_API_SECRET, API_SECRET, auth_token, etc.
	secretPatterns := twilioSecretPatterns

	// Check all snippet locations (Snippet is a value type, not a pointer)
	snippetParts := [][]byte{
		match.Snippet.Before,
		match.Snippet.Matching,
		match.Snippet.After,
	}

	for _, pattern := range secretPatterns {
		for _, part := range snippetParts {
			if matches := pattern.FindSubmatch(part); len(matches) >= 2 {
				return keySID, string(matches[1]), nil
			}
		}
	}

	return "", "", fmt.Errorf("partial credentials: found API Key SID but secret not in context")
}
