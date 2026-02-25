// pkg/validator/amplitude.go
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

// Pre-compiled patterns for extracting Amplitude secret key from snippet context.
var amplitudeSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)AMPLITUDE_SECRET_KEY\s*[=:]\s*["']?([a-f0-9]{32})["']?`),
	regexp.MustCompile(`(?i)AMPLITUDE_SECRET\s*[=:]\s*["']?([a-f0-9]{32})["']?`),
	regexp.MustCompile(`(?i)amplitude[._-]?secret\s*[=:]\s*["']?([a-f0-9]{32})["']?`),
	regexp.MustCompile(`(?i)secret[_-]?key\s*[=:]\s*["']?([a-f0-9]{32})["']?`),
}

// AmplitudeValidator validates Amplitude credentials using the Export API.
type AmplitudeValidator struct {
	client *http.Client
}

// NewAmplitudeValidator creates a new Amplitude credential validator.
func NewAmplitudeValidator() *AmplitudeValidator {
	return &AmplitudeValidator{client: http.DefaultClient}
}

// NewAmplitudeValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewAmplitudeValidatorWithClient(client *http.Client) *AmplitudeValidator {
	return &AmplitudeValidator{client: client}
}

// Name returns the validator name.
func (v *AmplitudeValidator) Name() string {
	return "amplitude"
}

// CanValidate returns true for Amplitude-related rule IDs.
func (v *AmplitudeValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.amplitude.1"
}

// Validate checks Amplitude credentials against the API.
func (v *AmplitudeValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials
	apiKey, secretKey, err := v.extractCredentials(match)
	if err != nil {
		// Partial credentials - return undetermined
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	// Build request to Amplitude Export API
	// Using export endpoint which requires auth and is read-only
	req, err := http.NewRequestWithContext(ctx, "GET", "https://amplitude.com/api/2/export?start=20200201T5&end=20210203T20", nil)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to create request: %v", err),
		), nil
	}

	// Set Basic Auth header (api_key:secret_key)
	auth := base64.StdEncoding.EncodeToString([]byte(apiKey + ":" + secretKey))
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
			fmt.Sprintf("valid Amplitude credentials for API key %s", apiKey),
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

// extractCredentials extracts Amplitude credentials from match.
// Expects api_key from NamedGroups, searches snippet for secret key.
func (v *AmplitudeValidator) extractCredentials(match *types.Match) (apiKey, secretKey string, err error) {
	// Extract api_key from named groups
	if match.NamedGroups == nil {
		return "", "", fmt.Errorf("no named capture groups in match")
	}

	apiKeyBytes, hasAPIKey := match.NamedGroups["api_key"]
	if !hasAPIKey || len(apiKeyBytes) == 0 {
		return "", "", fmt.Errorf("api_key not found in named groups")
	}
	apiKey = string(apiKeyBytes)

	// Search for secret key in snippet context
	// Amplitude secret keys are 32 hex characters
	snippetParts := [][]byte{
		match.Snippet.Before,
		match.Snippet.Matching,
		match.Snippet.After,
	}

	for _, pattern := range amplitudeSecretPatterns {
		for _, part := range snippetParts {
			if matches := pattern.FindSubmatch(part); len(matches) >= 2 {
				return apiKey, string(matches[1]), nil
			}
		}
	}

	return "", "", fmt.Errorf("partial credentials: found API key but secret key not in context")
}
