// pkg/validator/helpscout.go
package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Pre-compiled patterns for extracting Help Scout client ID from snippet context.
var helpScoutClientIDPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)HELPSCOUT_CLIENT_ID\s*[=:]\s*["']?([A-Za-z0-9]{10,40})["']?`),
	regexp.MustCompile(`(?i)HELPSCOUT_APP_ID\s*[=:]\s*["']?([A-Za-z0-9]{10,40})["']?`),
	regexp.MustCompile(`(?i)HELP_SCOUT_CLIENT_ID\s*[=:]\s*["']?([A-Za-z0-9]{10,40})["']?`),
	regexp.MustCompile(`(?i)application_id\s*[=:]\s*["']?([A-Za-z0-9]{10,40})["']?`),
	regexp.MustCompile(`(?i)client_id\s*[=:]\s*["']?([A-Za-z0-9]{10,40})["']?`),
}

// HelpScoutValidator validates Help Scout OAuth client credentials using the token endpoint.
type HelpScoutValidator struct {
	client *http.Client
}

// NewHelpScoutValidator creates a new Help Scout credential validator.
func NewHelpScoutValidator() *HelpScoutValidator {
	return &HelpScoutValidator{client: http.DefaultClient}
}

// NewHelpScoutValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewHelpScoutValidatorWithClient(client *http.Client) *HelpScoutValidator {
	return &HelpScoutValidator{client: client}
}

// Name returns the validator name.
func (v *HelpScoutValidator) Name() string {
	return "helpscout"
}

// CanValidate returns true for Help Scout-related rule IDs.
func (v *HelpScoutValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.helpscout.1"
}

// Validate checks Help Scout credentials against the OAuth2 token endpoint.
func (v *HelpScoutValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials
	clientID, clientSecret, err := v.extractCredentials(match)
	if err != nil {
		// Partial credentials - return undetermined
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	// Build request to Help Scout OAuth2 token endpoint
	body := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s", clientID, clientSecret)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.helpscout.net/v2/oauth2/token", strings.NewReader(body))
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to create request: %v", err),
		), nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
			fmt.Sprintf("valid Help Scout credentials for client %s", clientID),
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

// extractCredentials extracts Help Scout credentials from match.
// Expects secret from NamedGroups, searches snippet for client ID.
func (v *HelpScoutValidator) extractCredentials(match *types.Match) (clientID, clientSecret string, err error) {
	// Extract secret from named groups
	if match.NamedGroups == nil {
		return "", "", fmt.Errorf("no named capture groups in match")
	}

	secretBytes, hasSecret := match.NamedGroups["secret"]
	if !hasSecret || len(secretBytes) == 0 {
		return "", "", fmt.Errorf("secret not found in named groups")
	}
	clientSecret = string(secretBytes)

	// Search for client ID in snippet context
	snippetParts := [][]byte{
		match.Snippet.Before,
		match.Snippet.Matching,
		match.Snippet.After,
	}

	for _, pattern := range helpScoutClientIDPatterns {
		for _, part := range snippetParts {
			if matches := pattern.FindSubmatch(part); len(matches) >= 2 {
				return string(matches[1]), clientSecret, nil
			}
		}
	}

	return "", "", fmt.Errorf("partial credentials: found client secret but client_id not in context")
}
