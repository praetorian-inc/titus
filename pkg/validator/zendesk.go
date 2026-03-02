// pkg/validator/zendesk.go
package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Pre-compiled patterns for extracting Zendesk subdomain from snippet context.
var zendeskSubdomainPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:ZENDESK_SUBDOMAIN|ZENDESK_URL|zendesk_subdomain)\s*[=:]\s*["']?(?:https?://)?([a-z0-9][a-z0-9-]+)(?:\.zendesk\.com)?["']?`),
	regexp.MustCompile(`([a-z0-9][a-z0-9-]+)\.zendesk\.com`),
}

// Pre-compiled patterns for extracting Zendesk email from snippet context.
var zendeskEmailPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:ZENDESK_EMAIL|ZENDESK_USER|zendesk_email|zendesk_user)\s*[=:]\s*["']?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']?`),
	regexp.MustCompile(`(?i)(?:email|user(?:name)?)\s*[=:]\s*["']?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']?`),
	regexp.MustCompile(`-u\s+([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/token:`),
}

// ZendeskValidator validates Zendesk API tokens using the users/me API.
// Zendesk API token authentication requires email, subdomain, and an API token.
// Basic Auth format: {email}/token:{api_token}
// The regex captures the token; the validator searches snippet context for subdomain and email.
type ZendeskValidator struct {
	client *http.Client
}

// NewZendeskValidator creates a new Zendesk credential validator.
func NewZendeskValidator() *ZendeskValidator {
	return &ZendeskValidator{client: http.DefaultClient}
}

// NewZendeskValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewZendeskValidatorWithClient(client *http.Client) *ZendeskValidator {
	return &ZendeskValidator{client: client}
}

// Name returns the validator name.
func (v *ZendeskValidator) Name() string {
	return "zendesk"
}

// CanValidate returns true for Zendesk-related rule IDs.
func (v *ZendeskValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.zendesk.1"
}

// Validate checks Zendesk credentials against the API.
func (v *ZendeskValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials
	subdomain, email, token, err := v.extractCredentials(match)
	if err != nil {
		// Partial credentials - return undetermined
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	// Build request to Zendesk API (users/me is lightweight and requires no ticket scope)
	url := fmt.Sprintf("https://%s.zendesk.com/api/v2/users/me.json", subdomain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to create request: %v", err),
		), nil
	}

	// Set Basic Auth: {email}/token:{api_token}
	req.SetBasicAuth(email+"/token", token)

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
			fmt.Sprintf("valid Zendesk credentials for subdomain %s", subdomain),
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

// extractCredentials extracts Zendesk credentials from match.
// Expects token from NamedGroups, searches snippet for subdomain and email.
func (v *ZendeskValidator) extractCredentials(match *types.Match) (subdomain, email, token string, err error) {
	// Extract token from named groups
	if match.NamedGroups == nil {
		return "", "", "", fmt.Errorf("no named capture groups in match")
	}

	tokenBytes, hasToken := match.NamedGroups["token"]
	if !hasToken || len(tokenBytes) == 0 {
		return "", "", "", fmt.Errorf("token not found in named groups")
	}
	token = string(tokenBytes)

	snippetParts := [][]byte{
		match.Snippet.Before,
		match.Snippet.Matching,
		match.Snippet.After,
	}

	// Search for subdomain in snippet context
	for _, pattern := range zendeskSubdomainPatterns {
		for _, part := range snippetParts {
			if matches := pattern.FindSubmatch(part); len(matches) >= 2 {
				subdomain = string(matches[1])
				break
			}
		}
		if subdomain != "" {
			break
		}
	}

	if subdomain == "" {
		return "", "", "", fmt.Errorf("partial credentials: found token but subdomain not in context")
	}

	// Search for email in snippet context
	for _, pattern := range zendeskEmailPatterns {
		for _, part := range snippetParts {
			if matches := pattern.FindSubmatch(part); len(matches) >= 2 {
				email = string(matches[1])
				break
			}
		}
		if email != "" {
			break
		}
	}

	if email == "" {
		return "", "", "", fmt.Errorf("partial credentials: found token and subdomain but email not in context")
	}

	return subdomain, email, token, nil
}
