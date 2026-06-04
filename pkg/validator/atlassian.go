// pkg/validator/atlassian.go
package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Pre-compiled patterns for extracting email from snippet context.
var atlassianEmailPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)email\s*=\s*['"]([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['"]`),
	regexp.MustCompile(`(?i)JIRA_USER\s*=\s*['"]([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['"]`),
	regexp.MustCompile(`(?i)user\s*=\s*['"]([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['"]`),
	regexp.MustCompile(`(?i)env\s*\(\s*['"][^'"]*['"]\s*,\s*['"]([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['"]\s*\)`),
	regexp.MustCompile(`\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b`),
}

// Pre-compiled patterns for extracting Atlassian domain from snippet context.
var atlassianDomainPatterns = []*regexp.Regexp{
	regexp.MustCompile(`https?://([a-z][a-z0-9\-]{1,24}\.atlassian\.net)`),
	regexp.MustCompile(`\b([a-z][a-z0-9\-]{1,24}\.atlassian\.net)\b`),
}

// AtlassianValidator validates Atlassian Cloud API tokens using the Jira REST API.
// Atlassian API token authentication requires email and domain from context.
// Basic Auth format: email:api_token
// The regex captures the token; the validator searches snippet context for email and domain.
type AtlassianValidator struct {
	client *http.Client
}

// NewAtlassianValidator creates a new Atlassian credential validator.
func NewAtlassianValidator() *AtlassianValidator {
	return &AtlassianValidator{client: &http.Client{Timeout: 30 * time.Second}}
}

// NewAtlassianValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewAtlassianValidatorWithClient(client *http.Client) *AtlassianValidator {
	return &AtlassianValidator{client: client}
}

// Name returns the validator name.
func (v *AtlassianValidator) Name() string {
	return "atlassian"
}

// CanValidate returns true for Atlassian-related rule IDs.
func (v *AtlassianValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.atlassian.1"
}

// Validate checks Atlassian credentials against the Jira REST API.
func (v *AtlassianValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials
	domain, email, token, err := v.extractCredentials(match)
	if err != nil {
		// Partial credentials - return undetermined
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	// Build request to Atlassian API (myself is lightweight and confirms identity)
	url := fmt.Sprintf("https://%s/rest/api/3/myself", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to create request: %v", err),
		), nil
	}

	// Set Basic Auth: email:api_token
	req.SetBasicAuth(email, token)

	// Execute request
	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("request failed: %v", err),
		), nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	// Evaluate response
	switch resp.StatusCode {
	case http.StatusOK:
		return types.NewValidationResult(
			types.StatusValid,
			1.0,
			fmt.Sprintf("valid Atlassian credentials for domain %s", domain),
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

// extractCredentials extracts Atlassian credentials from match.
// Expects token from NamedGroups, searches snippet for domain and email.
func (v *AtlassianValidator) extractCredentials(match *types.Match) (domain, email, token string, err error) {
	// Extract token from named groups
	if match.NamedGroups == nil {
		return "", "", "", fmt.Errorf("no named capture groups in match")
	}

	tokenBytes, hasToken := match.NamedGroups["token"]
	if !hasToken || len(tokenBytes) == 0 {
		return "", "", "", fmt.Errorf("token not found in named groups")
	}
	token = string(tokenBytes)

	// Search domain in snippet context
	domain = searchSnippet(match.Snippet, atlassianDomainPatterns)
	if domain == "" {
		return "", "", "", fmt.Errorf("partial credentials: found token but atlassian domain not in context")
	}

	// Search email in snippet context
	email = searchSnippet(match.Snippet, atlassianEmailPatterns)
	if email == "" {
		return "", "", "", fmt.Errorf("partial credentials: found token and domain but email not in context")
	}

	return domain, email, token, nil
}
