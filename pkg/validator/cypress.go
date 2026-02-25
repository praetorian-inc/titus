// pkg/validator/cypress.go
package validator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Pre-compiled patterns for extracting Cypress project ID from snippet context.
var cypressProjectIDPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)CYPRESS_PROJECT_ID\s*[=:]\s*["']?([a-z0-9]{6,8})["']?`),
	regexp.MustCompile(`(?i)projectId\s*[=:]\s*["']?([a-z0-9]{6,8})["']?`),
	regexp.MustCompile(`(?i)project_id\s*[=:]\s*["']?([a-z0-9]{6,8})["']?`),
}

// CypressValidator validates Cypress record keys using the runs API.
type CypressValidator struct {
	client *http.Client
}

// NewCypressValidator creates a new Cypress credential validator.
func NewCypressValidator() *CypressValidator {
	return &CypressValidator{client: http.DefaultClient}
}

// NewCypressValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewCypressValidatorWithClient(client *http.Client) *CypressValidator {
	return &CypressValidator{client: client}
}

// Name returns the validator name.
func (v *CypressValidator) Name() string {
	return "cypress"
}

// CanValidate returns true for Cypress-related rule IDs.
func (v *CypressValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.cypress.1"
}

// Validate checks Cypress credentials against the runs API.
func (v *CypressValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials
	projectID, recordKey, err := v.extractCredentials(match)
	if err != nil {
		// Partial credentials - return undetermined
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	// Build JSON request body
	requestBody := map[string]interface{}{
		"projectId": projectID,
		"recordKey": recordKey,
		"specs":     []string{"test.js"},
		"platform":  map[string]string{"osName": "linux"},
		"ci":        map[string]string{"buildNumber": "1"},
	}
	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to marshal request body: %v", err),
		), nil
	}

	// Build request to Cypress runs API
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.cypress.io/runs", bytes.NewReader(bodyBytes))
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to create request: %v", err),
		), nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-route-version", "4")
	req.Header.Set("x-os-name", "darwin")
	req.Header.Set("x-cypress-version", "5.5.0")

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
			fmt.Sprintf("valid Cypress credentials for project %s", projectID),
		), nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return types.NewValidationResult(
			types.StatusInvalid,
			1.0,
			fmt.Sprintf("credentials rejected: HTTP %d", resp.StatusCode),
		), nil
	case http.StatusNotFound:
		return types.NewValidationResult(
			types.StatusInvalid,
			1.0,
			fmt.Sprintf("invalid project ID: HTTP %d", resp.StatusCode),
		), nil
	default:
		return types.NewValidationResult(
			types.StatusUndetermined,
			0.5,
			fmt.Sprintf("unexpected status code: HTTP %d", resp.StatusCode),
		), nil
	}
}

// extractCredentials extracts Cypress credentials from match.
// Expects key from NamedGroups, searches snippet for project ID.
func (v *CypressValidator) extractCredentials(match *types.Match) (projectID, recordKey string, err error) {
	// Extract record key from named groups
	if match.NamedGroups == nil {
		return "", "", fmt.Errorf("no named capture groups in match")
	}

	keyBytes, hasKey := match.NamedGroups["key"]
	if !hasKey || len(keyBytes) == 0 {
		return "", "", fmt.Errorf("key not found in named groups")
	}
	recordKey = string(keyBytes)

	// Search for project ID in snippet context
	snippetParts := [][]byte{
		match.Snippet.Before,
		match.Snippet.Matching,
		match.Snippet.After,
	}

	for _, pattern := range cypressProjectIDPatterns {
		for _, part := range snippetParts {
			if matches := pattern.FindSubmatch(part); len(matches) >= 2 {
				return string(matches[1]), recordKey, nil
			}
		}
	}

	return "", "", fmt.Errorf("partial credentials: found record key but projectId not in context")
}
