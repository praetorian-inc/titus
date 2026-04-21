// pkg/validator/keenio.go
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

// Pre-compiled patterns for extracting Keen.io project ID from snippet context.
// Keen.io project IDs are 24-character lowercase alphanumeric strings (MongoDB ObjectID style).
var keenProjectIDPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)KEEN_PROJECT_ID\s*[=:]\s*["']?([a-z0-9]{24})["']?`),
	regexp.MustCompile(`(?i)keen_project_id\s*[=:]\s*["']?([a-z0-9]{24})["']?`),
	regexp.MustCompile(`(?i)PROJECT_ID\s*[=:]\s*["']?([a-z0-9]{24})["']?`),
	regexp.MustCompile(`(?i)project_id\s*[=:]\s*["']?([a-z0-9]{24})["']?`),
}

// keenEndpoint defines an API endpoint to try for validation along with the key type it validates.
type keenEndpoint struct {
	method  string
	path    string // format string with %s for projectID
	keyType string
	body    string // request body (empty for GET)
}

// keenValidationEndpoints lists the API endpoints to try in order.
// Read key → GET /events; Write key → POST /events/validation_test; Master key → GET project root.
var keenValidationEndpoints = []keenEndpoint{
	{"GET", "https://api.keen.io/3.0/projects/%s/events", "read", ""},
	{"POST", "https://api.keen.io/3.0/projects/%s/events/validation_test", "write", `{"validation":"true"}`},
	{"GET", "https://api.keen.io/3.0/projects/%s", "master", ""},
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

// Validate checks Keen.io credentials against multiple API endpoints to determine
// the key type (read, write, or master) and validity.
func (v *KeenIOValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials
	apiKey, projectID, err := v.extractCredentials(match)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	// Try each endpoint in order: read → write → master.
	// A 200 on any endpoint means the key is valid for that type.
	// A 401 on all endpoints means the key is invalid.
	// A 403 means the key is valid but lacks permission for that endpoint — try the next one.
	allForbidden := true
	for _, ep := range keenValidationEndpoints {
		result, forbidden, err := v.tryEndpoint(ctx, ep, apiKey, projectID)
		if err != nil {
			return result, nil
		}
		if result != nil {
			return result, nil
		}
		if !forbidden {
			allForbidden = false
		}
	}

	// If all endpoints returned 403, the key is valid but has restricted permissions
	if allForbidden {
		return types.NewValidationResult(
			types.StatusValid,
			0.8,
			fmt.Sprintf("valid Keen.io key for project %s (restricted permissions, 403 on all endpoints)", projectID),
		), nil
	}

	return types.NewValidationResult(
		types.StatusUndetermined,
		0.5,
		"unable to determine key validity across all endpoints",
	), nil
}

// tryEndpoint attempts validation against a single Keen.io API endpoint.
// Returns (result, wasForbidden, error). If result is non-nil, validation is conclusive.
// If result is nil, the caller should try the next endpoint.
func (v *KeenIOValidator) tryEndpoint(ctx context.Context, ep keenEndpoint, apiKey, projectID string) (*types.ValidationResult, bool, error) {
	url := fmt.Sprintf(ep.path, projectID)

	var bodyReader io.Reader
	if ep.body != "" {
		bodyReader = strings.NewReader(ep.body)
	}

	req, err := http.NewRequestWithContext(ctx, ep.method, url, bodyReader)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to create request: %v", err),
		), false, nil
	}
	req.Header.Set("Authorization", apiKey)
	if ep.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("request failed: %v", err),
		), false, nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return types.NewValidationResult(
			types.StatusValid,
			1.0,
			fmt.Sprintf("valid Keen.io %s key for project %s", ep.keyType, projectID),
		), false, nil
	case http.StatusUnauthorized:
		return types.NewValidationResult(
			types.StatusInvalid,
			1.0,
			fmt.Sprintf("credentials rejected: HTTP %d", resp.StatusCode),
		), false, nil
	case http.StatusForbidden:
		// Key exists but lacks permission for this endpoint — try next
		return nil, true, nil
	default:
		return types.NewValidationResult(
			types.StatusUndetermined,
			0.5,
			fmt.Sprintf("unexpected status code: HTTP %d", resp.StatusCode),
		), false, nil
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
