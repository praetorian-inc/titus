// pkg/validator/confluent.go
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

// Pre-compiled patterns for extracting the Confluent key ID from snippet context.
// The Confluent API key ID is a 16-character uppercase alphanumeric string
// (e.g. "ABCD1234EFGH5678"). We look for it near keyword indicators.
var confluentClientIDPatterns = []*regexp.Regexp{
	// Keyword-proximity: confluent/ccloud/cpdev/kafka followed by the key ID.
	regexp.MustCompile(`(?i)(?:confluent|ccloud|cpdev|kafka)[^A-Z0-9]{0,32}([A-Z0-9]{16})`),
	// Explicit label: client_id= or api_key= followed by the key ID.
	regexp.MustCompile(`(?i)(?:client[_-]?id|api[_-]?key)\s*[=:]\s*["'\s]?([A-Z0-9]{16})`),
}

// ConfluentValidator validates Confluent Cloud API-key credentials using Basic
// authentication against the Confluent Cloud IAM API.
//
// Confluent API keys consist of two parts:
//   - client_id: a 16-character uppercase alphanumeric key ID
//   - secret:    a 64-character base64 string (confluent.2) or a cflt-prefixed
//     token (confluent.3)
//
// Validation uses GET https://api.confluent.cloud/iam/v2/api-keys with
// Authorization: Basic base64(client_id:secret). A 200 response means valid;
// 401/403 means invalid; anything else is undetermined.
type ConfluentValidator struct {
	client  *http.Client
	baseURL string // overridable for tests; defaults to https://api.confluent.cloud
}

// NewConfluentValidator creates a Confluent API-key validator using the default HTTP client.
func NewConfluentValidator() *ConfluentValidator {
	return &ConfluentValidator{
		client:  http.DefaultClient,
		baseURL: "https://api.confluent.cloud",
	}
}

// NewConfluentValidatorWithClient creates a Confluent API-key validator with a
// custom HTTP client (used in tests to inject a VCR or httptest client).
func NewConfluentValidatorWithClient(client *http.Client) *ConfluentValidator {
	return &ConfluentValidator{
		client:  client,
		baseURL: "https://api.confluent.cloud",
	}
}

// Name returns the validator identifier.
func (v *ConfluentValidator) Name() string {
	return "confluent"
}

// CanValidate returns true for the three Confluent Cloud API-key rule IDs.
func (v *ConfluentValidator) CanValidate(ruleID string) bool {
	switch ruleID {
	case "kingfisher.confluent.1",
		"kingfisher.confluent.2",
		"kingfisher.confluent.3":
		return true
	}
	return false
}

// Validate authenticates with the Confluent Cloud IAM API and maps the HTTP
// response to a ValidationStatus.
//
// Missing or incomplete credentials return StatusUndetermined without making an
// HTTP request. The method never returns a non-nil error; network and protocol
// failures are surfaced as StatusUndetermined with a descriptive message.
func (v *ConfluentValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	clientID, secret, err := v.extractCredentials(match)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate confluent credentials: %v", err),
		), nil
	}

	// Build Basic auth header: base64(client_id:secret)
	creds := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + secret))

	url := v.baseURL + "/iam/v2/api-keys"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to build request: %v", err),
		), nil
	}
	req.Header.Set("Authorization", "Basic "+creds)

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("request failed: %v", err),
		), nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return types.NewValidationResult(
			types.StatusValid,
			1.0,
			fmt.Sprintf("valid Confluent API key for client %s", clientID),
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

// extractCredentials extracts the Confluent client_id and secret from a match.
//
// Secret resolution (in priority order):
//  1. NamedGroups["secret"] — set by confluent.2 (64-char base64 string)
//  2. Groups[0]            — set by confluent.3 (full cflt… token)
//
// Client ID resolution: scan Snippet.Before / .Matching / .After with
// confluentClientIDPatterns (keyword-proximity or explicit label).
//
// Returns an error when either piece is missing; callers map errors to
// StatusUndetermined without making a network request.
func (v *ConfluentValidator) extractCredentials(match *types.Match) (clientID, secret string, err error) {
	// --- Extract secret ---
	if match.NamedGroups != nil {
		if s, ok := match.NamedGroups["secret"]; ok && len(s) > 0 {
			secret = string(s)
		}
	}
	// Fallback: confluent.3 stores the full cflt… token in Groups[0].
	if secret == "" && len(match.Groups) > 0 && len(match.Groups[0]) > 0 {
		secret = string(match.Groups[0])
	}
	if secret == "" {
		return "", "", fmt.Errorf("secret not found in named groups or positional groups")
	}

	// --- Extract client_id from snippet context ---
	snippetParts := [][]byte{
		match.Snippet.Before,
		match.Snippet.Matching,
		match.Snippet.After,
	}
	for _, pattern := range confluentClientIDPatterns {
		for _, part := range snippetParts {
			if sub := pattern.FindSubmatch(part); len(sub) >= 2 {
				return string(sub[1]), secret, nil
			}
		}
	}

	return "", "", fmt.Errorf("partial credentials: found secret but client_id not in snippet context")
}
