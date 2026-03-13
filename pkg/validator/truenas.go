// pkg/validator/truenas.go
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

// Pre-compiled patterns for extracting TrueNAS instance URL from snippet context.
var truenasURLPatterns = []*regexp.Regexp{
	// Env var / config style: TRUENAS_URL=https://192.168.1.50
	regexp.MustCompile(`(?i)(?:TRUENAS_URL|TRUENAS_HOST|TRUE_NAS_URL|TRUE_NAS_HOST|TN_URL|TN_HOST)\s*[=:]\s*["']?(https?://[a-zA-Z0-9._:/-]+?)["'\s]`),
	// URL in curl commands or code containing truenas-related paths
	regexp.MustCompile(`(https?://[a-zA-Z0-9._:-]+)/api/v2\.0`),
	// WebSocket URL (ws:// or wss://) — common for TrueNAS WebSocket API
	regexp.MustCompile(`wss?://([a-zA-Z0-9._:-]+)(?:/websocket)?`),
	// URL with truenas in the hostname
	regexp.MustCompile(`(https?://[a-zA-Z0-9._-]*(?:truenas|true-nas|tn)[a-zA-Z0-9._-]*(?::\d{2,5})?)`),
	// Generic IP-based URL (common for NAS devices on local networks)
	regexp.MustCompile(`(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{2,5})?)`),
}

// TrueNASValidator validates TrueNAS API keys by calling the system info endpoint.
// TrueNAS is self-hosted, so the validator searches snippet context for the instance URL.
type TrueNASValidator struct {
	client *http.Client
}

// NewTrueNASValidator creates a new TrueNAS API key validator.
func NewTrueNASValidator() *TrueNASValidator {
	return &TrueNASValidator{client: http.DefaultClient}
}

// NewTrueNASValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewTrueNASValidatorWithClient(client *http.Client) *TrueNASValidator {
	return &TrueNASValidator{client: client}
}

// Name returns the validator name.
func (v *TrueNASValidator) Name() string {
	return "truenas"
}

// CanValidate returns true for TrueNAS rule IDs.
func (v *TrueNASValidator) CanValidate(ruleID string) bool {
	switch ruleID {
	case "np.truenas.1", "np.truenas.2", "np.truenas.3":
		return true
	}
	return false
}

// Validate checks TrueNAS API key credentials against the system info endpoint.
func (v *TrueNASValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract token from named groups or capture groups
	token := v.extractToken(match)
	if token == "" {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			"token not found in match",
		), nil
	}

	// Search snippet context for TrueNAS instance URL
	baseURL := v.extractURL(match)
	if baseURL == "" {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			"partial credentials: found API key but TrueNAS instance URL not in context",
		), nil
	}

	// If extracted from a WebSocket URL (ws://host), the result is just the host.
	// Prepend http:// so we can call the REST API.
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}

	// Strip trailing slashes and any existing API path
	baseURL = strings.TrimRight(baseURL, "/")
	baseURL = strings.TrimSuffix(baseURL, "/api/v2.0")

	// Call system/info endpoint (read-only, lightweight)
	url := baseURL + "/api/v2.0/system/info"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to create request: %v", err),
		), nil
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("request failed: %v", err),
		), nil
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return types.NewValidationResult(
			types.StatusValid,
			1.0,
			fmt.Sprintf("valid TrueNAS API key for %s", baseURL),
		), nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return types.NewValidationResult(
			types.StatusInvalid,
			1.0,
			fmt.Sprintf("credentials rejected by %s: HTTP %d", baseURL, resp.StatusCode),
		), nil
	default:
		return types.NewValidationResult(
			types.StatusUndetermined,
			0.5,
			fmt.Sprintf("unexpected status code from %s: HTTP %d", baseURL, resp.StatusCode),
		), nil
	}
}

// extractToken extracts the TrueNAS API key from the match.
// Checks named groups first (np.truenas.3), then falls back to capture groups (np.truenas.1, np.truenas.2).
func (v *TrueNASValidator) extractToken(match *types.Match) string {
	// Try named groups first (np.truenas.3 uses (?P<token>...))
	if match.NamedGroups != nil {
		if tokenBytes, ok := match.NamedGroups["token"]; ok && len(tokenBytes) > 0 {
			return string(tokenBytes)
		}
	}

	// Fall back to positional capture groups (np.truenas.1 and np.truenas.2 use unnamed groups)
	if len(match.Groups) > 0 && len(match.Groups[0]) > 0 {
		return string(match.Groups[0])
	}

	return ""
}

// extractURL searches the snippet context for a TrueNAS instance URL.
func (v *TrueNASValidator) extractURL(match *types.Match) string {
	snippetParts := [][]byte{
		match.Snippet.Before,
		match.Snippet.Matching,
		match.Snippet.After,
	}

	for _, pattern := range truenasURLPatterns {
		for _, part := range snippetParts {
			if matches := pattern.FindSubmatch(part); len(matches) >= 2 {
				return string(matches[1])
			}
		}
	}

	return ""
}
