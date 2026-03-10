// pkg/validator/mattermost.go
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

// Pre-compiled pattern for extracting Mattermost instance URL from snippet context.
// Matches URLs containing "mattermost" or "mm" in the hostname.
var mattermostURLPattern = regexp.MustCompile(`(https?://[a-zA-Z0-9._-]*(?:mattermost|mm)[a-zA-Z0-9._-]*(?::\d{2,5})?)`)

// MattermostValidator validates Mattermost tokens and webhook URLs.
type MattermostValidator struct {
	client *http.Client
}

// NewMattermostValidator creates a new Mattermost validator.
func NewMattermostValidator() *MattermostValidator {
	return &MattermostValidator{client: http.DefaultClient}
}

// NewMattermostValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewMattermostValidatorWithClient(client *http.Client) *MattermostValidator {
	return &MattermostValidator{client: client}
}

// Name returns the validator name.
func (v *MattermostValidator) Name() string {
	return "mattermost"
}

// CanValidate returns true for Mattermost rule IDs.
func (v *MattermostValidator) CanValidate(ruleID string) bool {
	switch ruleID {
	case "kingfisher.mattermost.2", "kingfisher.mattermost.3", "np.mattermost.1":
		return true
	}
	return false
}

// Validate performs validation for Mattermost secrets.
func (v *MattermostValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	switch match.RuleID {
	case "kingfisher.mattermost.3":
		return v.validateWebhook(ctx, match)
	case "kingfisher.mattermost.2", "np.mattermost.1":
		return v.validateAccessToken(ctx, match)
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0, "unsupported rule ID"), nil
	}
}

// validateWebhook validates a Mattermost incoming webhook URL by POSTing an empty text payload.
// A 400 response means the webhook exists (valid but missing payload text).
func (v *MattermostValidator) validateWebhook(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	if match.NamedGroups == nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, "no named capture groups in match"), nil
	}

	webhookBytes, ok := match.NamedGroups["webhook"]
	if !ok || len(webhookBytes) == 0 {
		return types.NewValidationResult(types.StatusUndetermined, 0, "webhook URL not found in named groups"), nil
	}
	webhookURL := string(webhookBytes)

	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, strings.NewReader(`{"text":""}`))
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to create request: %v", err)), nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("request failed: %v", err)), nil
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return types.NewValidationResult(types.StatusValid, 1.0, "webhook accepted the request"), nil
	case http.StatusBadRequest:
		// 400 means webhook exists but payload is invalid (missing text) - this is a valid webhook
		return types.NewValidationResult(types.StatusValid, 1.0, "webhook exists (HTTP 400 - empty text rejected)"), nil
	case http.StatusNotFound, http.StatusForbidden:
		return types.NewValidationResult(types.StatusInvalid, 1.0, fmt.Sprintf("webhook rejected: HTTP %d", resp.StatusCode)), nil
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0.5, fmt.Sprintf("unexpected status code: HTTP %d", resp.StatusCode)), nil
	}
}

// validateAccessToken validates a Mattermost access token by calling /api/v4/users/me.
func (v *MattermostValidator) validateAccessToken(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	if match.NamedGroups == nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, "no named capture groups in match"), nil
	}

	tokenBytes, ok := match.NamedGroups["token"]
	if !ok || len(tokenBytes) == 0 {
		return types.NewValidationResult(types.StatusUndetermined, 0, "token not found in named groups"), nil
	}
	token := string(tokenBytes)

	// Search snippet context for a Mattermost instance URL
	baseURL := v.extractURL(match)
	if baseURL == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "partial credentials: found token but Mattermost instance URL not in context"), nil
	}

	// Strip trailing slashes and any existing /api/v4 path
	baseURL = strings.TrimRight(baseURL, "/")
	baseURL = strings.TrimSuffix(baseURL, "/api/v4")

	url := baseURL + "/api/v4/users/me"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to create request: %v", err)), nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("request failed: %v", err)), nil
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return types.NewValidationResult(types.StatusValid, 1.0, fmt.Sprintf("valid Mattermost token for %s", baseURL)), nil
	case http.StatusUnauthorized:
		return types.NewValidationResult(types.StatusInvalid, 1.0, fmt.Sprintf("credentials rejected by %s: HTTP 401", baseURL)), nil
	case http.StatusForbidden:
		return types.NewValidationResult(types.StatusInvalid, 1.0, fmt.Sprintf("credentials rejected by %s: HTTP 403", baseURL)), nil
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0.5, fmt.Sprintf("unexpected status code from %s: HTTP %d", baseURL, resp.StatusCode)), nil
	}
}

// extractURL searches the snippet context for a Mattermost instance URL.
func (v *MattermostValidator) extractURL(match *types.Match) string {
	snippetParts := [][]byte{
		match.Snippet.Before,
		match.Snippet.Matching,
		match.Snippet.After,
	}

	for _, part := range snippetParts {
		if matches := mattermostURLPattern.FindSubmatch(part); len(matches) >= 2 {
			return string(matches[1])
		}
	}

	return ""
}
