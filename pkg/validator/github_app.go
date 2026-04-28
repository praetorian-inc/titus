package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

// GitHubAppTokenValidator validates GitHub App tokens (np.github.3).
//
// np.github.3 matches both ghu_ (user-to-server) and ghs_ (server-to-server)
// tokens. These require different validation endpoints:
//
//   - ghu_ tokens represent a user and can call GET /user (returns 200).
//   - ghs_ tokens are installation credentials with no user identity;
//     GET /user always returns 403 regardless of token validity.
//     Instead we use GET /installation/repositories which returns 200
//     for valid installation tokens.
type GitHubAppTokenValidator struct {
	client *http.Client
}

func NewGitHubAppTokenValidator() *GitHubAppTokenValidator {
	return &GitHubAppTokenValidator{client: http.DefaultClient}
}

func NewGitHubAppTokenValidatorWithClient(client *http.Client) *GitHubAppTokenValidator {
	return &GitHubAppTokenValidator{client: client}
}

func (v *GitHubAppTokenValidator) Name() string {
	return "github-app-token"
}

func (v *GitHubAppTokenValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.github.3" || ruleID == "np.github.8"
}

func (v *GitHubAppTokenValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	token := v.extractToken(match)
	if token == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "token not found in match"), nil
	}

	if strings.HasPrefix(token, "ghs_") {
		return v.validateInstallationToken(ctx, token)
	}
	// ghu_ and any other prefix: use /user
	return v.validateUserToken(ctx, token)
}

// validateUserToken validates ghu_ tokens via GET /user.
func (v *GitHubAppTokenValidator) validateUserToken(ctx context.Context, token string) (*types.ValidationResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to create request: %v", err)), nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("request failed: %v", err)), nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return types.NewValidationResult(types.StatusValid, 1.0, "GitHub user token accepted (HTTP 200)"), nil
	case http.StatusUnauthorized:
		return types.NewValidationResult(types.StatusInvalid, 1.0, "GitHub token rejected (HTTP 401)"), nil
	case http.StatusForbidden:
		return types.NewValidationResult(types.StatusInvalid, 1.0, "GitHub token rejected (HTTP 403)"), nil
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0.5, fmt.Sprintf("unexpected response: HTTP %d", resp.StatusCode)), nil
	}
}

// validateInstallationToken validates ghs_ tokens via GET /installation/repositories.
//
// ghs_ tokens are server-to-server installation credentials. GET /user always
// returns 403 for these tokens regardless of validity, so we use
// /installation/repositories instead which returns 200 for valid tokens.
func (v *GitHubAppTokenValidator) validateInstallationToken(ctx context.Context, token string) (*types.ValidationResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/installation/repositories?per_page=1", nil)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to create request: %v", err)), nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("request failed: %v", err)), nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return types.NewValidationResult(types.StatusValid, 1.0, "GitHub installation token accepted (HTTP 200)"), nil
	case http.StatusUnauthorized:
		return types.NewValidationResult(types.StatusInvalid, 1.0, "GitHub installation token rejected (HTTP 401)"), nil
	case http.StatusForbidden:
		// 403 for /installation/repositories means the token is valid but
		// lacks repository access permissions — still a live token.
		return types.NewValidationResult(types.StatusValid, 0.8, "GitHub installation token is live but lacks repo permissions (HTTP 403)"), nil
	case http.StatusNotFound:
		return types.NewValidationResult(types.StatusInvalid, 1.0, "GitHub installation token invalid (HTTP 404)"), nil
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0.5, fmt.Sprintf("unexpected response: HTTP %d", resp.StatusCode)), nil
	}
}

func (v *GitHubAppTokenValidator) extractToken(match *types.Match) string {
	if match.NamedGroups != nil {
		if token, ok := match.NamedGroups["token"]; ok && len(token) > 0 {
			return string(token)
		}
	}
	if len(match.Groups) > 0 {
		return string(match.Groups[0])
	}
	return ""
}
