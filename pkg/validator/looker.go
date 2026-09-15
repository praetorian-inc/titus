package validator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

var lookerBaseURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(https://[a-zA-Z0-9.-]+\.looker\.com(?::\d{2,5})?)`),
}

var lookerClientIDPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:looker|client[_-]?id)\s*[:=]\s*['"]?([a-z0-9]{20})\b`),
}

type LookerValidator struct {
	client  *http.Client
	baseURL string // test override: when set, replaces extracted base URL and skips domain check
}

func NewLookerValidator() *LookerValidator {
	return &LookerValidator{
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func NewLookerValidatorWithClient(client *http.Client) *LookerValidator {
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &LookerValidator{client: client}
}

func (v *LookerValidator) Name() string { return "looker" }

func (v *LookerValidator) CanValidate(ruleID string) bool {
	switch ruleID {
	case "kingfisher.looker.1", "kingfisher.looker.2", "kingfisher.looker.3":
		return true
	}
	return false
}

func (v *LookerValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	switch match.RuleID {
	case "kingfisher.looker.1":
		return types.NewValidationResult(types.StatusUndetermined, 0,
			"base URL alone cannot be validated"), nil
	case "kingfisher.looker.2":
		return types.NewValidationResult(types.StatusUndetermined, 0,
			"client ID alone cannot be validated"), nil
	case "kingfisher.looker.3":
		return v.validateClientSecret(ctx, match)
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0, "unknown rule ID"), nil
	}
}

func (v *LookerValidator) validateClientSecret(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	secret := extractLookerSecret(match)
	if secret == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			"cannot extract client secret from match"), nil
	}

	baseURL := v.baseURL
	if baseURL == "" {
		baseURL = searchSnippet(match.Snippet, lookerBaseURLPatterns)
		if baseURL == "" {
			return types.NewValidationResult(types.StatusUndetermined, 0,
				"partial credentials: found client secret but no Looker base URL in context"), nil
		}

		if !isLookerDomain(baseURL) {
			return types.NewValidationResult(types.StatusUndetermined, 0,
				"base URL is not a valid Looker domain"), nil
		}

		host := extractHostFromURL(baseURL)
		if isLocalhost(host) {
			return types.NewValidationResult(types.StatusUndetermined, 0,
				"skipping localhost address"), nil
		}
	}

	clientID := searchSnippet(match.Snippet, lookerClientIDPatterns)
	if clientID == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			"partial credentials: found client secret but no client ID in context"), nil
	}

	loginURL := strings.TrimRight(baseURL, "/") + "/api/4.0/login"

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			fmt.Sprintf("failed to create request: %v", err)), nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			fmt.Sprintf("request failed: %v", err)), nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusOK:
		return v.verifyLoginResponse(resp, baseURL)
	case resp.StatusCode == http.StatusUnauthorized ||
		resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusNotFound:
		return types.NewValidationResult(types.StatusInvalid, 1.0,
			fmt.Sprintf("Looker credentials rejected: HTTP %d", resp.StatusCode)), nil
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0.5,
			fmt.Sprintf("unexpected status %d from Looker", resp.StatusCode)), nil
	}
}

func (v *LookerValidator) verifyLoginResponse(resp *http.Response, baseURL string) (*types.ValidationResult, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0.5,
			"failed to read login response"), nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0.5,
			"login response is not valid JSON"), nil
	}

	token, ok := result["access_token"]
	if !ok {
		return types.NewValidationResult(types.StatusUndetermined, 0.5,
			"login response missing access_token field"), nil
	}
	tokenStr, ok := token.(string)
	if !ok || tokenStr == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0.5,
			"login response has empty or non-string access_token"), nil
	}

	return types.NewValidationResult(types.StatusValid, 1.0,
		fmt.Sprintf("Looker credentials valid at %s", baseURL)), nil
}

func extractLookerSecret(match *types.Match) string {
	if s := extractPositionalGroup(match); s != "" {
		return s
	}
	if match.NamedGroups != nil {
		if v, ok := match.NamedGroups["secret"]; ok && len(v) > 0 {
			return string(v)
		}
	}
	return ""
}

func isLookerDomain(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if parsed.Scheme != "https" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return strings.HasSuffix(host, ".looker.com")
}
