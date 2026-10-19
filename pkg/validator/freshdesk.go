package validator

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

var freshdeskDomainPatterns = []*regexp.Regexp{
	regexp.MustCompile(`https?://([a-z0-9][a-z0-9\-]{0,62}\.freshdesk\.com)`),
	regexp.MustCompile(`\b([a-z0-9][a-z0-9\-]{0,62}\.freshdesk\.com)\b`),
}

type FreshdeskValidator struct {
	client *http.Client
}

func NewFreshdeskValidator() *FreshdeskValidator {
	return &FreshdeskValidator{client: &http.Client{Timeout: 30 * time.Second}}
}

func NewFreshdeskValidatorWithClient(client *http.Client) *FreshdeskValidator {
	return &FreshdeskValidator{client: client}
}

func (v *FreshdeskValidator) Name() string { return "freshdesk" }

func (v *FreshdeskValidator) CanValidate(ruleID string) bool {
	return ruleID == "kingfisher.freshdesk.2"
}

func (v *FreshdeskValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	token := extractNamedGroup(match, "token")
	if token == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "no API key found in match"), nil
	}

	domain := searchSnippet(match.Snippet, freshdeskDomainPatterns)
	if domain == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "freshdesk domain not found in context"), nil
	}

	baseURL := fmt.Sprintf("https://%s", domain)
	return v.validateAgainst(ctx, match, baseURL)
}

func (v *FreshdeskValidator) validateAgainst(ctx context.Context, match *types.Match, baseURL string) (*types.ValidationResult, error) {
	token := extractNamedGroup(match, "token")
	if token == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "no API key found in match"), nil
	}

	url := baseURL + "/api/v2/agents/me"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to create request: %v", err)), nil
	}

	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(token+":X")))

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("request failed: %v", err)), nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return types.NewValidationResult(types.StatusValid, 1.0, fmt.Sprintf("valid Freshdesk API key for %s", baseURL)), nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return types.NewValidationResult(types.StatusInvalid, 1.0, fmt.Sprintf("credentials rejected: HTTP %d", resp.StatusCode)), nil
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0.5, fmt.Sprintf("unexpected status: HTTP %d", resp.StatusCode)), nil
	}
}

func extractNamedGroup(match *types.Match, names ...string) string {
	if match.NamedGroups != nil {
		for _, name := range names {
			if v, ok := match.NamedGroups[name]; ok && len(v) > 0 {
				return string(v)
			}
		}
	}
	if len(match.Groups) > 1 && len(match.Groups[1]) > 0 {
		return string(match.Groups[1])
	}
	return ""
}
