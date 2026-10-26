package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

var vaultAddrPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:VAULT_ADDR|vault_addr|VAULT_URL|vault_url|VAULT_HOST|vault_host)\s*[=:]\s*["']?(https?://[^\s"']+)`),
	regexp.MustCompile(`(https?://[a-zA-Z0-9._-]*vault[a-zA-Z0-9._-]*(?::\d+)?)`),
}

type HashiCorpValidator struct {
	client *http.Client
}

func NewHashiCorpValidator() *HashiCorpValidator {
	return &HashiCorpValidator{client: &http.Client{Timeout: 30 * time.Second}}
}

func NewHashiCorpValidatorWithClient(client *http.Client) *HashiCorpValidator {
	return &HashiCorpValidator{client: client}
}

func (v *HashiCorpValidator) Name() string { return "hashicorp" }

func (v *HashiCorpValidator) CanValidate(ruleID string) bool {
	switch ruleID {
	case "np.hashicorp.1", "np.hashicorp.2", "np.hashicorp.3",
		"np.hashicorp.4", "np.hashicorp.5", "np.hashicorp.6",
		"np.hashicorp.7":
		return true
	}
	return false
}

func (v *HashiCorpValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	if match.RuleID == "np.hashicorp.7" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "unseal keys cannot be safely validated via API"), nil
	}

	token := extractNamedGroup(match, "token")
	if token == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "no token found in match"), nil
	}

	vaultURL := extractVaultURL(match.Snippet)
	if vaultURL == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "vault server URL not found in context"), nil
	}

	host := extractHostFromURL(vaultURL)
	if host == "localhost" || host == "127.0.0.1" || host == "[::1]" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "skipping localhost vault server"), nil
	}

	return v.validateAgainst(ctx, token, vaultURL)
}

func (v *HashiCorpValidator) validateAgainst(ctx context.Context, token, vaultURL string) (*types.ValidationResult, error) {
	url := strings.TrimRight(vaultURL, "/") + "/v1/auth/token/lookup-self"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to create request: %v", err)), nil
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("request failed: %v", err)), nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return types.NewValidationResult(types.StatusValid, 1.0, fmt.Sprintf("valid Vault token at %s", vaultURL)), nil
	case http.StatusForbidden:
		return types.NewValidationResult(types.StatusValid, 1.0, fmt.Sprintf("valid Vault token at %s (authenticated; insufficient permissions for lookup-self)", vaultURL)), nil
	case http.StatusBadRequest, http.StatusNotFound:
		return types.NewValidationResult(types.StatusInvalid, 1.0, fmt.Sprintf("invalid Vault token: HTTP %d", resp.StatusCode)), nil
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0.5, fmt.Sprintf("unexpected status: HTTP %d", resp.StatusCode)), nil
	}
}

func extractVaultURL(snippet types.Snippet) string {
	parts := [][]byte{snippet.Before, snippet.Matching, snippet.After}
	for _, pattern := range vaultAddrPatterns {
		for _, part := range parts {
			if m := pattern.FindSubmatch(part); len(m) >= 2 {
				return strings.TrimRight(string(m[1]), "'\"")
			}
		}
	}
	return ""
}
