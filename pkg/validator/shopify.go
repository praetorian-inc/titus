// pkg/validator/shopify.go
package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Pre-compiled pattern for extracting Shopify store domain from snippet context.
var shopifyDomainPattern = regexp.MustCompile(`([\w-]+\.myshopify\.com)`)

// ShopifyValidator validates Shopify access tokens using the Admin API.
type ShopifyValidator struct {
	client *http.Client
}

// NewShopifyValidator creates a new Shopify access token validator.
func NewShopifyValidator() *ShopifyValidator {
	return &ShopifyValidator{client: http.DefaultClient}
}

// NewShopifyValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewShopifyValidatorWithClient(client *http.Client) *ShopifyValidator {
	return &ShopifyValidator{client: client}
}

// Name returns the validator name.
func (v *ShopifyValidator) Name() string {
	return "shopify"
}

// CanValidate returns true for Shopify access token rule IDs.
func (v *ShopifyValidator) CanValidate(ruleID string) bool {
	switch ruleID {
	case "np.shopify.3", "np.shopify.4", "np.shopify.5":
		return true
	}
	return false
}

// Validate checks Shopify access token credentials against the Admin API.
func (v *ShopifyValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract token from named groups
	if match.NamedGroups == nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			"no named capture groups in match",
		), nil
	}

	tokenBytes, hasToken := match.NamedGroups["token"]
	if !hasToken || len(tokenBytes) == 0 {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			"token not found in named groups",
		), nil
	}
	token := string(tokenBytes)

	// Search snippet context for Shopify store domain
	domain := v.extractDomain(match)
	if domain == "" {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			"partial credentials: found token but store domain (.myshopify.com) not in context",
		), nil
	}

	// Build request to Shopify Admin API
	url := fmt.Sprintf("https://%s/admin/api/2024-01/shop.json", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to create request: %v", err),
		), nil
	}

	req.Header.Set("X-Shopify-Access-Token", token)

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
			fmt.Sprintf("valid Shopify access token for store %s", domain),
		), nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return types.NewValidationResult(
			types.StatusInvalid,
			1.0,
			fmt.Sprintf("credentials rejected by %s: HTTP %d", domain, resp.StatusCode),
		), nil
	default:
		return types.NewValidationResult(
			types.StatusUndetermined,
			0.5,
			fmt.Sprintf("unexpected status code from %s: HTTP %d", domain, resp.StatusCode),
		), nil
	}
}

// extractDomain searches the snippet context for a .myshopify.com domain.
func (v *ShopifyValidator) extractDomain(match *types.Match) string {
	snippetParts := [][]byte{
		match.Snippet.Before,
		match.Snippet.Matching,
		match.Snippet.After,
	}

	for _, part := range snippetParts {
		if matches := shopifyDomainPattern.FindSubmatch(part); len(matches) >= 2 {
			return string(matches[1])
		}
	}

	return ""
}
