// pkg/validator/pubnub.go
package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Pre-compiled patterns for extracting PubNub subscription key from snippet context.
var pubnubSubKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(sub-c-[a-z0-9]{8}(?:-[a-z0-9]{4}){3}-[a-z0-9]{12})\b`),
}

// PubNubValidator validates PubNub publish and subscription keys.
// Publish key validation requires the subscription key from snippet context.
type PubNubValidator struct {
	client *http.Client
}

// NewPubNubValidator creates a new PubNub credential validator.
func NewPubNubValidator() *PubNubValidator {
	return &PubNubValidator{client: &http.Client{Timeout: 30 * time.Second}}
}

// NewPubNubValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewPubNubValidatorWithClient(client *http.Client) *PubNubValidator {
	return &PubNubValidator{client: client}
}

// Name returns the validator name.
func (v *PubNubValidator) Name() string {
	return "pubnub"
}

// CanValidate returns true for PubNub rule IDs.
func (v *PubNubValidator) CanValidate(ruleID string) bool {
	return ruleID == "kingfisher.pubnub.1" || ruleID == "kingfisher.pubnub.2"
}

// Validate checks PubNub credentials against the PubNub API.
func (v *PubNubValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	switch match.RuleID {
	case "kingfisher.pubnub.2":
		return v.validateSubKey(ctx, match)
	case "kingfisher.pubnub.1":
		return v.validatePubKey(ctx, match)
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0, "unknown rule ID"), nil
	}
}

// validateSubKey validates a subscription key using the objects endpoint.
func (v *PubNubValidator) validateSubKey(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	subKey := extractPositionalGroup(match)
	if subKey == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "cannot extract subscription key"), nil
	}

	url := fmt.Sprintf("https://ps.pndsn.com/v2/objects/%s/uuids/titus_validate", subKey)
	return v.makeRequest(ctx, url)
}

// validatePubKey validates a publish key by finding the subscription key in context.
func (v *PubNubValidator) validatePubKey(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	pubKey := extractPositionalGroup(match)
	if pubKey == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "cannot extract publish key"), nil
	}

	// Search snippet for subscription key
	subKey := searchSnippet(match.Snippet, pubnubSubKeyPatterns)
	if subKey == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			"partial credentials: found publish key but subscription key not in context"), nil
	}

	url := fmt.Sprintf("https://ps.pndsn.com/publish/%s/%s/0/titus_validate/0/%%22ping%%22?uuid=titus_validate", pubKey, subKey)
	return v.makeRequest(ctx, url)
}

// makeRequest performs the HTTP request and evaluates the response.
func (v *PubNubValidator) makeRequest(ctx context.Context, url string) (*types.ValidationResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			fmt.Sprintf("failed to create request: %v", err)), nil
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			fmt.Sprintf("request failed: %v", err)), nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return types.NewValidationResult(types.StatusValid, 1.0,
			fmt.Sprintf("HTTP %d - PubNub key accepted", resp.StatusCode)), nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return types.NewValidationResult(types.StatusInvalid, 1.0,
			fmt.Sprintf("HTTP %d - PubNub key rejected", resp.StatusCode)), nil
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0.5,
			fmt.Sprintf("HTTP %d - unexpected status code", resp.StatusCode)), nil
	}
}

// extractPositionalGroup extracts the first positional capture group from a match.
func extractPositionalGroup(match *types.Match) string {
	if len(match.Groups) > 0 && len(match.Groups[0]) > 0 {
		return string(match.Groups[0])
	}
	// Fall back to named groups
	for _, name := range []string{"token", "key", "1"} {
		if v, ok := match.NamedGroups[name]; ok && len(v) > 0 {
			return string(v)
		}
	}
	return ""
}
