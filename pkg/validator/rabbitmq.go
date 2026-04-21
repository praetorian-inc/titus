// pkg/validator/rabbitmq.go
package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

// RabbitMQValidator validates RabbitMQ credentials via the Management HTTP API.
// Uses GET /api/whoami with Basic Auth — the lightest endpoint that confirms
// credential validity. Falls back gracefully when the management plugin is not
// enabled (connection refused → StatusUndetermined).
//
// Port selection:
//   - CloudAMQP (*.cloudamqp.com): HTTPS on port 443
//   - Amazon MQ (*.amazonaws.com): HTTPS on port 443
//   - Default: HTTP on port 15672
type RabbitMQValidator struct {
	client *http.Client
}

// NewRabbitMQValidator creates a new RabbitMQ credential validator.
func NewRabbitMQValidator() *RabbitMQValidator {
	return &RabbitMQValidator{client: http.DefaultClient}
}

// NewRabbitMQValidatorWithClient creates a validator with a custom HTTP client (for testing).
func NewRabbitMQValidatorWithClient(client *http.Client) *RabbitMQValidator {
	return &RabbitMQValidator{client: client}
}

// Name returns the validator name.
func (v *RabbitMQValidator) Name() string {
	return "rabbitmq"
}

// CanValidate returns true for RabbitMQ-related rule IDs.
func (v *RabbitMQValidator) CanValidate(ruleID string) bool {
	return ruleID == "kingfisher.rabbitmq.1"
}

// Validate checks RabbitMQ credentials against the Management API.
func (v *RabbitMQValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	user, password, host, err := v.extractCredentials(match)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	if isLocalhost(host) || isExampleHost(host) {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			"skipping localhost/example address - cannot validate remotely",
		), nil
	}

	mgmtURL := v.managementURL(host)

	req, err := http.NewRequestWithContext(ctx, "GET", mgmtURL+"/api/whoami", nil)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to create request: %v", err),
		), nil
	}
	req.SetBasicAuth(user, password)

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0.3,
			fmt.Sprintf("management API unreachable (plugin may not be enabled): %v", err),
		), nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return types.NewValidationResult(
			types.StatusValid,
			1.0,
			fmt.Sprintf("valid RabbitMQ credentials for user %s@%s", user, host),
		), nil
	case http.StatusUnauthorized:
		return types.NewValidationResult(
			types.StatusInvalid,
			1.0,
			fmt.Sprintf("credentials rejected by %s: HTTP 401", host),
		), nil
	default:
		return types.NewValidationResult(
			types.StatusUndetermined,
			0.5,
			fmt.Sprintf("unexpected status from management API: HTTP %d", resp.StatusCode),
		), nil
	}
}

// extractCredentials extracts user, password, and host from named capture groups.
func (v *RabbitMQValidator) extractCredentials(match *types.Match) (user, password, host string, err error) {
	if match.NamedGroups == nil {
		return "", "", "", fmt.Errorf("no named capture groups in match")
	}

	userBytes, hasUser := match.NamedGroups["user"]
	if !hasUser || len(userBytes) == 0 {
		return "", "", "", fmt.Errorf("user not found in named groups")
	}

	passBytes, hasPass := match.NamedGroups["password"]
	if !hasPass || len(passBytes) == 0 {
		return "", "", "", fmt.Errorf("password not found in named groups")
	}

	hostBytes, hasHost := match.NamedGroups["host"]
	if !hasHost || len(hostBytes) == 0 {
		return "", "", "", fmt.Errorf("host not found in named groups")
	}

	return string(userBytes), string(passBytes), string(hostBytes), nil
}

// managementURL returns the Management API base URL for a given host.
// Cloud providers (CloudAMQP, Amazon MQ) use HTTPS on 443; self-hosted
// defaults to HTTP on 15672.
func (v *RabbitMQValidator) managementURL(host string) string {
	if strings.HasSuffix(host, ".cloudamqp.com") || strings.HasSuffix(host, ".amazonaws.com") {
		return "https://" + host
	}
	return "http://" + host + ":15672"
}

// isExampleHost returns true for placeholder/documentation hostnames.
func isExampleHost(host string) bool {
	return host == "example.com" || strings.HasSuffix(host, ".example.com") ||
		host == "contoso.com" || strings.HasSuffix(host, ".contoso.com")
}
