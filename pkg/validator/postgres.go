// pkg/validator/postgres.go
package validator

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/praetorian-inc/titus/pkg/types"
)

// PostgresValidator validates PostgreSQL connection credentials.
// Uses pgx/v5 pgconn for low-level connection testing without connection pooling.
type PostgresValidator struct {
	timeout int // connection timeout in seconds
}

// NewPostgresValidator creates a new PostgreSQL credential validator.
func NewPostgresValidator() *PostgresValidator {
	return &PostgresValidator{
		timeout: 5, // 5 second timeout
	}
}

// Name returns the validator name.
func (v *PostgresValidator) Name() string {
	return "postgres"
}

// CanValidate returns true for PostgreSQL-related rule IDs.
func (v *PostgresValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.postgres.1"
}

// Validate checks PostgreSQL credentials by attempting a connection.
func (v *PostgresValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials from named groups
	username, password, host, port, err := v.extractCredentials(match)
	if err != nil {
		// Incomplete credentials - cannot validate
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	// Skip localhost addresses (can't validate local-only credentials)
	if isLocalhost(host) {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			"skipping localhost address - cannot validate",
		), nil
	}

	// Build connection string
	// Format: postgres://user:pass@host:port/postgres?connect_timeout=5
	connString := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/postgres?connect_timeout=%d",
		username, password, host, port, v.timeout,
	)

	// Attempt connection
	conn, err := pgconn.Connect(ctx, connString)
	if err != nil {
		// Analyze error to determine if it's auth failure or network issue
		return v.analyzeConnectionError(err)
	}
	defer conn.Close(ctx)

	// Connection successful - credentials are valid
	return types.NewValidationResult(
		types.StatusValid,
		1.0,
		fmt.Sprintf("valid PostgreSQL credentials for user %s@%s:%s", username, host, port),
	), nil
}

// extractCredentials extracts PostgreSQL credentials from match's named capture groups.
// Returns username, password, host, port (defaults to "5432"), and error if incomplete.
func (v *PostgresValidator) extractCredentials(match *types.Match) (username, password, host, port string, err error) {
	if match.NamedGroups == nil {
		return "", "", "", "", fmt.Errorf("no named capture groups in match")
	}

	// Extract username
	usernameBytes, hasUsername := match.NamedGroups["username"]
	if !hasUsername || len(usernameBytes) == 0 {
		return "", "", "", "", fmt.Errorf("username not found in named groups")
	}
	username = string(usernameBytes)

	// Extract password
	passwordBytes, hasPassword := match.NamedGroups["password"]
	if !hasPassword || len(passwordBytes) == 0 {
		return "", "", "", "", fmt.Errorf("password not found in named groups")
	}
	password = string(passwordBytes)

	// Extract host
	hostBytes, hasHost := match.NamedGroups["host"]
	if !hasHost || len(hostBytes) == 0 {
		return "", "", "", "", fmt.Errorf("host not found in named groups")
	}
	host = string(hostBytes)

	// Extract port (optional, defaults to 5432)
	port = "5432"
	if portBytes, hasPort := match.NamedGroups["port"]; hasPort && len(portBytes) > 0 {
		port = string(portBytes)
	}

	return username, password, host, port, nil
}

// isLocalhost returns true if the host is a localhost address.
func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// analyzeConnectionError determines validation status from connection error.
// Auth failures return StatusInvalid, network errors return StatusUndetermined.
func (v *PostgresValidator) analyzeConnectionError(err error) (*types.ValidationResult, error) {
	errMsg := err.Error()

	// Check for authentication failure patterns
	// pgx returns errors containing "authentication failed" or "password authentication failed"
	if contains(errMsg, "authentication failed") || contains(errMsg, "password authentication failed") {
		return types.NewValidationResult(
			types.StatusInvalid,
			1.0,
			fmt.Sprintf("credentials rejected: %v", err),
		), nil
	}

	// Network errors, DNS resolution failures, timeouts, connection refused
	// These don't definitively prove credentials are invalid
	return types.NewValidationResult(
		types.StatusUndetermined,
		0.5,
		fmt.Sprintf("connection failed (unable to verify credentials): %v", err),
	), nil
}

// contains checks if a string contains a substring (case-sensitive).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

// findSubstring searches for substr in s.
func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
