package validator

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/praetorian-inc/titus/pkg/types"
)

// MySQLValidator validates MySQL connection credentials extracted from URIs.
type MySQLValidator struct {
	timeout time.Duration
}

// NewMySQLValidator creates a new MySQL credential validator.
func NewMySQLValidator() *MySQLValidator {
	return &MySQLValidator{
		timeout: 5 * time.Second,
	}
}

func (v *MySQLValidator) Name() string { return "mysql" }

func (v *MySQLValidator) CanValidate(ruleID string) bool {
	return ruleID == "kingfisher.mysql.1"
}

// Validate checks MySQL credentials by attempting a connection.
func (v *MySQLValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	dsn, err := v.extractDSN(match)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("cannot validate: %v", err)), nil
	}

	host, _ := v.extractHost(match)
	if isLocalhost(host) {
		return types.NewValidationResult(types.StatusUndetermined, 0, "skipping localhost address — cannot validate"), nil
	}

	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to open: %v", err)), nil
	}
	defer func() { _ = db.Close() }()

	if err := db.PingContext(ctx); err != nil {
		return v.analyzeError(err)
	}

	return types.NewValidationResult(types.StatusValid, 1.0, "MySQL credentials are valid"), nil
}

// extractDSN parses the MySQL URI from the match and converts it to a
// go-sql-driver/mysql DSN: user:pass@tcp(host:port)/dbname?timeout=5s
func (v *MySQLValidator) extractDSN(match *types.Match) (string, error) {
	raw := v.rawURI(match)
	if raw == "" {
		return "", fmt.Errorf("no MySQL URI found in match")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URI: %w", err)
	}

	if u.Scheme != "mysql" {
		return "", fmt.Errorf("unexpected scheme %q", u.Scheme)
	}

	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" || pass == "" {
		return "", fmt.Errorf("missing user or password")
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "3306"
	}

	dbName := strings.TrimPrefix(u.Path, "/")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?timeout=%s",
		user, pass, host, port, dbName, v.timeout)

	q := u.Query()
	if mode := q.Get("ssl-mode"); mode != "" {
		q.Del("ssl-mode")
		if strings.EqualFold(mode, "REQUIRED") || strings.EqualFold(mode, "VERIFY_CA") || strings.EqualFold(mode, "VERIFY_IDENTITY") {
			q.Set("tls", "skip-verify")
		}
	}
	if encoded := q.Encode(); encoded != "" {
		dsn += "&" + encoded
	}

	return dsn, nil
}

func (v *MySQLValidator) extractHost(match *types.Match) (string, error) {
	raw := v.rawURI(match)
	if raw == "" {
		return "", fmt.Errorf("no URI")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

func (v *MySQLValidator) rawURI(match *types.Match) string {
	if len(match.Groups) > 0 {
		return string(match.Groups[0])
	}
	return ""
}

func (v *MySQLValidator) analyzeError(err error) (*types.ValidationResult, error) {
	msg := err.Error()
	if strings.Contains(msg, "Access denied") {
		return types.NewValidationResult(types.StatusInvalid, 1.0, fmt.Sprintf("credentials rejected: %v", err)), nil
	}
	return types.NewValidationResult(types.StatusUndetermined, 0.5, fmt.Sprintf("connection failed: %v", err)), nil
}
