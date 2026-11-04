package validator

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
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
	cfg, err := v.extractConfig(match)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("cannot validate: %v", err)), nil
	}

	host, _ := v.extractHost(match)
	if isLocalhost(host) {
		return types.NewValidationResult(types.StatusUndetermined, 0, "skipping localhost address — cannot validate"), nil
	}

	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to open: %v", err)), nil
	}
	db := sql.OpenDB(connector)
	defer func() { _ = db.Close() }()

	if err := db.PingContext(ctx); err != nil {
		return v.analyzeError(err)
	}

	return types.NewValidationResult(types.StatusValid, 1.0, "MySQL credentials are valid"), nil
}

// extractConfig parses the MySQL URI from the match into a driver Config.
// Only user, password, host, port, database and ssl-mode are taken from the
// URI; every other query parameter is ignored so a scanned URI cannot change
// driver behavior (allowCleartextPasswords, allowAllFiles, timeouts, ...).
func (v *MySQLValidator) extractConfig(match *types.Match) (*mysql.Config, error) {
	raw := v.rawURI(match)
	if raw == "" {
		return nil, fmt.Errorf("no MySQL URI found in match")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	if u.Scheme != "mysql" {
		return nil, fmt.Errorf("unexpected scheme %q", u.Scheme)
	}

	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" || pass == "" {
		return nil, fmt.Errorf("missing user or password")
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host")
	}
	port := u.Port()
	if port == "" {
		port = "3306"
	}

	cfg := mysql.NewConfig()
	cfg.User = user
	cfg.Passwd = pass
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(host, port)
	cfg.DBName = strings.TrimPrefix(u.Path, "/")
	cfg.Timeout = v.timeout

	switch strings.ToUpper(u.Query().Get("ssl-mode")) {
	case "REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY":
		cfg.TLSConfig = "skip-verify"
	}

	return cfg, nil
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
