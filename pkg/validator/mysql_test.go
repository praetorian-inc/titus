package validator

import (
	"context"
	"fmt"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMySQLValidator_Name(t *testing.T) {
	v := NewMySQLValidator()
	assert.Equal(t, "mysql", v.Name())
}

func TestMySQLValidator_CanValidate(t *testing.T) {
	v := NewMySQLValidator()

	tests := []struct {
		name   string
		ruleID string
		want   bool
	}{
		{"valid mysql rule", "kingfisher.mysql.1", true},
		{"postgres rule", "np.postgres.1", false},
		{"empty rule", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, v.CanValidate(tt.ruleID))
		})
	}
}

func TestMySQLValidator_ExtractConfig(t *testing.T) {
	v := NewMySQLValidator()

	tests := []struct {
		name     string
		uri      string
		wantUser string
		wantPass string
		wantAddr string
		wantDB   string
		wantTLS  string
		wantErr  bool
	}{
		{
			name:     "full URI with port and database",
			uri:      "mysql://admin:s3cret@db.example.com:3306/mydb",
			wantUser: "admin", wantPass: "s3cret", wantAddr: "db.example.com:3306", wantDB: "mydb",
		},
		{
			name:     "URI without port defaults to 3306",
			uri:      "mysql://user:pass@db.example.com/app",
			wantUser: "user", wantPass: "pass", wantAddr: "db.example.com:3306", wantDB: "app",
		},
		{
			name:     "URI with custom port",
			uri:      "mysql://user:pass@db.example.com:4406/app",
			wantUser: "user", wantPass: "pass", wantAddr: "db.example.com:4406", wantDB: "app",
		},
		{
			name:     "URI with ssl-mode translates to tls config",
			uri:      "mysql://user:pass@db.example.com:3306/app?ssl-mode=REQUIRED",
			wantUser: "user", wantPass: "pass", wantAddr: "db.example.com:3306", wantDB: "app", wantTLS: "skip-verify",
		},
		{
			name:     "URI with ssl-mode DISABLED leaves tls off",
			uri:      "mysql://user:pass@db.example.com:3306/app?ssl-mode=DISABLED",
			wantUser: "user", wantPass: "pass", wantAddr: "db.example.com:3306", wantDB: "app",
		},
		{
			name:     "URI without database",
			uri:      "mysql://user:pass@db.example.com:3306",
			wantUser: "user", wantPass: "pass", wantAddr: "db.example.com:3306",
		},
		{
			name:     "IPv6 host without port defaults to 3306",
			uri:      "mysql://user:pass@[2001:db8::1]/db",
			wantUser: "user", wantPass: "pass", wantAddr: "[2001:db8::1]:3306", wantDB: "db",
		},
		{
			name:     "IPv6 host with port",
			uri:      "mysql://user:pass@[2001:db8::1]:3307/db",
			wantUser: "user", wantPass: "pass", wantAddr: "[2001:db8::1]:3307", wantDB: "db",
		},
		{
			name:     "driver parameters in the query are ignored",
			uri:      "mysql://user:pass@db.example.com/app?allowCleartextPasswords=true&allowAllFiles=true&allowOldPasswords=true&timeout=1h&tls=false",
			wantUser: "user", wantPass: "pass", wantAddr: "db.example.com:3306", wantDB: "app",
		},
		{
			name:     "encoded query in database name stays literal",
			uri:      "mysql://user:pass@db.example.com/app%3FallowCleartextPasswords%3Dtrue",
			wantUser: "user", wantPass: "pass", wantAddr: "db.example.com:3306", wantDB: "app?allowCleartextPasswords=true",
		},
		{
			name:     "encoded address in password stays literal",
			uri:      "mysql://user:p%40tcp(evil.example.com:3306)%2F@db.example.com/app",
			wantUser: "user", wantPass: "p@tcp(evil.example.com:3306)/", wantAddr: "db.example.com:3306", wantDB: "app",
		},
		{
			name:    "missing password",
			uri:     "mysql://user@db.example.com:3306/app",
			wantErr: true,
		},
		{
			name:    "missing host",
			uri:     "mysql://user:pass@:3306/app",
			wantErr: true,
		},
		{
			name:    "wrong scheme",
			uri:     "postgres://user:pass@db.example.com/app",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := &types.Match{
				RuleID: "kingfisher.mysql.1",
				Groups: [][]byte{[]byte(tt.uri)},
			}

			cfg, err := v.extractConfig(match)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantUser, cfg.User)
			assert.Equal(t, tt.wantPass, cfg.Passwd)
			assert.Equal(t, "tcp", cfg.Net)
			assert.Equal(t, tt.wantAddr, cfg.Addr)
			assert.Equal(t, tt.wantDB, cfg.DBName)
			assert.Equal(t, tt.wantTLS, cfg.TLSConfig)
			assert.Equal(t, v.timeout, cfg.Timeout)
			assert.False(t, cfg.AllowCleartextPasswords)
			assert.False(t, cfg.AllowAllFiles)
			assert.False(t, cfg.AllowOldPasswords)
			assert.Empty(t, cfg.Params)
		})
	}
}

func TestMySQLValidator_SkipsLocalhost(t *testing.T) {
	v := NewMySQLValidator()

	hosts := []string{"localhost", "127.0.0.1", "::1"}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			match := &types.Match{
				RuleID: "kingfisher.mysql.1",
				Groups: [][]byte{[]byte("mysql://user:pass@" + host + ":3306/db")},
			}
			result, err := v.Validate(context.Background(), match)
			require.NoError(t, err)
			assert.Equal(t, types.StatusUndetermined, result.Status)
			assert.Contains(t, result.Message, "localhost")
		})
	}
}

func TestMySQLValidator_MissingCredentials(t *testing.T) {
	v := NewMySQLValidator()

	match := &types.Match{
		RuleID: "kingfisher.mysql.1",
		Groups: [][]byte{},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

func TestMySQLValidator_ConnectionError(t *testing.T) {
	v := NewMySQLValidator()

	match := &types.Match{
		RuleID: "kingfisher.mysql.1",
		Groups: [][]byte{[]byte("mysql://user:pass@nonexistent.invalid:3306/db")},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
}

func TestMySQLValidator_AnalyzeError_AccessDenied(t *testing.T) {
	v := NewMySQLValidator()

	result, err := v.analyzeError(fmt.Errorf("Error 1045 (28000): Access denied for user 'root'@'10.0.0.1'"))
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Contains(t, result.Message, "credentials rejected")
}

func TestMySQLValidator_AnalyzeError_NetworkError(t *testing.T) {
	v := NewMySQLValidator()

	result, err := v.analyzeError(fmt.Errorf("dial tcp: lookup nonexistent.invalid: no such host"))
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "connection failed")
}
