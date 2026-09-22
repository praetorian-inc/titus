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

func TestMySQLValidator_ExtractDSN(t *testing.T) {
	v := NewMySQLValidator()

	tests := []struct {
		name    string
		uri     string
		wantDSN string
		wantErr bool
	}{
		{
			name:    "full URI with port and database",
			uri:     "mysql://admin:s3cret@db.example.com:3306/mydb",
			wantDSN: "admin:s3cret@tcp(db.example.com:3306)/mydb?timeout=5s",
		},
		{
			name:    "URI without port defaults to 3306",
			uri:     "mysql://user:pass@db.example.com/app",
			wantDSN: "user:pass@tcp(db.example.com:3306)/app?timeout=5s",
		},
		{
			name:    "URI with custom port",
			uri:     "mysql://user:pass@db.example.com:4406/app",
			wantDSN: "user:pass@tcp(db.example.com:4406)/app?timeout=5s",
		},
		{
			name:    "URI with ssl-mode translates to tls param",
			uri:     "mysql://user:pass@db.example.com:3306/app?ssl-mode=REQUIRED",
			wantDSN: "user:pass@tcp(db.example.com:3306)/app?timeout=5s&tls=skip-verify",
		},
		{
			name:    "URI without database",
			uri:     "mysql://user:pass@db.example.com:3306",
			wantDSN: "user:pass@tcp(db.example.com:3306)/?timeout=5s",
		},
		{
			name:    "IPv6 host without port defaults to 3306",
			uri:     "mysql://user:pass@[2001:db8::1]/db",
			wantDSN: "user:pass@tcp(2001:db8::1:3306)/db?timeout=5s",
		},
		{
			name:    "IPv6 host with port",
			uri:     "mysql://user:pass@[2001:db8::1]:3307/db",
			wantDSN: "user:pass@tcp(2001:db8::1:3307)/db?timeout=5s",
		},
		{
			name:    "missing password",
			uri:     "mysql://user@db.example.com:3306/app",
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

			dsn, err := v.extractDSN(match)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantDSN, dsn)
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
