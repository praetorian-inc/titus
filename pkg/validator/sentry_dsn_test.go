package validator

import (
	"context"
	"fmt"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSentryDSNValidator_Name(t *testing.T) {
	v := NewSentryDSNValidator()
	assert.Equal(t, "sentry-dsn", v.Name())
}

func TestSentryDSNValidator_CanValidate(t *testing.T) {
	v := NewSentryDSNValidator()

	tests := []struct {
		name   string
		ruleID string
		want   bool
	}{
		{"sentry DSN rule", "kingfisher.sentry.4", true},
		{"sentry token rule", "kingfisher.sentry.1", false},
		{"other rule", "np.aws.1", false},
		{"empty rule", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, v.CanValidate(tt.ruleID))
		})
	}
}

func TestSentryDSNValidator_ParseDSN(t *testing.T) {
	v := NewSentryDSNValidator()

	tests := []struct {
		name      string
		dsn       string
		wantKey   string
		wantHost  string
		wantProj  string
		wantErr   bool
	}{
		{
			name:     "standard sentry.io DSN",
			dsn:      "https://0123456789abcdef0123456789abcdef@sentry.io/12345",
			wantKey:  "0123456789abcdef0123456789abcdef",
			wantHost: "sentry.io",
			wantProj: "12345",
		},
		{
			name:     "org-scoped sentry.io DSN",
			dsn:      "https://abcdef0123456789abcdef0123456789@o123456.sentry.io/67890",
			wantKey:  "abcdef0123456789abcdef0123456789",
			wantHost: "o123456.sentry.io",
			wantProj: "67890",
		},
		{
			name:     "self-hosted DSN",
			dsn:      "https://0123456789abcdef0123456789abcdef@sentry.example.com/99999",
			wantKey:  "0123456789abcdef0123456789abcdef",
			wantHost: "sentry.example.com",
			wantProj: "99999",
		},
		{
			name:    "missing key",
			dsn:     "https://sentry.io/12345",
			wantErr: true,
		},
		{
			name:    "wrong scheme",
			dsn:     "http://0123456789abcdef0123456789abcdef@sentry.io/12345",
			wantErr: true,
		},
		{
			name:    "missing project ID",
			dsn:     "https://0123456789abcdef0123456789abcdef@sentry.io/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := &types.Match{
				RuleID: "kingfisher.sentry.4",
				Groups: [][]byte{[]byte(tt.dsn)},
			}

			dsn, err := v.parseDSN(match)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantKey, dsn.key)
			assert.Equal(t, tt.wantHost, dsn.host)
			assert.Equal(t, tt.wantProj, dsn.projectID)
		})
	}
}

func TestSentryDSNValidator_SkipsLocalhost(t *testing.T) {
	v := NewSentryDSNValidator()

	hosts := []string{"localhost", "127.0.0.1", "[::1]"}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			dsn := fmt.Sprintf("https://0123456789abcdef0123456789abcdef@%s/12345", host)
			match := &types.Match{
				RuleID: "kingfisher.sentry.4",
				Groups: [][]byte{[]byte(dsn)},
			}
			result, err := v.Validate(context.Background(), match)
			require.NoError(t, err)
			assert.Equal(t, types.StatusUndetermined, result.Status)
			assert.Contains(t, result.Message, "localhost")
		})
	}
}

func TestSentryDSNValidator_MissingGroups(t *testing.T) {
	v := NewSentryDSNValidator()

	match := &types.Match{
		RuleID: "kingfisher.sentry.4",
		Groups: [][]byte{},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

func TestSentryDSNValidator_UnreachableHost(t *testing.T) {
	v := NewSentryDSNValidator()

	match := &types.Match{
		RuleID: "kingfisher.sentry.4",
		Groups: [][]byte{[]byte("https://0123456789abcdef0123456789abcdef@nonexistent.invalid/12345")},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "request failed")
}
