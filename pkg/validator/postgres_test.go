// pkg/validator/postgres_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgresValidator_Name(t *testing.T) {
	v := NewPostgresValidator()
	assert.Equal(t, "postgres", v.Name())
}

func TestPostgresValidator_CanValidate(t *testing.T) {
	v := NewPostgresValidator()

	tests := []struct {
		name   string
		ruleID string
		want   bool
	}{
		{"valid postgres rule", "np.postgres.1", true},
		{"invalid rule", "np.mysql.1", false},
		{"empty rule", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.CanValidate(tt.ruleID)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPostgresValidator_ExtractCredentials(t *testing.T) {
	v := NewPostgresValidator()

	tests := []struct {
		name        string
		namedGroups map[string][]byte
		wantUser    string
		wantPass    string
		wantHost    string
		wantPort    string
		wantErr     bool
	}{
		{
			name: "all fields with port",
			namedGroups: map[string][]byte{
				"username": []byte("testuser"),
				"password": []byte("testpass"),
				"host":     []byte("localhost"),
				"port":     []byte("5432"),
			},
			wantUser: "testuser",
			wantPass: "testpass",
			wantHost: "localhost",
			wantPort: "5432",
			wantErr:  false,
		},
		{
			name: "without port defaults to 5432",
			namedGroups: map[string][]byte{
				"username": []byte("user"),
				"password": []byte("pass"),
				"host":     []byte("db.example.com"),
			},
			wantUser: "user",
			wantPass: "pass",
			wantHost: "db.example.com",
			wantPort: "5432",
			wantErr:  false,
		},
		{
			name:        "missing username",
			namedGroups: map[string][]byte{
				"password": []byte("pass"),
				"host":     []byte("localhost"),
			},
			wantErr: true,
		},
		{
			name:        "missing password",
			namedGroups: map[string][]byte{
				"username": []byte("user"),
				"host":     []byte("localhost"),
			},
			wantErr: true,
		},
		{
			name:        "missing host",
			namedGroups: map[string][]byte{
				"username": []byte("user"),
				"password": []byte("pass"),
			},
			wantErr: true,
		},
		{
			name:        "nil named groups",
			namedGroups: nil,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := &types.Match{
				NamedGroups: tt.namedGroups,
			}

			user, pass, host, port, err := v.extractCredentials(match)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantUser, user)
			assert.Equal(t, tt.wantPass, pass)
			assert.Equal(t, tt.wantHost, host)
			assert.Equal(t, tt.wantPort, port)
		})
	}
}

func TestPostgresValidator_SkipsLocalhost(t *testing.T) {
	v := NewPostgresValidator()

	localhostTests := []struct {
		name string
		host string
	}{
		{"localhost", "localhost"},
		{"127.0.0.1", "127.0.0.1"},
		{"::1", "::1"},
	}

	for _, tt := range localhostTests {
		t.Run(tt.name, func(t *testing.T) {
			match := &types.Match{
				RuleID: "np.postgres.1",
				NamedGroups: map[string][]byte{
					"username": []byte("user"),
					"password": []byte("pass"),
					"host":     []byte(tt.host),
					"port":     []byte("5432"),
				},
			}

			result, err := v.Validate(context.Background(), match)
			require.NoError(t, err)
			assert.Equal(t, types.StatusUndetermined, result.Status)
			assert.Contains(t, result.Message, "localhost")
		})
	}
}

func TestPostgresValidator_MissingCredentials(t *testing.T) {
	v := NewPostgresValidator()

	match := &types.Match{
		RuleID: "np.postgres.1",
		NamedGroups: map[string][]byte{
			"username": []byte("user"),
			// missing password
			"host": []byte("example.com"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

func TestPostgresValidator_ValidCredentials(t *testing.T) {
	// Mock PostgreSQL server that accepts any auth
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is a simplified mock - real test would use actual PostgreSQL mock
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	// Note: This is a placeholder - real validation requires actual PostgreSQL connection
	// For now, we'll skip this test and implement it when we have a proper mock
	t.Skip("Requires PostgreSQL connection mock - implement with actual pgx test")
}

func TestPostgresValidator_InvalidCredentials(t *testing.T) {
	// This test would require a mock PostgreSQL server
	// Skipping for now - will implement with proper pgx mocking
	t.Skip("Requires PostgreSQL connection mock - implement with actual pgx test")
}

func TestPostgresValidator_ConnectionError(t *testing.T) {
	v := NewPostgresValidator()

	match := &types.Match{
		RuleID: "np.postgres.1",
		NamedGroups: map[string][]byte{
			"username": []byte("user"),
			"password": []byte("pass"),
			"host":     []byte("nonexistent.example.com"),
			"port":     []byte("5432"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	// Connection errors should return undetermined, not invalid
	assert.Equal(t, types.StatusUndetermined, result.Status)
}
