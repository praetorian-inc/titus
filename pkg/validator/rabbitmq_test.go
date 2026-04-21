// pkg/validator/rabbitmq_test.go
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

func TestRabbitMQValidator_Name(t *testing.T) {
	v := NewRabbitMQValidator()
	assert.Equal(t, "rabbitmq", v.Name())
}

func TestRabbitMQValidator_CanValidate(t *testing.T) {
	v := NewRabbitMQValidator()
	assert.True(t, v.CanValidate("kingfisher.rabbitmq.1"))
	assert.False(t, v.CanValidate("np.rabbitmq.1"))
	assert.False(t, v.CanValidate("np.postgres.1"))
}

func TestRabbitMQValidator_ExtractCredentials(t *testing.T) {
	v := NewRabbitMQValidator()

	tests := []struct {
		name        string
		namedGroups map[string][]byte
		wantUser    string
		wantPass    string
		wantHost    string
		wantErr     bool
	}{
		{
			name: "all fields",
			namedGroups: map[string][]byte{
				"user":     []byte("admin"),
				"password": []byte("s3cret"),
				"host":     []byte("broker.example.com"),
			},
			wantUser: "admin",
			wantPass: "s3cret",
			wantHost: "broker.example.com",
		},
		{
			name: "missing user",
			namedGroups: map[string][]byte{
				"password": []byte("s3cret"),
				"host":     []byte("broker.example.com"),
			},
			wantErr: true,
		},
		{
			name: "missing password",
			namedGroups: map[string][]byte{
				"user": []byte("admin"),
				"host": []byte("broker.example.com"),
			},
			wantErr: true,
		},
		{
			name: "missing host",
			namedGroups: map[string][]byte{
				"user":     []byte("admin"),
				"password": []byte("s3cret"),
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
			match := &types.Match{NamedGroups: tt.namedGroups}
			user, pass, host, err := v.extractCredentials(match)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantUser, user)
			assert.Equal(t, tt.wantPass, pass)
			assert.Equal(t, tt.wantHost, host)
		})
	}
}

func TestRabbitMQValidator_SkipsLocalhost(t *testing.T) {
	v := NewRabbitMQValidator()

	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			match := &types.Match{
				RuleID: "kingfisher.rabbitmq.1",
				NamedGroups: map[string][]byte{
					"user":     []byte("guest"),
					"password": []byte("guest"),
					"host":     []byte(host),
				},
			}
			result, err := v.Validate(context.Background(), match)
			require.NoError(t, err)
			assert.Equal(t, types.StatusUndetermined, result.Status)
			assert.Contains(t, result.Message, "localhost")
		})
	}
}

func TestRabbitMQValidator_SkipsExampleHosts(t *testing.T) {
	v := NewRabbitMQValidator()

	for _, host := range []string{"example.com", "rabbitmq.example.com", "contoso.com"} {
		t.Run(host, func(t *testing.T) {
			match := &types.Match{
				RuleID: "kingfisher.rabbitmq.1",
				NamedGroups: map[string][]byte{
					"user":     []byte("admin"),
					"password": []byte("s3cret"),
					"host":     []byte(host),
				},
			}
			result, err := v.Validate(context.Background(), match)
			require.NoError(t, err)
			assert.Equal(t, types.StatusUndetermined, result.Status)
			assert.Contains(t, result.Message, "example")
		})
	}
}

func TestRabbitMQValidator_ValidCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/whoami", r.URL.Path)
		assert.Equal(t, "GET", r.Method)

		user, pass, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "admin", user)
		assert.Equal(t, "s3cret", pass)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"admin","tags":"administrator"}`))
	}))
	defer server.Close()

	v := NewRabbitMQValidatorWithClient(&http.Client{
		Transport: &rabbitmqMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "kingfisher.rabbitmq.1",
		NamedGroups: map[string][]byte{
			"user":     []byte("admin"),
			"password": []byte("s3cret"),
			"host":     []byte("broker.internal"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "admin")
	assert.Contains(t, result.Message, "broker.internal")
}

func TestRabbitMQValidator_InvalidCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"not_authorised","reason":"Login failed"}`))
	}))
	defer server.Close()

	v := NewRabbitMQValidatorWithClient(&http.Client{
		Transport: &rabbitmqMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "kingfisher.rabbitmq.1",
		NamedGroups: map[string][]byte{
			"user":     []byte("admin"),
			"password": []byte("wrongpass"),
			"host":     []byte("broker.internal"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "401")
}

func TestRabbitMQValidator_ManagementUnreachable(t *testing.T) {
	v := NewRabbitMQValidator()

	match := &types.Match{
		RuleID: "kingfisher.rabbitmq.1",
		NamedGroups: map[string][]byte{
			"user":     []byte("admin"),
			"password": []byte("s3cret"),
			"host":     []byte("nonexistent.internal"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "management API unreachable")
}

func TestRabbitMQValidator_ManagementURL(t *testing.T) {
	v := NewRabbitMQValidator()

	tests := []struct {
		host string
		want string
	}{
		{"broker.internal", "http://broker.internal:15672"},
		{"bunny.cloudamqp.com", "https://bunny.cloudamqp.com"},
		{"eagle.cloudamqp.com", "https://eagle.cloudamqp.com"},
		{"b-abc123.mq.us-east-1.amazonaws.com", "https://b-abc123.mq.us-east-1.amazonaws.com"},
		{"192.168.1.10", "http://192.168.1.10:15672"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			assert.Equal(t, tt.want, v.managementURL(tt.host))
		})
	}
}

func TestRabbitMQValidator_UsesBasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Must use Basic Auth
		user, pass, ok := r.BasicAuth()
		assert.True(t, ok, "request must use Basic Auth")
		assert.Equal(t, "myuser", user)
		assert.Equal(t, "mypass", pass)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewRabbitMQValidatorWithClient(&http.Client{
		Transport: &rabbitmqMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "kingfisher.rabbitmq.1",
		NamedGroups: map[string][]byte{
			"user":     []byte("myuser"),
			"password": []byte("mypass"),
			"host":     []byte("broker.internal"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

// rabbitmqMockTransport redirects requests to the mock server.
type rabbitmqMockTransport struct {
	server *httptest.Server
}

func (t *rabbitmqMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}
