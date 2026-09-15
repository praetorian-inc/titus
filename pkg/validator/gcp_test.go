package validator

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testRSAPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

func testRSAPrivateKeyPKCS1PEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return string(pem.EncodeToMemory(block))
}

func testServiceAccountJSON(t *testing.T, overrides map[string]string) string {
	t.Helper()
	sa := map[string]string{
		"type":                        "service_account",
		"project_id":                  "test-project",
		"private_key_id":              "key123",
		"client_email":                "test@test-project.iam.gserviceaccount.com",
		"client_id":                   "123456789",
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"private_key":                 testRSAPrivateKeyPEM(t),
	}
	for k, v := range overrides {
		sa[k] = v
	}
	b, err := json.Marshal(sa)
	require.NoError(t, err)
	return string(b)
}

func newTestGCPValidator(srv *httptest.Server) *GCPValidator {
	return &GCPValidator{
		client:   srv.Client(),
		tokenURL: srv.URL + "/token",
	}
}

func TestGCPValidator_Name(t *testing.T) {
	v := NewGCPValidator()
	assert.Equal(t, "gcp", v.Name())
}

func TestGCPValidator_CanValidate(t *testing.T) {
	v := NewGCPValidator()
	assert.True(t, v.CanValidate("kingfisher.gcp.1"))
	assert.True(t, v.CanValidate("kingfisher.gcp.3"))
	assert.False(t, v.CanValidate("kingfisher.looker.1"))
	assert.False(t, v.CanValidate("np.jenkins.1"))
}

func TestGCPValidator_PrivateKeyIDUndetermined(t *testing.T) {
	v := NewGCPValidator()
	match := &types.Match{RuleID: "kingfisher.gcp.3"}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "private key ID alone")
}

func TestGCPValidator_ValidServiceAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/token", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		require.NoError(t, r.ParseForm())
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", r.FormValue("grant_type"))
		assert.NotEmpty(t, r.FormValue("assertion"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "ya29.test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	saJSON := testServiceAccountJSON(t, nil)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(saJSON),
		},
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Contains(t, result.Message, "GCP service account key valid")
	assert.Contains(t, result.Message, "test@test-project.iam.gserviceaccount.com")
}

func TestGCPValidator_InvalidGrant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "Invalid JWT: token has expired",
		})
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	saJSON := testServiceAccountJSON(t, nil)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(saJSON),
		},
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Contains(t, result.Message, "rejected")
}

func TestGCPValidator_InvalidGrantError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "invalid_grant",
		})
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	saJSON := testServiceAccountJSON(t, nil)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(saJSON),
		},
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Contains(t, result.Message, "invalid_grant")
}

func TestGCPValidator_InvalidGrantWithDescription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "Service account key has been deleted.",
		})
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	saJSON := testServiceAccountJSON(t, nil)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(saJSON),
		},
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Contains(t, result.Message, "Service account key has been deleted")
}

func TestGCPValidator_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	saJSON := testServiceAccountJSON(t, nil)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(saJSON),
		},
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Contains(t, result.Message, "rejected")
}

func TestGCPValidator_MissingClientEmail(t *testing.T) {
	v := NewGCPValidator()
	sa := map[string]string{
		"private_key":                 testRSAPrivateKeyPEM(t),
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
	}
	saJSON, _ := json.Marshal(sa)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": saJSON,
		},
		Snippet: types.Snippet{
			Matching: saJSON,
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "no service account found")
}

func TestGCPValidator_MissingPrivateKey(t *testing.T) {
	v := NewGCPValidator()
	sa := map[string]string{
		"client_email":                "test@test.iam.gserviceaccount.com",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
	}
	saJSON, _ := json.Marshal(sa)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": saJSON,
		},
		Snippet: types.Snippet{
			Matching: saJSON,
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "no service account found")
}

func TestGCPValidator_InvalidJSON(t *testing.T) {
	v := NewGCPValidator()
	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(`{"truncated json...`),
		},
		Snippet: types.Snippet{
			Matching: []byte(`{"truncated json...`),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "failed to parse")
}

func TestGCPValidator_BadPrivateKey(t *testing.T) {
	v := NewGCPValidator()
	sa := map[string]string{
		"client_email":                "test@test.iam.gserviceaccount.com",
		"private_key":                 "not-a-pem-key",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
	}
	saJSON, _ := json.Marshal(sa)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": saJSON,
		},
		Snippet: types.Snippet{
			Matching: saJSON,
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "failed to build JWT")
}

func TestGCPValidator_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	saJSON := testServiceAccountJSON(t, nil)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(saJSON),
		},
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "unexpected status")
}

func TestGCPValidator_FallbackToSnippetMatching(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "ya29.test",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	saJSON := testServiceAccountJSON(t, nil)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestGCPValidator_NoJSONFound(t *testing.T) {
	v := NewGCPValidator()
	match := &types.Match{
		RuleID:  "kingfisher.gcp.1",
		Snippet: types.Snippet{},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot extract")
}

func TestGCPValidator_MaliciousTokenURI(t *testing.T) {
	v := NewGCPValidator()
	saJSON := testServiceAccountJSON(t, map[string]string{
		"token_uri": "https://evil.com/token",
	})

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(saJSON),
		},
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "not a recognized Google endpoint")
}

func TestGCPValidator_HTTPTokenURIRejected(t *testing.T) {
	v := NewGCPValidator()
	saJSON := testServiceAccountJSON(t, map[string]string{
		"token_uri": "http://oauth2.googleapis.com/token",
	})

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(saJSON),
		},
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "not a recognized Google endpoint")
}

func TestIsAllowedGCPTokenHost(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://oauth2.googleapis.com/token", true},
		{"https://accounts.google.com/o/oauth2/token", true},
		{"https://www.googleapis.com/oauth2/v4/token", true},
		{"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test:generateAccessToken", true},
		{"http://oauth2.googleapis.com/token", false},
		{"https://evil.com/token", false},
		{"https://googleapis.com.evil.com/token", false},
		{"not-a-url", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.want, isAllowedGCPTokenHost(tt.url))
		})
	}
}

func TestGCPValidator_ResponseMissingAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token_type": "Bearer",
			"expires_in": 3600,
		})
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	saJSON := testServiceAccountJSON(t, nil)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(saJSON),
		},
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "missing access_token")
}

func TestGCPValidator_NullAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":null,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	saJSON := testServiceAccountJSON(t, nil)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(saJSON),
		},
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "empty or non-string")
}

func TestGCPValidator_EmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"","token_type":"Bearer"}`))
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	saJSON := testServiceAccountJSON(t, nil)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(saJSON),
		},
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "empty or non-string")
}

func TestGCPValidator_NestedServiceAccountGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "ya29.test",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	saJSON := testServiceAccountJSON(t, nil)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account_nested": []byte(saJSON),
		},
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestGCPValidator_NestedWrapperJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "ya29.test",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	innerSA := testServiceAccountJSON(t, nil)
	wrapper := `{"admin":{"credential":` + innerSA + `}}`

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account_nested": []byte(wrapper),
		},
		Snippet: types.Snippet{
			Matching: []byte(wrapper),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Contains(t, result.Message, "test@test-project.iam.gserviceaccount.com")
}

func TestGCPValidator_PKCS1PrivateKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "ya29.test",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	saJSON := testServiceAccountJSON(t, map[string]string{
		"private_key": testRSAPrivateKeyPKCS1PEM(t),
	})

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(saJSON),
		},
		Snippet: types.Snippet{
			Matching: []byte(saJSON),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestGCPValidator_SecretNamedGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "ya29.test",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	v := newTestGCPValidator(srv)
	saJSON := testServiceAccountJSON(t, nil)

	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"secret": []byte(saJSON),
		},
		Snippet: types.Snippet{},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}
