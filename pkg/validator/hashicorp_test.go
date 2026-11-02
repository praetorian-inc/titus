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

func TestHashiCorpValidator_Name(t *testing.T) {
	v := NewHashiCorpValidator()
	assert.Equal(t, "hashicorp", v.Name())
}

func TestHashiCorpValidator_CanValidate(t *testing.T) {
	v := NewHashiCorpValidator()

	tests := []struct {
		name   string
		ruleID string
		want   bool
	}{
		{"vault service token old", "np.hashicorp.1", true},
		{"vault batch token old", "np.hashicorp.2", true},
		{"vault recovery token old", "np.hashicorp.3", true},
		{"vault service token new", "np.hashicorp.4", true},
		{"vault batch token new", "np.hashicorp.5", true},
		{"vault recovery token new", "np.hashicorp.6", true},
		{"vault unseal key", "np.hashicorp.7", true},
		{"other rule", "np.aws.1", false},
		{"empty rule", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, v.CanValidate(tt.ruleID))
		})
	}
}

func TestHashiCorpValidator_Validate_Valid(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/auth/token/lookup-self", r.URL.Path)
		assert.Equal(t, "s.Z4bTMtngfLeQ18AqVoBBkUAOD1", r.Header.Get("X-Vault-Token"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"id":"s.Z4bTMtngfLeQ18AqVoBBkUAOD1"}}`))
	}))
	defer srv.Close()

	v := NewHashiCorpValidatorWithClient(srv.Client())
	token := "s.Z4bTMtngfLeQ18AqVoBBkUAOD1"

	result, err := v.validateAgainst(context.Background(), token, srv.URL)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestHashiCorpValidator_Validate_Invalid(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":["missing client token"]}`))
	}))
	defer srv.Close()

	v := NewHashiCorpValidatorWithClient(srv.Client())

	result, err := v.validateAgainst(context.Background(), "s.invalidtoken", srv.URL)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestHashiCorpValidator_Validate_Forbidden_IsUndetermined(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	defer srv.Close()

	v := NewHashiCorpValidatorWithClient(srv.Client())

	result, err := v.validateAgainst(context.Background(), "hvs.JGbZZaCkOSgsZ56uhGlTK2zyC1j2mwhy0VLp4", srv.URL)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "403")
}

func TestHashiCorpValidator_Validate_UnsealKey(t *testing.T) {
	v := NewHashiCorpValidator()
	match := &types.Match{
		RuleID: "np.hashicorp.7",
		Groups: [][]byte{[]byte("98m+o2ylRhVbOi+3o5ub6PbP343ocFUVORgSYeypMDjh")},
		Snippet: types.Snippet{
			Before:   []byte("Unseal Key 2: "),
			Matching: []byte("98m+o2ylRhVbOi+3o5ub6PbP343ocFUVORgSYeypMDjh"),
			After:    []byte("\n"),
		},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "unseal keys")
}

func TestHashiCorpValidator_Validate_NoVaultURL(t *testing.T) {
	v := NewHashiCorpValidator()
	match := &types.Match{
		RuleID: "np.hashicorp.4",
		Groups: [][]byte{[]byte("hvs.JGbZZaCkOSgsZ56uhGlTK2zyC1j2mwhy0VLp4")},
		Snippet: types.Snippet{
			Before:   []byte("some random context\n"),
			Matching: []byte("hvs.JGbZZaCkOSgsZ56uhGlTK2zyC1j2mwhy0VLp4"),
			After:    []byte("\nmore context"),
		},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "vault server URL not found")
}

func TestHashiCorpValidator_Validate_Localhost(t *testing.T) {
	v := NewHashiCorpValidator()
	match := &types.Match{
		RuleID: "np.hashicorp.4",
		Groups: [][]byte{[]byte("hvs.JGbZZaCkOSgsZ56uhGlTK2zyC1j2mwhy0VLp4")},
		Snippet: types.Snippet{
			Before:   []byte("VAULT_ADDR=http://localhost:8200\n"),
			Matching: []byte("hvs.JGbZZaCkOSgsZ56uhGlTK2zyC1j2mwhy0VLp4"),
			After:    []byte(""),
		},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "localhost")
}

func TestHashiCorpValidator_Validate_ConnectionError(t *testing.T) {
	v := NewHashiCorpValidator()
	match := &types.Match{
		RuleID: "np.hashicorp.1",
		Groups: [][]byte{[]byte("s.Z4bTMtngfLeQ18AqVoBBkUAOD1")},
		Snippet: types.Snippet{
			Before:   []byte("VAULT_ADDR=https://nonexistent.invalid\n"),
			Matching: []byte("s.Z4bTMtngfLeQ18AqVoBBkUAOD1"),
			After:    []byte(""),
		},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "request failed")
}

func TestHashiCorpValidator_VaultURLExtraction(t *testing.T) {
	tests := []struct {
		name    string
		snippet types.Snippet
		want    string
	}{
		{
			name: "VAULT_ADDR export",
			snippet: types.Snippet{
				Before:   []byte("export VAULT_ADDR=https://vault.example.com:8200\n"),
				Matching: []byte("hvs.somefaketoken12345678"),
			},
			want: "https://vault.example.com:8200",
		},
		{
			name: "VAULT_ADDR with quotes",
			snippet: types.Snippet{
				Before:   []byte("VAULT_ADDR='https://vault.corp.net'\n"),
				Matching: []byte("hvs.somefaketoken12345678"),
			},
			want: "https://vault.corp.net",
		},
		{
			name: "vault_url lowercase",
			snippet: types.Snippet{
				Before:   []byte("vault_url: https://vault.internal.io\n"),
				Matching: []byte("hvs.somefaketoken12345678"),
			},
			want: "https://vault.internal.io",
		},
		{
			name: "fallback URL with vault in hostname",
			snippet: types.Snippet{
				Before:   []byte("curl https://vault.prod.company.com/v1/secret/data/app\n"),
				Matching: []byte("s.sometoken1234567890abcd"),
			},
			want: "https://vault.prod.company.com",
		},
		{
			name: "VAULT_ADDR in after context",
			snippet: types.Snippet{
				Matching: []byte("hvs.somefaketoken12345678"),
				After:    []byte("\nVAULT_ADDR=https://vault.example.com"),
			},
			want: "https://vault.example.com",
		},
		{
			name: "no vault URL",
			snippet: types.Snippet{
				Before:   []byte("some random context\n"),
				Matching: []byte("hvs.somefaketoken12345678"),
				After:    []byte("\nmore context"),
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractVaultURL(tt.snippet)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHashiCorpValidator_Validate_RecoveryToken(t *testing.T) {
	v := NewHashiCorpValidator()
	for _, ruleID := range []string{"np.hashicorp.3", "np.hashicorp.6"} {
		t.Run(ruleID, func(t *testing.T) {
			match := &types.Match{
				RuleID: ruleID,
				Groups: [][]byte{[]byte("hvr.somerecoverytoken12345678")},
				Snippet: types.Snippet{
					Before:   []byte("VAULT_ADDR=https://vault.example.com\n"),
					Matching: []byte("hvr.somerecoverytoken12345678"),
					After:    []byte(""),
				},
			}
			result, err := v.Validate(context.Background(), match)
			require.NoError(t, err)
			assert.Equal(t, types.StatusUndetermined, result.Status)
			assert.Contains(t, result.Message, "recovery tokens")
		})
	}
}

func TestHashiCorpValidator_Validate_IPv6Localhost(t *testing.T) {
	v := NewHashiCorpValidator()
	match := &types.Match{
		RuleID: "np.hashicorp.4",
		Groups: [][]byte{[]byte("hvs.JGbZZaCkOSgsZ56uhGlTK2zyC1j2mwhy0VLp4")},
		Snippet: types.Snippet{
			Before:   []byte("VAULT_ADDR=http://[::1]:8200\n"),
			Matching: []byte("hvs.JGbZZaCkOSgsZ56uhGlTK2zyC1j2mwhy0VLp4"),
			After:    []byte(""),
		},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "localhost")
}

func TestHashiCorpValidator_Validate_NewFormatToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/auth/token/lookup-self", r.URL.Path)
		assert.NotEmpty(t, r.Header.Get("X-Vault-Token"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	v := NewHashiCorpValidatorWithClient(srv.Client())
	token := "hvs.JGbZZaCkOSgsZ56uhGlTK2zyC1j2mwhy0VLp4"

	result, err := v.validateAgainst(context.Background(), token, srv.URL)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}
