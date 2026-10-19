package validator

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFreshdeskValidator_Name(t *testing.T) {
	v := NewFreshdeskValidator()
	assert.Equal(t, "freshdesk", v.Name())
}

func TestFreshdeskValidator_CanValidate(t *testing.T) {
	v := NewFreshdeskValidator()

	tests := []struct {
		name   string
		ruleID string
		want   bool
	}{
		{"freshdesk API key rule", "kingfisher.freshdesk.2", true},
		{"freshdesk domain rule", "kingfisher.freshdesk.1", false},
		{"other rule", "np.aws.1", false},
		{"empty rule", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, v.CanValidate(tt.ruleID))
		})
	}
}

func TestFreshdeskValidator_Validate_Valid(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v2/agents/me", r.URL.Path)
		assert.NotEmpty(t, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"id":1234,"contact":{"name":"Test Agent"}}`)
	}))
	defer srv.Close()

	v := NewFreshdeskValidatorWithClient(srv.Client())

	// The validator builds the URL from the domain in the snippet. We override
	// the domain resolution by supplying the test server's host directly.
	match := freshdeskMatch("ABCDEFGHIJ1234567890", srv.URL)
	result, err := v.validateAgainst(context.Background(), match, srv.URL)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestFreshdeskValidator_Validate_Invalid(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	v := NewFreshdeskValidatorWithClient(srv.Client())

	match := freshdeskMatch("INVALIDKEY1234567890", srv.URL)
	result, err := v.validateAgainst(context.Background(), match, srv.URL)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestFreshdeskValidator_Validate_NoDomain(t *testing.T) {
	v := NewFreshdeskValidator()
	match := &types.Match{
		RuleID: "kingfisher.freshdesk.2",
		Groups: [][]byte{nil, []byte("ABCDEFGHIJ1234567890")},
		Snippet: types.Snippet{
			Before:   []byte("FRESHDESK_API_KEY="),
			Matching: []byte("ABCDEFGHIJ1234567890"),
			After:    []byte("\n"),
		},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "domain not found")
}

func TestFreshdeskValidator_Validate_DomainExtraction(t *testing.T) {
	tests := []struct {
		name    string
		snippet types.Snippet
		want    string
	}{
		{
			name: "URL in before context",
			snippet: types.Snippet{
				Before:   []byte("FRESHDESK_URL=https://acme-support.freshdesk.com\nFRESHDESK_API_KEY="),
				Matching: []byte("ABCDEFGHIJ1234567890"),
			},
			want: "acme-support.freshdesk.com",
		},
		{
			name: "bare domain in after context",
			snippet: types.Snippet{
				Matching: []byte("ABCDEFGHIJ1234567890"),
				After:    []byte("\nDOMAIN=mycompany.freshdesk.com"),
			},
			want: "mycompany.freshdesk.com",
		},
		{
			name: "no domain anywhere",
			snippet: types.Snippet{
				Before:   []byte("api_key: "),
				Matching: []byte("ABCDEFGHIJ1234567890"),
				After:    []byte("\n"),
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := searchSnippet(tt.snippet, freshdeskDomainPatterns)
			assert.Equal(t, tt.want, got)
		})
	}
}

func freshdeskMatch(apiKey, serverURL string) *types.Match {
	domain := "acme-support.freshdesk.com"
	return &types.Match{
		RuleID: "kingfisher.freshdesk.2",
		Groups: [][]byte{nil, []byte(apiKey)},
		Snippet: types.Snippet{
			Before:   []byte(fmt.Sprintf("FRESHDESK_URL=https://%s\nFRESHDESK_API_KEY=", domain)),
			Matching: []byte(apiKey),
			After:    []byte("\n"),
		},
	}
}
