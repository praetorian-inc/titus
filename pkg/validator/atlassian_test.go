// pkg/validator/atlassian_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestAtlassianValidator_Name(t *testing.T) {
	v := NewAtlassianValidator()
	assert.Equal(t, "atlassian", v.Name())
}

func TestAtlassianValidator_CanValidate(t *testing.T) {
	v := NewAtlassianValidator()

	// Atlassian rule
	assert.True(t, v.CanValidate("np.atlassian.1"))

	// Non-Atlassian rules
	assert.False(t, v.CanValidate("np.github.1"))
	assert.False(t, v.CanValidate("np.aws.1"))
	assert.False(t, v.CanValidate("np.zendesk.1"))
}

func TestAtlassianValidator_ExtractCredentials_TokenFromNamedGroups(t *testing.T) {
	v := NewAtlassianValidator()

	match := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEtokenFORunit_testing=00000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("email = 'info@example.com'\n"),
			Matching: []byte("api_token = 'ATATT3xFfGF0testEXAMPLEtokenFORunit_testing=00000000'"),
			After:    []byte("# https://mycompany.atlassian.net/rest/api/3/myself\n"),
		},
	}

	domain, email, token, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "ATATT3xFfGF0testEXAMPLEtokenFORunit_testing=00000000", token)
	assert.Equal(t, "info@example.com", email)
	assert.Equal(t, "mycompany.atlassian.net", domain)
}

func TestAtlassianValidator_ExtractCredentials_EmailFromJIRA_USER(t *testing.T) {
	v := NewAtlassianValidator()

	match := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEjiraUserToken_ForTests=00000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("JIRA_USER=\"example@example.com\"\n"),
			Matching: []byte("JIRA_API_TOKEN=\"ATATT3xFfGF0testEXAMPLEjiraUserToken_ForTests=00000000\""),
			After:    []byte("JIRA_HOST=https://myorg.atlassian.net\n"),
		},
	}

	domain, email, token, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "ATATT3xFfGF0testEXAMPLEjiraUserToken_ForTests=00000000", token)
	assert.Equal(t, "example@example.com", email)
	assert.Equal(t, "myorg.atlassian.net", domain)
}

func TestAtlassianValidator_ExtractCredentials_EmailFromEnvFunction(t *testing.T) {
	v := NewAtlassianValidator()

	// Example from the rule file: env('JIRA_USER', 'admin@example.com')
	match := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEenvFuncToken_Test=00000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("'user' => env('JIRA_USER', 'admin@example.com'),\n"),
			Matching: []byte("'token' => env('JIRA_API_TOKEN', 'ATATT3xFfGF0testEXAMPLEenvFuncToken_Test=00000000'),"),
			After:    []byte("'host' => env('JIRA_HOST', 'https://example.atlassian.net'),\n"),
		},
	}

	domain, email, token, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "ATATT3xFfGF0testEXAMPLEenvFuncToken_Test=00000000", token)
	assert.Equal(t, "admin@example.com", email)
	assert.Equal(t, "example.atlassian.net", domain)
}

func TestAtlassianValidator_ExtractCredentials_DomainFromHTTPSURL(t *testing.T) {
	v := NewAtlassianValidator()

	match := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEhttpsDomain_Testing=00000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("url = 'https://myteam.atlassian.net'\nuser = 'ops@myteam.com'\n"),
			Matching: []byte("token = 'ATATT3xFfGF0testEXAMPLEhttpsDomain_Testing=00000000'"),
			After:    []byte(""),
		},
	}

	domain, email, token, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "myteam.atlassian.net", domain)
	assert.Equal(t, "ops@myteam.com", email)
	assert.Equal(t, "ATATT3xFfGF0testEXAMPLEhttpsDomain_Testing=00000000", token)
}

func TestAtlassianValidator_ExtractCredentials_MissingToken(t *testing.T) {
	v := NewAtlassianValidator()

	match := &types.Match{
		RuleID:      "np.atlassian.1",
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before: []byte("email = 'info@example.com'\n"),
		},
	}

	_, _, _, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestAtlassianValidator_ExtractCredentials_NoNamedGroups(t *testing.T) {
	v := NewAtlassianValidator()

	match := &types.Match{
		RuleID:      "np.atlassian.1",
		NamedGroups: nil,
	}

	_, _, _, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no named capture groups")
}

func TestAtlassianValidator_ExtractCredentials_MissingEmail(t *testing.T) {
	v := NewAtlassianValidator()

	match := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEshort=00000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("# no email here\n"),
			Matching: []byte("api_token = 'ATATT3xFfGF0testEXAMPLEshort=00000000'"),
			After:    []byte("JIRA_HOST=https://mycompany.atlassian.net\n"),
		},
	}

	_, _, _, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email")
}

func TestAtlassianValidator_ExtractCredentials_MissingDomain(t *testing.T) {
	v := NewAtlassianValidator()

	match := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEshort=00000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("email = 'info@example.com'\n"),
			Matching: []byte("api_token = 'ATATT3xFfGF0testEXAMPLEshort=00000000'"),
			After:    []byte("# no atlassian domain here\n"),
		},
	}

	_, _, _, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "domain")
}

func TestAtlassianValidator_Validate_Valid(t *testing.T) {
	// Mock server that returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Basic auth header is present
		auth := r.Header.Get("Authorization")
		assert.Contains(t, auth, "Basic ")
		// Verify path
		assert.Equal(t, "/rest/api/3/myself", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewAtlassianValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEtokenFORunit_testing=00000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("email = 'info@example.com'\n"),
			Matching: []byte("api_token = 'ATATT3xFfGF0testEXAMPLEtokenFORunit_testing=00000000'"),
			After:    []byte("# https://mycompany.atlassian.net/rest/api/3/myself\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "mycompany.atlassian.net")
}

func TestAtlassianValidator_Validate_Invalid_Unauthorized(t *testing.T) {
	// Mock server that returns 401
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewAtlassianValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testINVALIDexample=00000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("email = 'info@example.com'\n"),
			Matching: []byte("api_token = 'ATATT3xFfGF0testINVALIDexample=00000000'"),
			After:    []byte("JIRA_HOST=https://mycompany.atlassian.net\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "401")
}

func TestAtlassianValidator_Validate_Invalid_Forbidden(t *testing.T) {
	// Mock server that returns 403
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := NewAtlassianValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEshort=00000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("email = 'info@example.com'\n"),
			Matching: []byte("api_token = 'ATATT3xFfGF0testEXAMPLEshort=00000000'"),
			After:    []byte("JIRA_HOST=https://mycompany.atlassian.net\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "403")
}

func TestAtlassianValidator_Validate_Undetermined_ServerError(t *testing.T) {
	// Mock server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewAtlassianValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEshort=00000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("email = 'info@example.com'\n"),
			Matching: []byte("api_token = 'ATATT3xFfGF0testEXAMPLEshort=00000000'"),
			After:    []byte("JIRA_HOST=https://mycompany.atlassian.net\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Equal(t, 0.5, result.Confidence)
	assert.Contains(t, result.Message, "500")
}

func TestAtlassianValidator_Validate_PartialCredentials(t *testing.T) {
	v := NewAtlassianValidator()

	// Missing domain in context
	match := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEshort=00000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("email = 'info@example.com'\n"),
			Matching: []byte("api_token = 'ATATT3xFfGF0testEXAMPLEshort=00000000'"),
			After:    []byte("# no atlassian domain in context\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

func TestAtlassianValidator_Validate_BasicAuthFormat(t *testing.T) {
	// Verify that Basic auth uses email:token format
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		assert.True(t, ok, "Basic auth should be present")
		assert.Equal(t, "info@example.com", username)
		assert.Equal(t, "ATATT3xFfGF0testEXAMPLEbasicAuthCheck=00000000", password)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewAtlassianValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEbasicAuthCheck=00000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("email = 'info@example.com'\n"),
			Matching: []byte("api_token = 'ATATT3xFfGF0testEXAMPLEbasicAuthCheck=00000000'"),
			After:    []byte("# https://mycompany.atlassian.net/rest/api/3/myself\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}
