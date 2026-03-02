// pkg/validator/zendesk_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestZendeskValidator_Name(t *testing.T) {
	v := NewZendeskValidator()
	assert.Equal(t, "zendesk", v.Name())
}

func TestZendeskValidator_CanValidate(t *testing.T) {
	v := NewZendeskValidator()

	// Zendesk rule
	assert.True(t, v.CanValidate("np.zendesk.1"))

	// Non-Zendesk rules
	assert.False(t, v.CanValidate("np.github.1"))
	assert.False(t, v.CanValidate("np.aws.1"))
	assert.False(t, v.CanValidate("np.slack.1"))
}

func TestZendeskValidator_ExtractCredentials_Complete(t *testing.T) {
	v := NewZendeskValidator()

	// Match with token in named groups, subdomain and email in snippet
	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
		},
		Snippet: types.Snippet{
			Before:   []byte("ZENDESK_SUBDOMAIN=mycompany\nZENDESK_EMAIL=admin@mycompany.com"),
			Matching: []byte("ZENDESK_API_TOKEN=a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
			After:    []byte(""),
		},
	}

	subdomain, email, token, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "mycompany", subdomain)
	assert.Equal(t, "admin@mycompany.com", email)
	assert.Equal(t, "a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI", token)
}

func TestZendeskValidator_ExtractCredentials_SubdomainInAfter(t *testing.T) {
	v := NewZendeskValidator()

	// Match with subdomain in after context and email in before
	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
		},
		Snippet: types.Snippet{
			Before:   []byte("ZENDESK_EMAIL=admin@aftercompany.com"),
			Matching: []byte("ZENDESK_API_TOKEN=a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
			After:    []byte("ZENDESK_SUBDOMAIN=aftercompany"),
		},
	}

	subdomain, email, token, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "aftercompany", subdomain)
	assert.Equal(t, "admin@aftercompany.com", email)
	assert.Equal(t, "a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI", token)
}

func TestZendeskValidator_ExtractCredentials_SubdomainFromURL(t *testing.T) {
	v := NewZendeskValidator()

	// Match with subdomain extracted from URL pattern and email in after
	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
		},
		Snippet: types.Snippet{
			Before:   []byte("# API endpoint: https://mycompany.zendesk.com/api/v2"),
			Matching: []byte("ZENDESK_API_TOKEN=a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
			After:    []byte("ZENDESK_EMAIL=admin@mycompany.com"),
		},
	}

	subdomain, email, token, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "mycompany", subdomain)
	assert.Equal(t, "admin@mycompany.com", email)
	assert.Equal(t, "a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI", token)
}

func TestZendeskValidator_ExtractCredentials_MissingToken(t *testing.T) {
	v := NewZendeskValidator()

	// Missing token named group
	match := &types.Match{
		RuleID:      "np.zendesk.1",
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before: []byte("ZENDESK_SUBDOMAIN=mycompany"),
		},
	}

	subdomain, email, token, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token")
	assert.Empty(t, subdomain)
	assert.Empty(t, email)
	assert.Empty(t, token)
}

func TestZendeskValidator_ExtractCredentials_MissingSubdomain(t *testing.T) {
	v := NewZendeskValidator()

	// Has token but no subdomain in context
	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
		},
		Snippet: types.Snippet{
			Before:   []byte("some other content"),
			Matching: []byte("ZENDESK_API_TOKEN=a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
			After:    []byte("more content"),
		},
	}

	subdomain, email, token, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial")
	assert.Contains(t, err.Error(), "subdomain")
	assert.Empty(t, subdomain)
	assert.Empty(t, email)
	assert.Empty(t, token)
}

func TestZendeskValidator_ExtractCredentials_NoNamedGroups(t *testing.T) {
	v := NewZendeskValidator()

	// No named groups at all
	match := &types.Match{
		RuleID:      "np.zendesk.1",
		NamedGroups: nil,
	}

	subdomain, email, token, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no named capture groups")
	assert.Empty(t, subdomain)
	assert.Empty(t, email)
	assert.Empty(t, token)
}

func TestZendeskValidator_ExtractCredentials_MissingEmail(t *testing.T) {
	v := NewZendeskValidator()

	// Has token and subdomain but no email in context
	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
		},
		Snippet: types.Snippet{
			Before:   []byte("ZENDESK_SUBDOMAIN=mycompany"),
			Matching: []byte("ZENDESK_API_TOKEN=a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
			After:    []byte("no email address here"),
		},
	}

	subdomain, email, token, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email")
	assert.Empty(t, subdomain)
	assert.Empty(t, email)
	assert.Empty(t, token)
}

func TestZendeskValidator_ExtractCredentials_EmailFromCurl(t *testing.T) {
	v := NewZendeskValidator()

	// Email extracted from curl -u user@company.com/token: pattern
	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
		},
		Snippet: types.Snippet{
			Before:   []byte("ZENDESK_SUBDOMAIN=mycompany\ncurl -u user@company.com/token:a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
			Matching: []byte("ZENDESK_API_TOKEN=a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
			After:    []byte(""),
		},
	}

	subdomain, email, token, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "mycompany", subdomain)
	assert.Equal(t, "user@company.com", email)
	assert.Equal(t, "a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI", token)
}

func TestZendeskValidator_Validate_Valid(t *testing.T) {
	// Create mock server that returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Basic auth header is present (not Bearer)
		auth := r.Header.Get("Authorization")
		assert.Contains(t, auth, "Basic ")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create validator with custom client that redirects to test server
	v := NewZendeskValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
		},
		Snippet: types.Snippet{
			Before: []byte("ZENDESK_SUBDOMAIN=mycompany\nZENDESK_EMAIL=admin@mycompany.com"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "mycompany")
}

func TestZendeskValidator_Validate_Invalid_Unauthorized(t *testing.T) {
	// Create mock server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Basic auth header is present (not Bearer)
		auth := r.Header.Get("Authorization")
		assert.Contains(t, auth, "Basic ")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewZendeskValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("invalid0key12345678901234567890ab"),
		},
		Snippet: types.Snippet{
			Before: []byte("ZENDESK_SUBDOMAIN=mycompany\nZENDESK_EMAIL=admin@mycompany.com"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "401")
}

func TestZendeskValidator_Validate_Invalid_Forbidden(t *testing.T) {
	// Create mock server that returns 403 Forbidden
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := NewZendeskValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
		},
		Snippet: types.Snippet{
			Before: []byte("ZENDESK_SUBDOMAIN=mycompany\nZENDESK_EMAIL=admin@mycompany.com"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "403")
}

func TestZendeskValidator_Validate_Undetermined_ServerError(t *testing.T) {
	// Create mock server that returns 500 Internal Server Error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewZendeskValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
		},
		Snippet: types.Snippet{
			Before: []byte("ZENDESK_SUBDOMAIN=mycompany\nZENDESK_EMAIL=admin@mycompany.com"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Equal(t, 0.5, result.Confidence)
	assert.Contains(t, result.Message, "500")
}

func TestZendeskValidator_Validate_PartialCredentials(t *testing.T) {
	v := NewZendeskValidator()

	// Missing subdomain in context
	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
		},
		Snippet: types.Snippet{
			Before:   []byte("no subdomain here"),
			Matching: []byte("ZENDESK_API_TOKEN=a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
			After:    []byte("or here"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

func TestZendeskValidator_ExtractCredentials_EmailFromGenericKey(t *testing.T) {
	v := NewZendeskValidator()

	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
		},
		Snippet: types.Snippet{
			Before:   []byte("ZENDESK_SUBDOMAIN=mycompany\nemail=support@mycompany.com"),
			Matching: []byte("ZENDESK_API_TOKEN=a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
			After:    []byte(""),
		},
	}

	subdomain, email, token, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "mycompany", subdomain)
	assert.Equal(t, "support@mycompany.com", email)
	assert.Equal(t, "a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI", token)
}

func TestZendeskValidator_ExtractCredentials_EmailInAfter(t *testing.T) {
	v := NewZendeskValidator()

	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
		},
		Snippet: types.Snippet{
			Before:   []byte("ZENDESK_SUBDOMAIN=mycompany"),
			Matching: []byte("ZENDESK_API_TOKEN=a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
			After:    []byte("ZENDESK_EMAIL=ops@mycompany.com"),
		},
	}

	subdomain, email, token, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "mycompany", subdomain)
	assert.Equal(t, "ops@mycompany.com", email)
	assert.Equal(t, "a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI", token)
}

func TestZendeskValidator_Validate_BasicAuthFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Basic Auth credentials format
		username, password, ok := r.BasicAuth()
		assert.True(t, ok, "Basic auth should be present")
		assert.Equal(t, "admin@mycompany.com/token", username)
		assert.Equal(t, "a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI", password)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewZendeskValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "np.zendesk.1",
		NamedGroups: map[string][]byte{
			"token": []byte("a3B8f29E4d1C6a0578e23D9f41b6C8e2qR7tY4uI"),
		},
		Snippet: types.Snippet{
			Before: []byte("ZENDESK_SUBDOMAIN=mycompany\nZENDESK_EMAIL=admin@mycompany.com"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}
