// pkg/validator/mattermost_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestMattermostValidator_Name(t *testing.T) {
	v := NewMattermostValidator()
	assert.Equal(t, "mattermost", v.Name())
}

func TestMattermostValidator_CanValidate(t *testing.T) {
	v := NewMattermostValidator()
	assert.True(t, v.CanValidate("kingfisher.mattermost.2"))
	assert.True(t, v.CanValidate("kingfisher.mattermost.3"))
	assert.True(t, v.CanValidate("np.mattermost.1"))
	assert.False(t, v.CanValidate("kingfisher.mattermost.1"))
	assert.False(t, v.CanValidate("np.slack.1"))
}

// --- Webhook validation tests ---

func TestMattermostValidator_Webhook_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusBadRequest) // 400 = webhook exists but empty text
	}))
	defer server.Close()

	v := NewMattermostValidatorWithClient(&http.Client{
		Transport: &mattermostMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "kingfisher.mattermost.3",
		NamedGroups: map[string][]byte{
			"webhook": []byte("https://mattermost.example.com/hooks/9xuqwrwgstrb3mzrxb83nb357a"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestMattermostValidator_Webhook_OK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewMattermostValidatorWithClient(&http.Client{
		Transport: &mattermostMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "kingfisher.mattermost.3",
		NamedGroups: map[string][]byte{
			"webhook": []byte("https://mattermost.example.com/hooks/9xuqwrwgstrb3mzrxb83nb357a"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestMattermostValidator_Webhook_Invalid_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	v := NewMattermostValidatorWithClient(&http.Client{
		Transport: &mattermostMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "kingfisher.mattermost.3",
		NamedGroups: map[string][]byte{
			"webhook": []byte("https://mattermost.example.com/hooks/invalidhookid0000000000000"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestMattermostValidator_Webhook_Invalid_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := NewMattermostValidatorWithClient(&http.Client{
		Transport: &mattermostMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "kingfisher.mattermost.3",
		NamedGroups: map[string][]byte{
			"webhook": []byte("https://mattermost.example.com/hooks/9xuqwrwgstrb3mzrxb83nb357a"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestMattermostValidator_Webhook_UnexpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewMattermostValidatorWithClient(&http.Client{
		Transport: &mattermostMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "kingfisher.mattermost.3",
		NamedGroups: map[string][]byte{
			"webhook": []byte("https://mattermost.example.com/hooks/9xuqwrwgstrb3mzrxb83nb357a"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
}

func TestMattermostValidator_Webhook_NoNamedGroups(t *testing.T) {
	v := NewMattermostValidator()

	match := &types.Match{
		RuleID:      "kingfisher.mattermost.3",
		NamedGroups: nil,
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "named capture groups")
}

func TestMattermostValidator_Webhook_MissingWebhookGroup(t *testing.T) {
	v := NewMattermostValidator()

	match := &types.Match{
		RuleID:      "kingfisher.mattermost.3",
		NamedGroups: map[string][]byte{},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "webhook")
}

// --- Access token validation tests ---

func TestMattermostValidator_AccessToken_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "/api/v4/users/me")
		assert.Equal(t, "Bearer testtoken12345678901234", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"abc123","username":"testuser"}`))
	}))
	defer server.Close()

	v := NewMattermostValidatorWithClient(&http.Client{
		Transport: &mattermostMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "kingfisher.mattermost.2",
		NamedGroups: map[string][]byte{
			"token": []byte("testtoken12345678901234"),
		},
		Snippet: types.Snippet{
			Before:   []byte("mattermost_url = 'https://mattermost.example.com'"),
			Matching: []byte("MATTERMOST_TOKEN=testtoken12345678901234"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Contains(t, result.Message, "mattermost.example.com")
}

func TestMattermostValidator_AccessToken_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewMattermostValidatorWithClient(&http.Client{
		Transport: &mattermostMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "kingfisher.mattermost.2",
		NamedGroups: map[string][]byte{
			"token": []byte("invalidtoken1234567890ab"),
		},
		Snippet: types.Snippet{
			Before:   []byte("mm_url=https://mm.company.com:8065"),
			Matching: []byte("MATTERMOST_TOKEN=invalidtoken1234567890ab"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestMattermostValidator_AccessToken_NoURL(t *testing.T) {
	v := NewMattermostValidator()

	match := &types.Match{
		RuleID: "kingfisher.mattermost.2",
		NamedGroups: map[string][]byte{
			"token": []byte("testtoken12345678901234"),
		},
		Snippet: types.Snippet{
			Before:   []byte("# no URL here"),
			Matching: []byte("MATTERMOST_TOKEN=testtoken12345678901234"),
			After:    []byte("# nothing here either"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "URL not in context")
}

func TestMattermostValidator_AccessToken_NoToken(t *testing.T) {
	v := NewMattermostValidator()

	match := &types.Match{
		RuleID:      "kingfisher.mattermost.2",
		NamedGroups: map[string][]byte{},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "token")
}

func TestMattermostValidator_AccessToken_NoNamedGroups(t *testing.T) {
	v := NewMattermostValidator()

	match := &types.Match{
		RuleID:      "np.mattermost.1",
		NamedGroups: nil,
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
}

// --- URL extraction tests ---

func TestMattermostValidator_ExtractURL_FromBefore(t *testing.T) {
	v := NewMattermostValidator()

	match := &types.Match{
		Snippet: types.Snippet{
			Before:   []byte("url = https://mattermost.example.com"),
			Matching: []byte("token=abc123"),
			After:    []byte(""),
		},
	}

	url := v.extractURL(match)
	assert.Equal(t, "https://mattermost.example.com", url)
}

func TestMattermostValidator_ExtractURL_FromAfter(t *testing.T) {
	v := NewMattermostValidator()

	match := &types.Match{
		Snippet: types.Snippet{
			Before:   []byte("# token config"),
			Matching: []byte("token=abc123"),
			After:    []byte("mm_url=https://mm.company.com:8065"),
		},
	}

	url := v.extractURL(match)
	assert.Equal(t, "https://mm.company.com:8065", url)
}

func TestMattermostValidator_ExtractURL_FromMatching(t *testing.T) {
	v := NewMattermostValidator()

	match := &types.Match{
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("https://mm.localhost:8082 token=abc123"),
			After:    []byte(""),
		},
	}

	url := v.extractURL(match)
	assert.Equal(t, "https://mm.localhost:8082", url)
}

func TestMattermostValidator_ExtractURL_WithPort(t *testing.T) {
	v := NewMattermostValidator()

	match := &types.Match{
		Snippet: types.Snippet{
			Before:   []byte("MATTERMOST_URL=http://mattermost:8065"),
			Matching: []byte("token=abc123"),
			After:    []byte(""),
		},
	}

	url := v.extractURL(match)
	assert.Equal(t, "http://mattermost:8065", url)
}

func TestMattermostValidator_ExtractURL_NotFound(t *testing.T) {
	v := NewMattermostValidator()

	match := &types.Match{
		Snippet: types.Snippet{
			Before:   []byte("# no url"),
			Matching: []byte("token=abc123"),
			After:    []byte("# nothing"),
		},
	}

	url := v.extractURL(match)
	assert.Empty(t, url)
}

func TestMattermostValidator_ExtractURL_FromWebhookContext(t *testing.T) {
	v := NewMattermostValidator()

	match := &types.Match{
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("https://mm.example.com/hooks/abc12345678901234567890 token=xyz"),
			After:    []byte(""),
		},
	}

	// Regex captures the hostname portion (base URL), which is valid for API calls
	url := v.extractURL(match)
	assert.Equal(t, "https://mm.example.com", url)
}

func TestMattermostValidator_AccessToken_URLWithTrailingSlash(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/users/me", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewMattermostValidatorWithClient(&http.Client{
		Transport: &mattermostMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.mattermost.1",
		NamedGroups: map[string][]byte{
			"token": []byte("testtoken12345678901234"),
		},
		Snippet: types.Snippet{
			Before:   []byte("url=https://mattermost.example.com/"),
			Matching: []byte("mattermost_token=testtoken12345678901234"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestMattermostValidator_AccessToken_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := NewMattermostValidatorWithClient(&http.Client{
		Transport: &mattermostMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.mattermost.1",
		NamedGroups: map[string][]byte{
			"token": []byte("testtoken12345678901234"),
		},
		Snippet: types.Snippet{
			Before:   []byte("url=https://mattermost.example.com"),
			Matching: []byte("mattermost_token=testtoken12345678901234"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestMattermostValidator_AccessToken_UnexpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewMattermostValidatorWithClient(&http.Client{
		Transport: &mattermostMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "kingfisher.mattermost.2",
		NamedGroups: map[string][]byte{
			"token": []byte("testtoken12345678901234"),
		},
		Snippet: types.Snippet{
			Before:   []byte("url=https://mattermost.example.com"),
			Matching: []byte("MATTERMOST_TOKEN=testtoken12345678901234"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
}

// mattermostMockTransport redirects requests to the mock server.
type mattermostMockTransport struct {
	server *httptest.Server
}

func (t *mattermostMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}
