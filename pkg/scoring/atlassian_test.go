package scoring

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func atlassianMatch(email, domain string) *types.Match {
	return &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEtokenFORunit_testing=00000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("email = '" + email + "'\n"),
			Matching: []byte("api_token = 'ATATT3xFfGF0testEXAMPLEtokenFORunit_testing=00000000'"),
			After:    []byte("# https://" + domain + "/rest/api/3/myself\n"),
		},
	}
}

func TestExtractAtlassianCredentials_Success(t *testing.T) {
	m := atlassianMatch("info@example.com", "mycompany.atlassian.net")
	token, email, domain, ok := extractAtlassianCredentials(m)
	assert.True(t, ok)
	assert.Equal(t, "ATATT3xFfGF0testEXAMPLEtokenFORunit_testing=00000000", token)
	assert.Equal(t, "info@example.com", email)
	assert.Equal(t, "mycompany.atlassian.net", domain)
}

func TestExtractAtlassianCredentials_MissingToken(t *testing.T) {
	m := &types.Match{
		RuleID:      "np.atlassian.1",
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before: []byte("email = 'info@example.com'\n"),
			After:  []byte("https://mycompany.atlassian.net\n"),
		},
	}
	_, _, _, ok := extractAtlassianCredentials(m)
	assert.False(t, ok)
}

func TestExtractAtlassianCredentials_MissingEmail(t *testing.T) {
	m := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEshort=00000000"),
		},
		Snippet: types.Snippet{
			Before: []byte("no email here\n"),
			After:  []byte("https://mycompany.atlassian.net\n"),
		},
	}
	_, _, _, ok := extractAtlassianCredentials(m)
	assert.False(t, ok)
}

func TestExtractAtlassianCredentials_MissingDomain(t *testing.T) {
	m := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEshort=00000000"),
		},
		Snippet: types.Snippet{
			Before: []byte("email = 'info@example.com'\n"),
			After:  []byte("no domain here\n"),
		},
	}
	_, _, _, ok := extractAtlassianCredentials(m)
	assert.False(t, ok)
}

func TestAtlassianSiteAdminCondition_IsAdmin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/api/3/myself":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"accountType": "atlassian",
				"accountId":   "123",
			})
		case "/rest/api/3/mypermissions":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"permissions": map[string]interface{}{
					"ADMINISTER": map[string]interface{}{
						"havePermission": true,
					},
				},
			})
		}
	}))
	defer server.Close()

	c := &atlassianSiteAdminCondition{
		client: &redirectingClient{target: server.URL},
	}

	m := atlassianMatch("info@example.com", "mycompany.atlassian.net")
	fired, err := c.Evaluate(context.Background(), m)
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestAtlassianSiteAdminCondition_NotAdmin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/api/3/myself":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"accountType": "atlassian",
			})
		case "/rest/api/3/mypermissions":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"permissions": map[string]interface{}{
					"ADMINISTER": map[string]interface{}{
						"havePermission": false,
					},
				},
			})
		}
	}))
	defer server.Close()

	c := &atlassianSiteAdminCondition{
		client: &redirectingClient{target: server.URL},
	}

	m := atlassianMatch("info@example.com", "mycompany.atlassian.net")
	fired, err := c.Evaluate(context.Background(), m)
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestAtlassianProjectCountCondition_AboveThreshold(t *testing.T) {
	projects := make([]map[string]string, 55)
	for i := range projects {
		projects[i] = map[string]string{"key": "PROJ"}
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(projects)
	}))
	defer server.Close()

	c := &atlassianProjectCountCondition{
		threshold: 50,
		client:    &redirectingClient{target: server.URL},
	}

	m := atlassianMatch("info@example.com", "mycompany.atlassian.net")
	fired, err := c.Evaluate(context.Background(), m)
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestAtlassianProjectCountCondition_BelowThreshold(t *testing.T) {
	projects := []map[string]string{{"key": "PROJ1"}, {"key": "PROJ2"}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(projects)
	}))
	defer server.Close()

	c := &atlassianProjectCountCondition{
		threshold: 50,
		client:    &redirectingClient{target: server.URL},
	}

	m := atlassianMatch("info@example.com", "mycompany.atlassian.net")
	fired, err := c.Evaluate(context.Background(), m)
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestAtlassianBitbucketAccessCondition_HasBitbucket(t *testing.T) {
	c := &atlassianBitbucketAccessCondition{}
	m := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEshort=00000000"),
		},
		Snippet: types.Snippet{
			Before: []byte("# Bitbucket integration\nemail = 'info@example.com'\n"),
			After:  []byte("https://mycompany.atlassian.net\n"),
		},
	}
	fired, err := c.Evaluate(context.Background(), m)
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestAtlassianBitbucketAccessCondition_NoBitbucket(t *testing.T) {
	c := &atlassianBitbucketAccessCondition{}
	m := atlassianMatch("info@example.com", "mycompany.atlassian.net")
	fired, err := c.Evaluate(context.Background(), m)
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestAtlassianGuestAccountCondition_IsGuest(t *testing.T) {
	c := &atlassianGuestAccountCondition{}
	m := &types.Match{
		RuleID: "np.atlassian.1",
		NamedGroups: map[string][]byte{
			"token": []byte("ATATT3xFfGF0testEXAMPLEshort=00000000"),
		},
		Snippet: types.Snippet{
			Before: []byte("# Guest user access\n"),
			After:  []byte("https://mycompany.atlassian.net\n"),
		},
	}
	fired, err := c.Evaluate(context.Background(), m)
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestAtlassianGuestAccountCondition_NotGuest(t *testing.T) {
	c := &atlassianGuestAccountCondition{}
	m := atlassianMatch("info@example.com", "mycompany.atlassian.net")
	fired, err := c.Evaluate(context.Background(), m)
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestAtlassianTokenExpiredCondition_Expired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := &atlassianTokenExpiredCondition{
		client: &redirectingClient{target: server.URL},
	}

	m := atlassianMatch("info@example.com", "mycompany.atlassian.net")
	fired, err := c.Evaluate(context.Background(), m)
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestAtlassianTokenExpiredCondition_NotExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accountId":"123"}`))
	}))
	defer server.Close()

	c := &atlassianTokenExpiredCondition{
		client: &redirectingClient{target: server.URL},
	}

	m := atlassianMatch("info@example.com", "mycompany.atlassian.net")
	fired, err := c.Evaluate(context.Background(), m)
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestAtlassianGoScorer_Structure(t *testing.T) {
	s := AtlassianGoScorer()
	assert.Equal(t, "atlassian-scope", s.Name)
	assert.Contains(t, s.RuleIDs, "np.atlassian.1")
	assert.Equal(t, 5, len(s.Modifiers), "expected 5 modifiers")

	// Verify modifier names and priorities
	names := make([]string, len(s.Modifiers))
	for i, mod := range s.Modifiers {
		names[i] = mod.Name
	}
	assert.Contains(t, names, "token-expired")
	assert.Contains(t, names, "site-admin")
	assert.Contains(t, names, "bitbucket-access")
	assert.Contains(t, names, "broad-project-access")
	assert.Contains(t, names, "guest-account")
}

func TestAtlassianGoScorer_MissingCredentials(t *testing.T) {
	// All conditions should gracefully return false when credentials are missing
	s := AtlassianGoScorer()
	m := &types.Match{
		RuleID:      "np.atlassian.1",
		NamedGroups: map[string][]byte{},
	}

	for _, mod := range s.Modifiers {
		fired, err := mod.Condition.Evaluate(context.Background(), m)
		assert.NoError(t, err, "modifier %s should not error", mod.Name)
		assert.False(t, fired, "modifier %s should not fire without credentials", mod.Name)
	}
}

// redirectingClient redirects all requests to a test server URL.
type redirectingClient struct {
	target string
}

func (c *redirectingClient) Do(req *http.Request) (*http.Response, error) {
	// Rewrite the URL to point to the test server
	testURL := c.target + req.URL.Path
	if req.URL.RawQuery != "" {
		testURL += "?" + req.URL.RawQuery
	}
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, testURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header
	return http.DefaultClient.Do(newReq)
}
