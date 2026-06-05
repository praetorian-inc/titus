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

func supabaseMatch() *types.Match {
	return &types.Match{
		RuleID: "kingfisher.supabase.1",
		Groups: [][]byte{
			[]byte("sbp_testexampletoken1234567890abcdefghij"),
		},
		NamedGroups: map[string][]byte{},
	}
}

func TestExtractSupabaseToken_FromPositionalGroup(t *testing.T) {
	m := supabaseMatch()
	token, ok := extractSupabaseToken(m)
	assert.True(t, ok)
	assert.Equal(t, "sbp_testexampletoken1234567890abcdefghij", token)
}

func TestExtractSupabaseToken_FromNamedGroup(t *testing.T) {
	m := &types.Match{
		RuleID: "kingfisher.supabase.1",
		Groups: [][]byte{},
		NamedGroups: map[string][]byte{
			"token": []byte("sbp_testexampletoken1234567890abcdefghij"),
		},
	}
	token, ok := extractSupabaseToken(m)
	assert.True(t, ok)
	assert.Equal(t, "sbp_testexampletoken1234567890abcdefghij", token)
}

func TestExtractSupabaseToken_Missing(t *testing.T) {
	m := &types.Match{
		RuleID:      "kingfisher.supabase.1",
		Groups:      [][]byte{},
		NamedGroups: map[string][]byte{},
	}
	_, ok := extractSupabaseToken(m)
	assert.False(t, ok)
}

func TestExtractSupabaseToken_Nil(t *testing.T) {
	_, ok := extractSupabaseToken(nil)
	assert.False(t, ok)
}

func TestSupabaseTokenExpiredCondition_Expired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := &supabaseTokenExpiredCondition{
		client: &supabaseRedirectingClient{target: server.URL},
	}

	fired, err := c.Evaluate(context.Background(), supabaseMatch())
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestSupabaseTokenExpiredCondition_NotExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":"org1"}]`))
	}))
	defer server.Close()

	c := &supabaseTokenExpiredCondition{
		client: &supabaseRedirectingClient{target: server.URL},
	}

	fired, err := c.Evaluate(context.Background(), supabaseMatch())
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestSupabaseActiveTokenCondition_Active(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer sbp_")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":"org1"}]`))
	}))
	defer server.Close()

	c := &supabaseActiveTokenCondition{
		client: &supabaseRedirectingClient{target: server.URL},
	}

	fired, err := c.Evaluate(context.Background(), supabaseMatch())
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestSupabaseActiveTokenCondition_Inactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := &supabaseActiveTokenCondition{
		client: &supabaseRedirectingClient{target: server.URL},
	}

	fired, err := c.Evaluate(context.Background(), supabaseMatch())
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestSupabaseMultiProjectCondition_AboveThreshold(t *testing.T) {
	projects := make([]map[string]string, 7)
	for i := range projects {
		projects[i] = map[string]string{"id": "proj"}
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/projects", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(projects)
	}))
	defer server.Close()

	c := &supabaseMultiProjectCondition{
		threshold: 5,
		client:    &supabaseRedirectingClient{target: server.URL},
	}

	fired, err := c.Evaluate(context.Background(), supabaseMatch())
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestSupabaseMultiProjectCondition_BelowThreshold(t *testing.T) {
	projects := []map[string]string{{"id": "proj1"}, {"id": "proj2"}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(projects)
	}))
	defer server.Close()

	c := &supabaseMultiProjectCondition{
		threshold: 5,
		client:    &supabaseRedirectingClient{target: server.URL},
	}

	fired, err := c.Evaluate(context.Background(), supabaseMatch())
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestSupabaseGoScorer_Structure(t *testing.T) {
	s := SupabaseGoScorer()
	assert.Equal(t, "supabase-management-scope", s.Name)
	assert.Contains(t, s.RuleIDs, "kingfisher.supabase.1")
	assert.Equal(t, 3, len(s.Modifiers))

	names := make([]string, len(s.Modifiers))
	for i, mod := range s.Modifiers {
		names[i] = mod.Name
	}
	assert.Contains(t, names, "token-expired")
	assert.Contains(t, names, "active-token")
	assert.Contains(t, names, "multi-project")
}

// supabaseRedirectingClient redirects all requests to a test server URL.
type supabaseRedirectingClient struct {
	target string
}

func (c *supabaseRedirectingClient) Do(req *http.Request) (*http.Response, error) {
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

func TestSupabaseGoScorer_MissingToken(t *testing.T) {
	s := SupabaseGoScorer()
	m := &types.Match{
		RuleID:      "kingfisher.supabase.1",
		Groups:      [][]byte{},
		NamedGroups: map[string][]byte{},
	}

	for _, mod := range s.Modifiers {
		fired, err := mod.Condition.Evaluate(context.Background(), m)
		assert.NoError(t, err, "modifier %s should not error", mod.Name)
		assert.False(t, fired, "modifier %s should not fire without token", mod.Name)
	}
}
