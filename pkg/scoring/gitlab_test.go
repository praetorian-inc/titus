package scoring

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gitlabMatch(host string) *types.Match {
	return &types.Match{
		RuleID: "np.gitlab.2",
		Groups: [][]byte{
			[]byte("glpat-testTOKENforUNIT_test"),
		},
		Snippet: types.Snippet{
			Before:   []byte("GITLAB_HOST=" + host + "\n"),
			Matching: []byte("PRIVATE_TOKEN=glpat-testTOKENforUNIT_test"),
			After:    []byte("\n"),
		},
	}
}

// gitlabServer creates a test server that responds to GitLab API endpoints.
// scopes, revoked, expiresAt configure /personal_access_tokens/self.
// isAdmin configures /user.
// groups configures /groups.
func gitlabServer(t *testing.T, scopes []string, revoked bool, expiresAt string, isAdmin bool, groups []map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/personal_access_tokens/self":
			w.WriteHeader(http.StatusOK)
			resp := map[string]interface{}{
				"scopes":  scopes,
				"revoked": revoked,
			}
			if expiresAt != "" {
				resp["expires_at"] = expiresAt
			}
			_ = json.NewEncoder(w).Encode(resp)
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"is_admin": isAdmin,
			})
		case "/api/v4/groups":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(groups)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestExtractGitLabToken_Present(t *testing.T) {
	m := &types.Match{
		Groups: [][]byte{
			[]byte("glpat-testTOKENforUNIT_test"),
		},
	}
	tok, ok := extractGitLabToken(m)
	assert.True(t, ok)
	assert.Equal(t, "glpat-testTOKENforUNIT_test", tok)
}

func TestExtractGitLabToken_Missing(t *testing.T) {
	m := &types.Match{Groups: [][]byte{}}
	_, ok := extractGitLabToken(m)
	assert.False(t, ok)
}

func TestExtractGitLabHost_FromSnippet(t *testing.T) {
	m := gitlabMatch("gitlab.mycompany.com")
	host := extractGitLabHost(m)
	assert.Equal(t, "gitlab.mycompany.com", host)
}

func TestExtractGitLabHost_DefaultsToGitLabCom(t *testing.T) {
	m := &types.Match{
		Groups: [][]byte{[]byte("glpat-test")},
		Snippet: types.Snippet{
			Before:   []byte("PRIVATE_TOKEN=glpat-test\n"),
			Matching: []byte("x=1"),
			After:    []byte("\n"),
		},
	}
	host := extractGitLabHost(m)
	assert.Equal(t, "gitlab.com", host)
}

func TestGitLabTokenRevokedCondition_Revoked(t *testing.T) {
	server := gitlabServer(t, []string{"api"}, true, "", false, nil)
	defer server.Close()

	c := &gitlabTokenRevokedCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGitLabTokenRevokedCondition_Expired(t *testing.T) {
	server := gitlabServer(t, []string{"api"}, false, "2000-01-01", false, nil)
	defer server.Close()

	c := &gitlabTokenRevokedCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGitLabTokenRevokedCondition_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := &gitlabTokenRevokedCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGitLabTokenRevokedCondition_Active(t *testing.T) {
	server := gitlabServer(t, []string{"api"}, false, "2099-01-01", false, nil)
	defer server.Close()

	c := &gitlabTokenRevokedCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGitLabSudoScopeCondition_HasSudo(t *testing.T) {
	server := gitlabServer(t, []string{"api", "sudo"}, false, "", false, nil)
	defer server.Close()

	c := &gitlabSudoScopeCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGitLabSudoScopeCondition_NoSudo(t *testing.T) {
	server := gitlabServer(t, []string{"api", "read_user"}, false, "", false, nil)
	defer server.Close()

	c := &gitlabSudoScopeCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGitLabAdminAPIScopeCondition_AdminWithAPI(t *testing.T) {
	server := gitlabServer(t, []string{"api"}, false, "", true, nil)
	defer server.Close()

	c := &gitlabAdminAPIScopeCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGitLabAdminAPIScopeCondition_AdminNoAPI(t *testing.T) {
	server := gitlabServer(t, []string{"read_user"}, false, "", true, nil)
	defer server.Close()

	c := &gitlabAdminAPIScopeCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGitLabAdminAPIScopeCondition_NonAdminWithAPI(t *testing.T) {
	server := gitlabServer(t, []string{"api"}, false, "", false, nil)
	defer server.Close()

	c := &gitlabAdminAPIScopeCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGitLabReadUserOnlyCondition_OnlyReadUser(t *testing.T) {
	server := gitlabServer(t, []string{"read_user"}, false, "", false, nil)
	defer server.Close()

	c := &gitlabReadUserOnlyCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGitLabReadUserOnlyCondition_MultipleScopes(t *testing.T) {
	server := gitlabServer(t, []string{"read_user", "api"}, false, "", false, nil)
	defer server.Close()

	c := &gitlabReadUserOnlyCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGitLabAPIScopeGroupOwnerCondition_HasBoth(t *testing.T) {
	groups := []map[string]interface{}{{"id": 1, "name": "mygroup"}}
	server := gitlabServer(t, []string{"api"}, false, "", false, groups)
	defer server.Close()

	c := &gitlabAPIScopeGroupOwnerCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGitLabAPIScopeGroupOwnerCondition_NoGroups(t *testing.T) {
	server := gitlabServer(t, []string{"api"}, false, "", false, []map[string]interface{}{})
	defer server.Close()

	c := &gitlabAPIScopeGroupOwnerCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGitLabSelfHostedCondition_SelfHosted(t *testing.T) {
	server := gitlabServer(t, []string{"api"}, false, "", false, nil)
	defer server.Close()

	c := &gitlabSelfHostedCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.mycompany.com"))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGitLabSelfHostedCondition_GitLabCom(t *testing.T) {
	server := gitlabServer(t, []string{"api"}, false, "", false, nil)
	defer server.Close()

	c := &gitlabSelfHostedCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGitLabReadAPIOnlyNonAdminCondition_Fires(t *testing.T) {
	server := gitlabServer(t, []string{"read_api"}, false, "", false, nil)
	defer server.Close()

	c := &gitlabReadAPIOnlyNonAdminCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGitLabReadAPIOnlyNonAdminCondition_AdminDoesNotFire(t *testing.T) {
	server := gitlabServer(t, []string{"read_api"}, false, "", true, nil)
	defer server.Close()

	c := &gitlabReadAPIOnlyNonAdminCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGitLabNoGroupOwnerCondition_NoOwner(t *testing.T) {
	server := gitlabServer(t, []string{"api"}, false, "", false, []map[string]interface{}{})
	defer server.Close()

	c := &gitlabNoGroupOwnerCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGitLabNoGroupOwnerCondition_HasOwner(t *testing.T) {
	groups := []map[string]interface{}{{"id": 1, "name": "mygroup"}}
	server := gitlabServer(t, []string{"api"}, false, "", false, groups)
	defer server.Close()

	c := &gitlabNoGroupOwnerCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGitLabAdminAPIScopeCondition_SudoExcluded(t *testing.T) {
	// Token has sudo + api + is_admin → admin-api-scope should NOT fire
	// because sudo-scope already covers it at higher priority.
	server := gitlabServer(t, []string{"sudo", "api"}, false, "", true, nil)
	defer server.Close()

	c := &gitlabAdminAPIScopeCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired, "admin-api-scope should not fire when sudo scope is present")
}

func TestGitLabNoGroupOwnerCondition_SkipsReadUserOnly(t *testing.T) {
	// Token with only read_user scope can't access groups at all.
	// no-group-owner should not fire since the check is meaningless.
	server := gitlabServer(t, []string{"read_user"}, false, "", false, []map[string]interface{}{})
	defer server.Close()

	c := &gitlabNoGroupOwnerCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired, "no-group-owner should not fire when token lacks api/read_api scope")
}

func TestGitLabGoScorer_Structure(t *testing.T) {
	s := GitLabGoScorer()
	assert.Equal(t, "gitlab-pat-scope", s.Name)
	assert.Contains(t, s.RuleIDs, "np.gitlab.2")
	assert.Contains(t, s.RuleIDs, "np.gitlab.4")
	assert.Equal(t, 9, len(s.Modifiers), "expected 9 modifiers")

	names := make([]string, len(s.Modifiers))
	for i, mod := range s.Modifiers {
		names[i] = mod.Name
	}
	assert.Contains(t, names, "token-revoked-expired")
	assert.Contains(t, names, "sudo-scope")
	assert.Contains(t, names, "admin-api-scope")
	assert.Contains(t, names, "read-user-only")
	assert.Contains(t, names, "api-scope-group-owner")
	assert.Contains(t, names, "self-hosted-instance")
	assert.Contains(t, names, "write-repo-multi-group")
	assert.Contains(t, names, "read-api-only-non-admin")
	assert.Contains(t, names, "no-group-owner")
}

func TestGitLabGoScorer_MissingCredentials(t *testing.T) {
	s := GitLabGoScorer()
	m := &types.Match{
		RuleID: "np.gitlab.2",
		Groups: [][]byte{},
	}

	for _, mod := range s.Modifiers {
		fired, err := mod.Condition.Evaluate(context.Background(), m)
		assert.NoError(t, err, "modifier %s should not error", mod.Name)
		assert.False(t, fired, "modifier %s should not fire without credentials", mod.Name)
	}
}

func TestGitLabSudoScopeCondition_RevokedTokenDoesNotFire(t *testing.T) {
	// Token is revoked but still has sudo scope in API response.
	// Condition must NOT fire — revoked overrides all scope checks.
	server := gitlabServer(t, []string{"sudo", "api"}, true, "", true, nil)
	defer server.Close()

	c := &gitlabSudoScopeCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired, "sudo-scope must not fire on revoked token")
}

func TestGitLabAdminAPIScopeCondition_RevokedTokenDoesNotFire(t *testing.T) {
	server := gitlabServer(t, []string{"api"}, true, "", true, nil)
	defer server.Close()

	c := &gitlabAdminAPIScopeCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired, "admin-api-scope must not fire on revoked token")
}

func TestGitLabWriteRepoMultiGroupCondition_Fires(t *testing.T) {
	groups := []map[string]interface{}{{"id": 1, "name": "mygroup"}}
	server := gitlabServer(t, []string{"write_repository", "api"}, false, "2099-01-01", false, groups)
	defer server.Close()

	c := &gitlabWriteRepoMultiGroupCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGitLabWriteRepoMultiGroupCondition_NoWriteRepo(t *testing.T) {
	groups := []map[string]interface{}{{"id": 1, "name": "mygroup"}}
	server := gitlabServer(t, []string{"read_api"}, false, "2099-01-01", false, groups)
	defer server.Close()

	c := &gitlabWriteRepoMultiGroupCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGitLabNoGroupOwnerCondition_ReadAPIScope(t *testing.T) {
	// read_api is sufficient scope to check groups; condition should fire when no groups.
	server := gitlabServer(t, []string{"read_api"}, false, "2099-01-01", false, []map[string]interface{}{})
	defer server.Close()

	c := &gitlabNoGroupOwnerCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGitLabGoScorer_IsDynamic(t *testing.T) {
	s := GitLabGoScorer()
	for _, mod := range s.Modifiers {
		assert.True(t, mod.IsDynamic(), "modifier %s should be dynamic", mod.Name)
	}
}

func TestGitLabSelfHostedCondition_RevokedDoesNotFire(t *testing.T) {
	server := gitlabServer(t, []string{"api"}, true, "", false, nil)
	defer server.Close()

	c := &gitlabSelfHostedCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.mycompany.com"))
	require.NoError(t, err)
	assert.False(t, fired, "self-hosted delta must not fire on revoked token")
}

func TestGitLabWriteRepoMultiGroupCondition_NoAPIScope(t *testing.T) {
	groups := []map[string]interface{}{{"id": 1, "name": "mygroup"}}
	server := gitlabServer(t, []string{"write_repository"}, false, "2099-01-01", false, groups)
	defer server.Close()

	c := &gitlabWriteRepoMultiGroupCondition{client: &redirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), gitlabMatch("gitlab.com"))
	require.NoError(t, err)
	assert.False(t, fired, "write-repo-multi-group should not fire without api/read_api scope")
}
