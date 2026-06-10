package scoring

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-github/v57/github"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testClientFactory returns a clientFactory that points a go-github client at
// the test server (mirrors the pattern in github_test.go).
func testClientFactory(serverURL string) func(token string) *github.Client {
	return func(token string) *github.Client {
		c := github.NewClient(http.DefaultClient)
		base, _ := url.Parse(serverURL + "/")
		c.BaseURL = base
		c.UploadURL = base
		return c
	}
}

func ghMatch() *types.Match {
	return &types.Match{NamedGroups: map[string][]byte{"token": []byte("ghp_testtoken")}}
}

// ---- parseOAuthScopes ----

func TestParseOAuthScopes_SplitsAndTrims(t *testing.T) {
	got := parseOAuthScopes("repo, admin:org ,delete_repo")
	assert.True(t, got["repo"])
	assert.True(t, got["admin:org"])
	assert.True(t, got["delete_repo"])
	assert.Len(t, got, 3)
}

func TestParseOAuthScopes_Empty(t *testing.T) {
	assert.Len(t, parseOAuthScopes(""), 0)
	assert.Len(t, parseOAuthScopes("   "), 0)
}

// public_repo must NOT be reported as repo (exact-token, no substring bug).
func TestParseOAuthScopes_NoSubstringCollision(t *testing.T) {
	got := parseOAuthScopes("public_repo, read:user")
	assert.True(t, got["public_repo"])
	assert.False(t, got["repo"], "public_repo must not match repo")
	assert.False(t, got["user"], "read:user must not match user")
}

// ---- dynamic markers ----

func TestGitHubClassicConditions_AreDynamic(t *testing.T) {
	for _, c := range []Condition{
		&githubScopePresentCondition{scope: "admin:org"},
		&githubScopeOnlyCondition{allowed: []string{"public_repo"}},
		&githubSiteAdminCondition{},
		&githubTokenRevokedCondition{},
		&githubOrgOwnerCondition{minCount: 3},
		&githubEnterprisePlanCondition{},
	} {
		var mod Modifier
		mod.Condition = c
		assert.Truef(t, mod.IsDynamic(), "%T must be dynamic", c)
	}
}

// ---- scope-present (admin:org, delete_repo) ----

func userScopesServer(t *testing.T, scopes string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-OAuth-Scopes", scopes)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"login":"alice","site_admin":false}`)
	}))
}

func TestScopePresent_FiresOnExactScope(t *testing.T) {
	srv := userScopesServer(t, "repo, admin:org, delete_repo")
	defer srv.Close()
	cond := &githubScopePresentCondition{scope: "admin:org", clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestScopePresent_DoesNotFireOnSubstring(t *testing.T) {
	// scopes contain public_repo only; "repo" present-check must NOT fire.
	srv := userScopesServer(t, "public_repo")
	defer srv.Close()
	cond := &githubScopePresentCondition{scope: "repo", clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.False(t, fired, "repo must not match public_repo")
}

func TestScopePresent_DeleteRepo(t *testing.T) {
	srv := userScopesServer(t, "repo, delete_repo")
	defer srv.Close()
	cond := &githubScopePresentCondition{scope: "delete_repo", clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

// ---- scope-only (public_repo-only, read:user-only) ----

func TestScopeOnly_FiresWhenAllWithinAllowed(t *testing.T) {
	srv := userScopesServer(t, "public_repo")
	defer srv.Close()
	cond := &githubScopeOnlyCondition{allowed: []string{"public_repo"}, clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestScopeOnly_DoesNotFireWhenExtraScopePresent(t *testing.T) {
	srv := userScopesServer(t, "public_repo, repo")
	defer srv.Close()
	cond := &githubScopeOnlyCondition{allowed: []string{"public_repo"}, clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.False(t, fired, "must not fire when a non-allowed scope (repo) is present")
}

func TestScopeOnly_DoesNotFireWhenNoScopes(t *testing.T) {
	srv := userScopesServer(t, "")
	defer srv.Close()
	cond := &githubScopeOnlyCondition{allowed: []string{"public_repo"}, clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.False(t, fired, "empty scope set must not be treated as public_repo-only")
}

func TestScopeOnly_ReadUserOnly(t *testing.T) {
	srv := userScopesServer(t, "read:user")
	defer srv.Close()
	cond := &githubScopeOnlyCondition{allowed: []string{"read:user"}, clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

// ---- site_admin ----

func TestSiteAdmin_FiresWhenTrue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"login":"root","site_admin":true}`)
	}))
	defer srv.Close()
	cond := &githubSiteAdminCondition{clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestSiteAdmin_DoesNotFireWhenFalse(t *testing.T) {
	srv := userScopesServer(t, "repo")
	defer srv.Close()
	cond := &githubSiteAdminCondition{clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

// ---- revoked / expired (401) ----

func TestTokenRevoked_FiresOn401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintln(w, `{"message":"Bad credentials"}`)
	}))
	defer srv.Close()
	cond := &githubTokenRevokedCondition{clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestTokenRevoked_DoesNotFireOn200(t *testing.T) {
	srv := userScopesServer(t, "repo")
	defer srv.Close()
	cond := &githubTokenRevokedCondition{clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

// ---- org ownership ----

func orgMembershipsServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/memberships/orgs" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, body)
	}))
}

func TestOrgOwner_FiresWhenThreeAdminMemberships(t *testing.T) {
	srv := orgMembershipsServer(t, `[
		{"state":"active","role":"admin","organization":{"login":"o1"}},
		{"state":"active","role":"admin","organization":{"login":"o2"}},
		{"state":"active","role":"member","organization":{"login":"o3"}},
		{"state":"active","role":"admin","organization":{"login":"o4"}}
	]`)
	defer srv.Close()
	cond := &githubOrgOwnerCondition{minCount: 3, clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.True(t, fired, "3 active admin memberships should fire")
}

func TestOrgOwner_DoesNotFireWhenOnlyTwoAdmin(t *testing.T) {
	srv := orgMembershipsServer(t, `[
		{"state":"active","role":"admin","organization":{"login":"o1"}},
		{"state":"active","role":"admin","organization":{"login":"o2"}},
		{"state":"active","role":"member","organization":{"login":"o3"}}
	]`)
	defer srv.Close()
	cond := &githubOrgOwnerCondition{minCount: 3, clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.False(t, fired, "only 2 active admin memberships must not fire")
}

// ---- scorer wiring ----

func TestGitHubClassicPATGoScorer_Shape(t *testing.T) {
	s := GitHubClassicPATGoScorer()
	assert.Equal(t, "github-classic-pat-scope", s.Name)
	assert.Contains(t, s.RuleIDs, "np.github.1")
	assert.Contains(t, s.RuleIDs, "np.github.2")
	assert.NotContains(t, s.RuleIDs, "np.github.7", "fine-grained PATs are handled by GitHubGoScorer")
	assert.Greater(t, len(s.Modifiers), 0)
	for _, m := range s.Modifiers {
		assert.Truef(t, m.IsDynamic(), "modifier %q must be dynamic (scope-gated)", m.Name)
	}
}

func TestBuiltinGoScorers_IncludesGitHubClassic(t *testing.T) {
	var found bool
	for _, s := range BuiltinGoScorers() {
		if s.Name == "github-classic-pat-scope" {
			found = true
			assert.Contains(t, s.RuleIDs, "np.github.1")
			assert.Contains(t, s.RuleIDs, "np.github.2")
		}
	}
	assert.True(t, found, "BuiltinGoScorers must include github-classic-pat-scope")
}

// SF-2: pending org invitations carry role=admin but grant no access; they
// must not count toward org ownership.
func TestOrgOwner_DoesNotCountPendingInvitations(t *testing.T) {
	srv := orgMembershipsServer(t, `[
		{"state":"active","role":"admin","organization":{"login":"o1"}},
		{"state":"pending","role":"admin","organization":{"login":"o2"}},
		{"state":"pending","role":"admin","organization":{"login":"o3"}},
		{"state":"pending","role":"admin","organization":{"login":"o4"}}
	]`)
	defer srv.Close()
	cond := &githubOrgOwnerCondition{minCount: 3, clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.False(t, fired, "pending admin invitations must not count as org ownership")
}

// SF-3: a transport/network failure must surface as an error (engine logs it),
// not be silently swallowed — while a genuine 401 still fires without error.
func TestTokenRevoked_TransportErrorReturnsError(t *testing.T) {
	// Closed server => connection refused (transport error, status 0).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	cond := &githubTokenRevokedCondition{clientFactory: testClientFactory(url)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	assert.Error(t, err, "transport failure must return an error")
	assert.False(t, fired)
}

// ---- enterprise plan (parity with retired YAML scorer) ----

func userPlanServer(t *testing.T, plan string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-OAuth-Scopes", "repo")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"login":"u","plan":{"name":%q}}`+"\n", plan)
	}))
}

func TestEnterprisePlan_FiresForEnterprise(t *testing.T) {
	srv := userPlanServer(t, "enterprise")
	defer srv.Close()
	cond := &githubEnterprisePlanCondition{clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestEnterprisePlan_DoesNotFireForFree(t *testing.T) {
	srv := userPlanServer(t, "free")
	defer srv.Close()
	cond := &githubEnterprisePlanCondition{clientFactory: testClientFactory(srv.URL)}
	fired, err := cond.Evaluate(context.Background(), ghMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

// ---- engine-level final-score tests (SF-4) ----
// These run the real modifier wiring (priorities, set_score/delta) through
// Engine.Score so a priority/value regression is caught mechanically.

// ghClassicEngineServer serves /user and /user/memberships/orgs for end-to-end
// scoring tests.
func ghClassicEngineServer(t *testing.T, status int, scopes string, siteAdmin bool, memberships string) *httptest.Server {
	t.Helper()
	if memberships == "" {
		memberships = "[]"
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			if status != 200 {
				w.WriteHeader(status)
				_, _ = fmt.Fprintln(w, `{"message":"err"}`)
				return
			}
			w.Header().Set("X-OAuth-Scopes", scopes)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"login":"u","site_admin":%t}`+"\n", siteAdmin)
		case "/user/memberships/orgs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, memberships)
		default:
			http.NotFound(w, r)
		}
	}))
}

func scoreClassicToken(t *testing.T, srv *httptest.Server, ruleID string, base int) *types.Score {
	t.Helper()
	scorer := gitHubClassicPATScorerWithFactory(testClientFactory(srv.URL))
	engine := NewEngine([]*Scorer{scorer}, EngineConfig{ScopeEnabled: true, Timeout: 5 * time.Second})
	rule := &types.Rule{ID: ruleID, BaseScore: base}
	finding := &types.Finding{ID: "f", RuleID: ruleID}
	match := &types.Match{RuleID: ruleID, NamedGroups: map[string][]byte{"token": []byte("ghp_secret")}}
	score := engine.Score(context.Background(), finding, []*types.Match{match}, rule)
	require.NotNil(t, score)
	return score
}

func TestEngineScore_Revoked(t *testing.T) {
	srv := ghClassicEngineServer(t, 401, "", false, "")
	defer srv.Close()
	score := scoreClassicToken(t, srv, "np.github.1", 75)
	assert.Equal(t, 5, score.Final, "revoked token should set_score to 5")
}

func TestEngineScore_PublicRepoOnly(t *testing.T) {
	srv := ghClassicEngineServer(t, 200, "public_repo", false, "")
	defer srv.Close()
	score := scoreClassicToken(t, srv, "np.github.1", 75)
	assert.Equal(t, 25, score.Final, "public_repo-only should set_score to 25")
}

func TestEngineScore_AdminOrgAndDeleteRepo_AdminOrgWins(t *testing.T) {
	srv := ghClassicEngineServer(t, 200, "repo, delete_repo, admin:org", false, "")
	defer srv.Close()
	score := scoreClassicToken(t, srv, "np.github.2", 70)
	assert.Equal(t, 90, score.Final, "admin:org (90) must win over delete_repo (85) when both fire")
}

func TestEngineScore_SiteAdminWinsOverScopes(t *testing.T) {
	srv := ghClassicEngineServer(t, 200, "delete_repo, admin:org", true, "")
	defer srv.Close()
	score := scoreClassicToken(t, srv, "np.github.1", 75)
	assert.Equal(t, 95, score.Final, "site_admin (95) must win over admin:org/delete_repo")
}

func TestEngineScore_OrgOwnerDeltaStacksAndClamps(t *testing.T) {
	srv := ghClassicEngineServer(t, 200, "admin:org", true, `[
		{"state":"active","role":"admin","organization":{"login":"o1"}},
		{"state":"active","role":"admin","organization":{"login":"o2"}},
		{"state":"active","role":"admin","organization":{"login":"o3"}}
	]`)
	defer srv.Close()
	score := scoreClassicToken(t, srv, "np.github.1", 75)
	assert.Equal(t, 100, score.Final, "site_admin 95 + org-owner +12 clamps to 100")
}

// Enterprise plan applies as a +15 delta on top of the scope set_score,
// matching the retired YAML scorer's behavior.
func TestEngineScore_EnterprisePlanStacks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			w.Header().Set("X-OAuth-Scopes", "repo") // no UP/DOWN modifier fires
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{"login":"u","site_admin":false,"plan":{"name":"enterprise"}}`)
		case "/user/memberships/orgs":
			_, _ = fmt.Fprintln(w, `[]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	score := scoreClassicToken(t, srv, "np.github.2", 70)
	assert.Equal(t, 85, score.Final, "enterprise plan adds +15 to base 70")
}

// SF-1: the scope-based conditions must share a single GET /user fetch per
// finding rather than each issuing its own request.
func TestEngineScore_DedupesUserFetch(t *testing.T) {
	var userHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			atomic.AddInt32(&userHits, 1)
			w.Header().Set("X-OAuth-Scopes", "admin:org")
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{"login":"u","site_admin":false}`)
		case "/user/memberships/orgs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `[]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	_ = scoreClassicToken(t, srv, "np.github.1", 75)
	assert.Equal(t, int32(1), atomic.LoadInt32(&userHits),
		"all scope conditions should share one GET /user call per finding")
}
