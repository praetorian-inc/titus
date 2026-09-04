package scoring

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/google/go-github/v57/github"
	"github.com/praetorian-inc/titus/pkg/types"
	"golang.org/x/sync/singleflight"
)

// userFetchReady classifies a GET /user outcome for the scope/site/enterprise
// conditions: a 200 means evaluate the predicate; a 401 is a silent non-fire
// (the token-revoked modifier scores that case, so emitting an error here would
// just produce noise); any other failure (transport, timeout, 5xx) is surfaced
// so the engine logs and tracks it instead of silently treating it as "absent".
func userFetchReady(res githubUserResult, err error) (ready bool, retErr error) {
	switch {
	case res.status == 200:
		return true, nil
	case res.status == 401:
		return false, nil
	case err != nil:
		return false, err
	default:
		return false, nil
	}
}

// Classic PATs (np.github.1, Authorization: token) and OAuth tokens
// (np.github.2) carry a comma-separated scope list in the X-OAuth-Scopes
// response header. Unlike fine-grained PATs (np.github.7, handled by
// GitHubGoScorer), they default to wide-open scope and must be ranked from
// live scope enumeration. These conditions parse the scope set with exact
// token matching — substring matching would conflate public_repo with repo
// and read:user with user — which the YAML header_contains DSL cannot do.

// parseOAuthScopes splits an X-OAuth-Scopes header value into a set of exact
// scope tokens. Empty/whitespace entries are dropped.
func parseOAuthScopes(header string) map[string]bool {
	scopes := make(map[string]bool)
	for _, part := range strings.Split(header, ",") {
		s := strings.TrimSpace(part)
		if s != "" {
			scopes[s] = true
		}
	}
	return scopes
}

// githubClientFor returns the condition's injected client factory result, or a
// default authenticated client when no factory is set.
func githubClientFor(ctx context.Context, factory func(token string) *github.Client, token string) *github.Client {
	if factory != nil {
		return factory(token)
	}
	return newGitHubClient(ctx, token)
}

// githubUserResult holds the parsed outcome of a single GET /user call.
type githubUserResult struct {
	user   *github.User
	scopes map[string]bool
	status int
}

// fetchGitHubUser performs GET /user and returns the authenticated user, the
// parsed X-OAuth-Scopes set, and the HTTP status. On transport/auth error the
// status is still reported (e.g. 401 for a revoked token) so callers can
// distinguish "revoked" (401) from a transport failure (status 0, err set).
func fetchGitHubUser(ctx context.Context, client *github.Client) (githubUserResult, error) {
	user, resp, err := client.Users.Get(ctx, "")
	res := githubUserResult{scopes: map[string]bool{}}
	if resp != nil {
		res.status = resp.StatusCode
		res.scopes = parseOAuthScopes(resp.Header.Get("X-OAuth-Scopes"))
	}
	if err != nil {
		return res, err
	}
	res.user = user
	return res, nil
}

// maxGitHubUserCacheEntries bounds the cache so a long-lived (library service)
// engine reuse cannot grow it without limit. A single scan's working set of
// distinct tokens sits well under this, so the wholesale drop rarely triggers.
const maxGitHubUserCacheEntries = 4096

// githubUserCache deduplicates GET /user across the multiple scope-based
// conditions that score a single token. Modifiers for one finding evaluate
// sequentially, but findings are scored concurrently; a singleflight.Group
// coalesces concurrent fetches for the same token into one network call, and
// the mutex guards the result map. Only terminal outcomes (a 200 or a 401
// revocation) are cached — transient failures are left uncached so a later
// finding retries. Keys are SHA-256 hashes of the token, never the plaintext
// secret.
type githubUserCache struct {
	mu      sync.Mutex
	entries map[string]githubUserResult
	group   singleflight.Group
}

func newGitHubUserCache() *githubUserCache {
	return &githubUserCache{entries: make(map[string]githubUserResult)}
}

// fetch returns the cached GET /user result for token, fetching once on miss.
// A nil cache fetches directly (used by unit tests that construct conditions
// without a shared cache).
func (c *githubUserCache) fetch(ctx context.Context, client *github.Client, token string) (githubUserResult, error) {
	if c == nil {
		return fetchGitHubUser(ctx, client)
	}
	key := hashToken(token)

	c.mu.Lock()
	cached, ok := c.entries[key]
	c.mu.Unlock()
	if ok {
		return cached, nil
	}

	v, err, _ := c.group.Do(key, func() (interface{}, error) {
		// Another caller may have populated the cache while this one queued
		// behind the singleflight lock.
		c.mu.Lock()
		entry, ok := c.entries[key]
		c.mu.Unlock()
		if ok {
			return entry, nil
		}

		res, ferr := fetchGitHubUser(ctx, client)
		// Cache only terminal results: a successful 200 or a definitive 401
		// revocation. A transient failure (5xx/network/timeout) is not cached,
		// so later findings retry rather than inheriting a pinned error.
		if ferr == nil || res.status == 401 {
			c.store(key, res)
		}
		return res, ferr
	})
	res, _ := v.(githubUserResult)
	return res, err
}

func (c *githubUserCache) store(key string, res githubUserResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxGitHubUserCacheEntries {
		c.entries = make(map[string]githubUserResult, maxGitHubUserCacheEntries)
	}
	c.entries[key] = res
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// setGitHubOwner populates owner info on the match from a successful GET /user response.
func setGitHubOwner(m *types.Match, res githubUserResult) {
	if m.Owner != nil || res.user == nil {
		return
	}
	m.Owner = &types.OwnerInfo{
		Service:     "github",
		User:        res.user.GetLogin(),
		Email:       res.user.GetEmail(),
		DisplayName: res.user.GetName(),
	}
}

// githubScopePresentCondition fires when an exact scope token is present in the
// token's X-OAuth-Scopes set.
type githubScopePresentCondition struct {
	scope         string
	clientFactory func(token string) *github.Client
	userCache     *githubUserCache
}

func (c *githubScopePresentCondition) markDynamic() {}

func (c *githubScopePresentCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitHubToken(m)
	if !ok {
		return false, nil
	}
	res, err := c.userCache.fetch(ctx, githubClientFor(ctx, c.clientFactory, token), token)
	if ready, ferr := userFetchReady(res, err); !ready {
		return false, ferr
	}
	setGitHubOwner(m, res)
	return res.scopes[c.scope], nil
}

// githubScopeOnlyCondition fires when the token has at least one scope and
// every scope is within the allowed set — i.e. the token is limited to those
// low-privilege scopes (public_repo-only, read:user-only).
type githubScopeOnlyCondition struct {
	allowed       []string
	clientFactory func(token string) *github.Client
	userCache     *githubUserCache
}

func (c *githubScopeOnlyCondition) markDynamic() {}

func (c *githubScopeOnlyCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitHubToken(m)
	if !ok {
		return false, nil
	}
	res, err := c.userCache.fetch(ctx, githubClientFor(ctx, c.clientFactory, token), token)
	if ready, ferr := userFetchReady(res, err); !ready {
		return false, ferr
	}
	setGitHubOwner(m, res)
	if len(res.scopes) == 0 {
		return false, nil
	}
	allowedSet := make(map[string]bool, len(c.allowed))
	for _, a := range c.allowed {
		allowedSet[a] = true
	}
	for s := range res.scopes {
		if !allowedSet[s] {
			return false, nil
		}
	}
	return true, nil
}

// githubSiteAdminCondition fires when the authenticated user is a GitHub
// instance administrator (self-hosted GitHub Enterprise Server site_admin).
type githubSiteAdminCondition struct {
	clientFactory func(token string) *github.Client
	userCache     *githubUserCache
}

func (c *githubSiteAdminCondition) markDynamic() {}

func (c *githubSiteAdminCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitHubToken(m)
	if !ok {
		return false, nil
	}
	res, err := c.userCache.fetch(ctx, githubClientFor(ctx, c.clientFactory, token), token)
	if ready, ferr := userFetchReady(res, err); !ready {
		return false, ferr
	}
	setGitHubOwner(m, res)
	if res.user == nil {
		return false, nil
	}
	return res.user.GetSiteAdmin(), nil
}

// githubTokenRevokedCondition fires when GET /user returns 401, indicating an
// expired or revoked token (dead credential). A transport failure (no status)
// is returned as an error so the engine logs it rather than silently treating
// the token as live.
type githubTokenRevokedCondition struct {
	clientFactory func(token string) *github.Client
	userCache     *githubUserCache
}

func (c *githubTokenRevokedCondition) markDynamic() {}

func (c *githubTokenRevokedCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitHubToken(m)
	if !ok {
		return false, nil
	}
	res, err := c.userCache.fetch(ctx, githubClientFor(ctx, c.clientFactory, token), token)
	// A 401 is the expected "revoked/expired" signal; go-github surfaces it as
	// an error, so check status before treating err as a transport failure.
	if res.status == 401 {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

// githubEnterprisePlanCondition fires when the authenticated user's account is
// on the GitHub enterprise plan (GET /user .plan.name == "enterprise"),
// indicating elevated organizational risk. Ported from the retired YAML scorer.
type githubEnterprisePlanCondition struct {
	clientFactory func(token string) *github.Client
	userCache     *githubUserCache
}

func (c *githubEnterprisePlanCondition) markDynamic() {}

func (c *githubEnterprisePlanCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitHubToken(m)
	if !ok {
		return false, nil
	}
	res, err := c.userCache.fetch(ctx, githubClientFor(ctx, c.clientFactory, token), token)
	if ready, ferr := userFetchReady(res, err); !ready {
		return false, ferr
	}
	setGitHubOwner(m, res)
	if res.user == nil {
		return false, nil
	}
	return res.user.GetPlan().GetName() == "enterprise", nil
}

// githubOrgOwnerCondition fires when the token is an admin (owner) of at least
// minCount organizations (GET /user/memberships/orgs, role == "admin"). Only
// active memberships count — pending invitations carry role=admin but grant no
// access.
type githubOrgOwnerCondition struct {
	minCount      int
	clientFactory func(token string) *github.Client
}

func (c *githubOrgOwnerCondition) markDynamic() {}

func (c *githubOrgOwnerCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitHubToken(m)
	if !ok {
		return false, nil
	}
	client := githubClientFor(ctx, c.clientFactory, token)

	opts := &github.ListOrgMembershipsOptions{
		State:       "active",
		ListOptions: github.ListOptions{PerPage: 100},
	}
	const maxPages = 5
	adminCount := 0
	for page := 1; page <= maxPages; page++ {
		memberships, resp, err := client.Organizations.ListOrgMemberships(ctx, opts)
		if err != nil {
			// A revoked/forbidden token (401/403) is a silent non-fire; surface
			// genuine transport/5xx failures so the engine logs and tracks them
			// rather than scoring them identically to "fewer than minCount orgs".
			if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
				return false, nil
			}
			return false, err
		}
		for _, ms := range memberships {
			if ms.GetState() == "active" && ms.GetRole() == "admin" {
				adminCount++
				if adminCount >= c.minCount {
					return true, nil
				}
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return false, nil
}

// GitHubClassicPATGoScorer scores classic PATs (np.github.1) and OAuth tokens
// (np.github.2) by live scope enumeration. All modifiers are dynamic and only
// run under --score-scope.
func GitHubClassicPATGoScorer() *Scorer {
	return gitHubClassicPATScorerWithFactory(nil)
}

// gitHubClassicPATScorerWithFactory builds the scorer with an injectable client
// factory (nil = production default) and a single GET /user cache shared across
// all scope-based conditions.
//
// set_score priorities are ordered so the most severe co-firing modifier is
// applied last (the engine's last-fired set_score wins). The scope-only DOWN
// modifiers are mutually exclusive with the scope UP modifiers by construction;
// site_admin is orthogonal to scopes, and its lower priority lets it correctly
// override admin:org/delete_repo when present. org-owner-3plus is a delta and
// fires last, stacking on top of whatever set_score won.
func gitHubClassicPATScorerWithFactory(factory func(token string) *github.Client) *Scorer {
	cache := newGitHubUserCache()
	return &Scorer{
		Name:    "github-classic-pat-scope",
		RuleIDs: []string{"np.github.1", "np.github.2"},
		Modifiers: []Modifier{
			{
				Name:      "token-revoked",
				Priority:  80,
				Kind:      ModifierKindSetScore,
				Value:     5,
				Condition: &githubTokenRevokedCondition{clientFactory: factory, userCache: cache},
			},
			{
				Name:      "read-user-only",
				Priority:  78,
				Kind:      ModifierKindSetScore,
				Value:     10,
				Condition: &githubScopeOnlyCondition{allowed: []string{"read:user"}, clientFactory: factory, userCache: cache},
			},
			{
				Name:      "public-repo-only",
				Priority:  76,
				Kind:      ModifierKindSetScore,
				Value:     25,
				Condition: &githubScopeOnlyCondition{allowed: []string{"public_repo"}, clientFactory: factory, userCache: cache},
			},
			{
				Name:      "delete-repo-scope",
				Priority:  60,
				Kind:      ModifierKindSetScore,
				Value:     85,
				Condition: &githubScopePresentCondition{scope: "delete_repo", clientFactory: factory, userCache: cache},
			},
			{
				Name:      "admin-org-scope",
				Priority:  55,
				Kind:      ModifierKindSetScore,
				Value:     90,
				Condition: &githubScopePresentCondition{scope: "admin:org", clientFactory: factory, userCache: cache},
			},
			{
				Name:      "site-admin",
				Priority:  50,
				Kind:      ModifierKindSetScore,
				Value:     95,
				Condition: &githubSiteAdminCondition{clientFactory: factory, userCache: cache},
			},
			{
				Name:      "org-owner-3plus",
				Priority:  20,
				Kind:      ModifierKindDelta,
				Value:     12,
				Condition: &githubOrgOwnerCondition{minCount: 3, clientFactory: factory},
			},
			// Delta; fires after all set_score modifiers so the enterprise
			// signal stacks on top of whichever scope score won.
			{
				Name:      "enterprise-plan",
				Priority:  18,
				Kind:      ModifierKindDelta,
				Value:     15,
				Condition: &githubEnterprisePlanCondition{clientFactory: factory, userCache: cache},
			},
		},
	}
}
