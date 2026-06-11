package scoring

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Pre-compiled patterns for extracting GitLab host from snippet context.
var gitlabHostPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)https?://([a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})(?:/api/|/[a-zA-Z0-9])`),
	regexp.MustCompile(`(?i)(?:GITLAB_HOST|CI_SERVER_HOST|CI_SERVER_URL)\s*=\s*['"]?(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})`),
}

const gitlabDefaultHost = "gitlab.com"

// extractGitLabToken extracts the token from match.NamedGroups["1"].
// GitLab PAT rules use unnamed capture groups.
func extractGitLabToken(m *types.Match) (string, bool) {
	if m == nil {
		return "", false
	}
	tok, ok := m.NamedGroups["1"]
	if !ok || len(tok) == 0 {
		return "", false
	}
	return string(tok), true
}

// extractGitLabHost extracts the GitLab host from snippet context.
// Defaults to "gitlab.com" if not found.
func extractGitLabHost(m *types.Match) string {
	if m == nil {
		return gitlabDefaultHost
	}
	host := searchSnippetForScoring(m.Snippet, gitlabHostPatterns)
	if host == "" {
		return gitlabDefaultHost
	}
	// Exclude Atlassian-style domains that may match the generic URL pattern.
	if strings.Contains(strings.ToLower(host), "atlassian.net") {
		return gitlabDefaultHost
	}
	return host
}

// gitlabHTTPClient is an interface for making HTTP requests (allows testing).
type gitlabHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// gitlabTokenSelfResponse holds the relevant fields from /personal_access_tokens/self.
type gitlabTokenSelfResponse struct {
	Scopes    []string `json:"scopes"`
	Revoked   bool     `json:"revoked"`
	ExpiresAt string   `json:"expires_at"`
}

// gitlabUserResponse holds the relevant fields from /user.
type gitlabUserResponse struct {
	IsAdmin bool `json:"is_admin"`
}

// gitlabFetchTokenSelf calls GET /api/v4/personal_access_tokens/self and returns
// the parsed response along with the HTTP status code.
func gitlabFetchTokenSelf(ctx context.Context, client gitlabHTTPClient, host, token string) (*gitlabTokenSelfResponse, int, error) {
	url := fmt.Sprintf("https://%s/api/v4/personal_access_tokens/self", host)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	var info gitlabTokenSelfResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, resp.StatusCode, err
	}
	return &info, resp.StatusCode, nil
}

// gitlabFetchUser calls GET /api/v4/user and returns the parsed response.
func gitlabFetchUser(ctx context.Context, client gitlabHTTPClient, host, token string) (*gitlabUserResponse, error) {
	url := fmt.Sprintf("https://%s/api/v4/user", host)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var user gitlabUserResponse
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// gitlabHasGroupOwnerAccess calls GET /api/v4/groups?min_access_level=50&per_page=5
// and returns true if at least one group is returned.
func gitlabHasGroupOwnerAccess(ctx context.Context, client gitlabHTTPClient, host, token string) (bool, error) {
	url := fmt.Sprintf("https://%s/api/v4/groups?min_access_level=50&per_page=5", host)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var groups []json.RawMessage
	if err := json.Unmarshal(body, &groups); err != nil {
		return false, err
	}
	return len(groups) > 0, nil
}

// gitlabTokenIsActive returns true when the token is not revoked and not expired.
// Scope conditions must guard with this to prevent a revoked token's scopes from
// overwriting the lower score set by token-revoked-expired.
func gitlabTokenIsActive(info *gitlabTokenSelfResponse) bool {
	return info != nil && !gitlabTokenExpired(info)
}

// gitlabTokenExpired returns true when the token is revoked or has a past expiry.
func gitlabTokenExpired(info *gitlabTokenSelfResponse) bool {
	if info.Revoked {
		return true
	}
	if info.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", info.ExpiresAt)
	if err != nil {
		return false
	}
	return time.Now().UTC().After(t.UTC())
}

// gitlabScopesContain reports whether the target scope is in the scopes list.
func gitlabScopesContain(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

// gitlabOnlyHasScopes returns true when every scope in the list is one of the
// allowed values and at least one scope is present.
func gitlabOnlyHasScopes(scopes []string, allowed ...string) bool {
	if len(scopes) == 0 {
		return false
	}
	allowSet := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allowSet[a] = true
	}
	for _, s := range scopes {
		if !allowSet[s] {
			return false
		}
	}
	return true
}

// ----------------------------------------------------------------------------
// Condition implementations
// ----------------------------------------------------------------------------

// gitlabTokenRevokedCondition fires when the token returns 401/403 or is
// revoked/expired according to /personal_access_tokens/self.
type gitlabTokenRevokedCondition struct {
	client gitlabHTTPClient
}

func (c *gitlabTokenRevokedCondition) markDynamic() {}

func (c *gitlabTokenRevokedCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitLabToken(m)
	if !ok {
		return false, nil
	}
	host := extractGitLabHost(m)

	info, status, err := gitlabFetchTokenSelf(ctx, c.httpClient(), host, token)
	if err != nil {
		return false, nil
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return true, nil
	}
	if info == nil {
		return false, nil
	}
	return gitlabTokenExpired(info), nil
}

func (c *gitlabTokenRevokedCondition) httpClient() gitlabHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// gitlabSudoScopeCondition fires when the token's scopes contain "sudo".
type gitlabSudoScopeCondition struct {
	client gitlabHTTPClient
}

func (c *gitlabSudoScopeCondition) markDynamic() {}

func (c *gitlabSudoScopeCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitLabToken(m)
	if !ok {
		return false, nil
	}
	host := extractGitLabHost(m)

	info, _, err := gitlabFetchTokenSelf(ctx, c.httpClient(), host, token)
	if err != nil || info == nil {
		return false, nil
	}
	if !gitlabTokenIsActive(info) {
		return false, nil
	}
	return gitlabScopesContain(info.Scopes, "sudo"), nil
}

func (c *gitlabSudoScopeCondition) httpClient() gitlabHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// gitlabAdminAPIScopeCondition fires when is_admin=true AND the token has the "api" scope.
type gitlabAdminAPIScopeCondition struct {
	client gitlabHTTPClient
}

func (c *gitlabAdminAPIScopeCondition) markDynamic() {}

func (c *gitlabAdminAPIScopeCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitLabToken(m)
	if !ok {
		return false, nil
	}
	host := extractGitLabHost(m)
	cl := c.httpClient()

	info, _, err := gitlabFetchTokenSelf(ctx, cl, host, token)
	if err != nil || info == nil {
		return false, nil
	}
	if !gitlabTokenIsActive(info) {
		return false, nil
	}
	if !gitlabScopesContain(info.Scopes, "api") {
		return false, nil
	}
	if gitlabScopesContain(info.Scopes, "sudo") {
		return false, nil
	}

	user, err := gitlabFetchUser(ctx, cl, host, token)
	if err != nil || user == nil {
		return false, nil
	}
	return user.IsAdmin, nil
}

func (c *gitlabAdminAPIScopeCondition) httpClient() gitlabHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// gitlabReadUserOnlyCondition fires when the token only has the "read_user" scope.
type gitlabReadUserOnlyCondition struct {
	client gitlabHTTPClient
}

func (c *gitlabReadUserOnlyCondition) markDynamic() {}

func (c *gitlabReadUserOnlyCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitLabToken(m)
	if !ok {
		return false, nil
	}
	host := extractGitLabHost(m)

	info, _, err := gitlabFetchTokenSelf(ctx, c.httpClient(), host, token)
	if err != nil || info == nil {
		return false, nil
	}
	if !gitlabTokenIsActive(info) {
		return false, nil
	}
	return gitlabOnlyHasScopes(info.Scopes, "read_user"), nil
}

func (c *gitlabReadUserOnlyCondition) httpClient() gitlabHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// gitlabAPIScopeGroupOwnerCondition fires when the token has the "api" scope
// AND the user has Owner access to at least one group.
type gitlabAPIScopeGroupOwnerCondition struct {
	client gitlabHTTPClient
}

func (c *gitlabAPIScopeGroupOwnerCondition) markDynamic() {}

func (c *gitlabAPIScopeGroupOwnerCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitLabToken(m)
	if !ok {
		return false, nil
	}
	host := extractGitLabHost(m)
	cl := c.httpClient()

	info, _, err := gitlabFetchTokenSelf(ctx, cl, host, token)
	if err != nil || info == nil {
		return false, nil
	}
	if !gitlabTokenIsActive(info) {
		return false, nil
	}
	if !gitlabScopesContain(info.Scopes, "api") {
		return false, nil
	}

	hasOwner, err := gitlabHasGroupOwnerAccess(ctx, cl, host, token)
	if err != nil {
		return false, nil
	}
	return hasOwner, nil
}

func (c *gitlabAPIScopeGroupOwnerCondition) httpClient() gitlabHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// gitlabSelfHostedCondition fires when the host is not gitlab.com (static).
type gitlabSelfHostedCondition struct{}

func (c *gitlabSelfHostedCondition) Evaluate(_ context.Context, m *types.Match) (bool, error) {
	host := extractGitLabHost(m)
	return !strings.EqualFold(host, gitlabDefaultHost), nil
}

// gitlabWriteRepoMultiGroupCondition fires when the token has "write_repository"
// scope AND the user has Owner access to at least one group.
type gitlabWriteRepoMultiGroupCondition struct {
	client gitlabHTTPClient
}

func (c *gitlabWriteRepoMultiGroupCondition) markDynamic() {}

func (c *gitlabWriteRepoMultiGroupCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitLabToken(m)
	if !ok {
		return false, nil
	}
	host := extractGitLabHost(m)
	cl := c.httpClient()

	info, _, err := gitlabFetchTokenSelf(ctx, cl, host, token)
	if err != nil || info == nil {
		return false, nil
	}
	if !gitlabTokenIsActive(info) {
		return false, nil
	}
	if !gitlabScopesContain(info.Scopes, "write_repository") {
		return false, nil
	}

	hasOwner, err := gitlabHasGroupOwnerAccess(ctx, cl, host, token)
	if err != nil {
		return false, nil
	}
	return hasOwner, nil
}

func (c *gitlabWriteRepoMultiGroupCondition) httpClient() gitlabHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// gitlabReadAPIOnlyNonAdminCondition fires when the token only has "read_api"
// scope AND the user is not an admin.
type gitlabReadAPIOnlyNonAdminCondition struct {
	client gitlabHTTPClient
}

func (c *gitlabReadAPIOnlyNonAdminCondition) markDynamic() {}

func (c *gitlabReadAPIOnlyNonAdminCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitLabToken(m)
	if !ok {
		return false, nil
	}
	host := extractGitLabHost(m)
	cl := c.httpClient()

	info, _, err := gitlabFetchTokenSelf(ctx, cl, host, token)
	if err != nil || info == nil {
		return false, nil
	}
	if !gitlabTokenIsActive(info) {
		return false, nil
	}
	if !gitlabOnlyHasScopes(info.Scopes, "read_api") {
		return false, nil
	}

	user, err := gitlabFetchUser(ctx, cl, host, token)
	if err != nil || user == nil {
		return false, nil
	}
	return !user.IsAdmin, nil
}

func (c *gitlabReadAPIOnlyNonAdminCondition) httpClient() gitlabHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// gitlabNoGroupOwnerCondition fires when the user has NO Owner access to any group.
type gitlabNoGroupOwnerCondition struct {
	client gitlabHTTPClient
}

func (c *gitlabNoGroupOwnerCondition) markDynamic() {}

func (c *gitlabNoGroupOwnerCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitLabToken(m)
	if !ok {
		return false, nil
	}
	host := extractGitLabHost(m)
	cl := c.httpClient()

	info, _, err := gitlabFetchTokenSelf(ctx, cl, host, token)
	if err != nil || info == nil {
		return false, nil
	}
	if !gitlabTokenIsActive(info) {
		return false, nil
	}
	if !gitlabScopesContain(info.Scopes, "api") && !gitlabScopesContain(info.Scopes, "read_api") {
		return false, nil
	}

	hasOwner, err := gitlabHasGroupOwnerAccess(ctx, cl, host, token)
	if err != nil {
		return false, nil
	}
	return !hasOwner, nil
}

func (c *gitlabNoGroupOwnerCondition) httpClient() gitlabHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// GitLabGoScorer returns the GitLab PAT scoring configuration for np.gitlab.2
// and np.gitlab.4 (LAB-3360).
func GitLabGoScorer() *Scorer {
	return &Scorer{
		Name:    "gitlab-pat-scope",
		RuleIDs: []string{"np.gitlab.2", "np.gitlab.4"},
		Modifiers: []Modifier{
			{Name: "token-revoked-expired", Priority: 100, Kind: ModifierKindSetScore, Value: 5, Condition: &gitlabTokenRevokedCondition{}},
			{Name: "sudo-scope", Priority: 95, Kind: ModifierKindSetScore, Value: 99, Condition: &gitlabSudoScopeCondition{}},
			{Name: "admin-api-scope", Priority: 90, Kind: ModifierKindSetScore, Value: 95, Condition: &gitlabAdminAPIScopeCondition{}},
			{Name: "read-user-only", Priority: 85, Kind: ModifierKindSetScore, Value: 15, Condition: &gitlabReadUserOnlyCondition{}},
			{Name: "api-scope-group-owner", Priority: 70, Kind: ModifierKindDelta, Value: 15, Condition: &gitlabAPIScopeGroupOwnerCondition{}},
			{Name: "self-hosted-instance", Priority: 65, Kind: ModifierKindDelta, Value: 10, Condition: &gitlabSelfHostedCondition{}},
			{Name: "write-repo-multi-group", Priority: 60, Kind: ModifierKindDelta, Value: 10, Condition: &gitlabWriteRepoMultiGroupCondition{}},
			{Name: "read-api-only-non-admin", Priority: 55, Kind: ModifierKindDelta, Value: -20, Condition: &gitlabReadAPIOnlyNonAdminCondition{}},
			{Name: "no-group-owner", Priority: 50, Kind: ModifierKindDelta, Value: -10, Condition: &gitlabNoGroupOwnerCondition{}},
		},
	}
}
