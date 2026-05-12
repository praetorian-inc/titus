package scoring

import (
	"context"
	"regexp"

	"github.com/google/go-github/v57/github"
	"github.com/praetorian-inc/titus/pkg/types"
	"golang.org/x/oauth2"
)

// extractGitHubToken extracts the OAuth token from match.NamedGroups["token"].
func extractGitHubToken(m *types.Match) (string, bool) {
	if m == nil {
		return "", false
	}
	tok, ok := m.NamedGroups["token"]
	if !ok || len(tok) == 0 {
		return "", false
	}
	return string(tok), true
}

// newGitHubClient creates an authenticated GitHub client for the given token.
func newGitHubClient(ctx context.Context, token string) *github.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

// githubFineGrainedPermCondition fires when a fine-grained PAT has at least
// the given access level on >=1 accessible repository.
// requiredPerm: "write" (push) or "admin"
type githubFineGrainedPermCondition struct {
	requiredPerm  string
	clientFactory func(token string) *github.Client
}

func (c *githubFineGrainedPermCondition) markDynamic() {}

func (c *githubFineGrainedPermCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitHubToken(m)
	if !ok {
		return false, nil
	}

	client := newGitHubClient(ctx, token)
	if c.clientFactory != nil {
		client = c.clientFactory(token)
	}

	// Use the authenticated user repos endpoint (GET /user/repos).
	// Apps.ListRepos is the GitHub App installation API and always returns 401
	// for PATs; Repositories.ListByAuthenticatedUser is the correct endpoint.
	opts := &github.RepositoryListByAuthenticatedUserOptions{
		ListOptions: github.ListOptions{PerPage: 10},
	}
	repos, _, err := client.Repositories.ListByAuthenticatedUser(ctx, opts)
	if err != nil {
		return false, nil
	}

	for _, repo := range repos {
		perms := repo.GetPermissions()
		switch c.requiredPerm {
		case "admin":
			if v, ok := perms["admin"]; ok && v {
				return true, nil
			}
		case "write":
			if v, ok := perms["push"]; ok && v {
				return true, nil
			}
		}
	}
	return false, nil
}

// githubOrgMemberCondition fires when the token is authorized for >=1 organization.
type githubOrgMemberCondition struct {
	clientFactory func(token string) *github.Client
}

func (c *githubOrgMemberCondition) markDynamic() {}

func (c *githubOrgMemberCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitHubToken(m)
	if !ok {
		return false, nil
	}

	client := newGitHubClient(ctx, token)
	if c.clientFactory != nil {
		client = c.clientFactory(token)
	}

	orgs, _, err := client.Organizations.List(ctx, "", &github.ListOptions{PerPage: 1})
	if err != nil {
		return false, nil
	}
	return len(orgs) > 0, nil
}

// GitHubGoScorer returns a *Scorer targeting fine-grained GitHub PATs (np.github.7).
// Classic PATs (np.github.1/2) remain handled by the YAML scorer.
func GitHubGoScorer() *Scorer {
	return &Scorer{
		Name:    "github-fine-grained-scope",
		RuleIDs: []string{"np.github.7"},
		Modifiers: []Modifier{
			// Static: fine-grained prefix always runs
			{
				Name:     "fine-grained-pat-prefix",
				Priority: 100,
				Kind:     ModifierKindDelta,
				Value:    -10,
				Condition: &matchGroupCondition{
					Name:  "token",
					Regex: regexp.MustCompile(`(?i)^github_pat_`),
				},
			},
			// Dynamic: repo/org access (requires --score-scope)
			{
				Name:      "fine-grained-admin-repo",
				Priority:  95,
				Kind:      ModifierKindSetScore,
				Value:     92,
				Condition: &githubFineGrainedPermCondition{requiredPerm: "admin"},
			},
			{
				Name:      "fine-grained-write-repo",
				Priority:  90,
				Kind:      ModifierKindSetScore,
				Value:     85,
				Condition: &githubFineGrainedPermCondition{requiredPerm: "write"},
			},
			{
				Name:      "token-org-member",
				Priority:  70,
				Kind:      ModifierKindDelta,
				Value:     8,
				Condition: &githubOrgMemberCondition{},
			},
		},
	}
}
