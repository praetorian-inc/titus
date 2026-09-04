package scoring

import (
	"context"

	"github.com/google/go-github/v57/github"
	"github.com/praetorian-inc/titus/pkg/types"
)

// githubResourcesCondition enumerates repos and orgs accessible via the token
// and populates m.Resources. Always fires true (the enumeration itself is the
// value; the delta is a small bump for having enumerable resources).
type githubResourcesCondition struct {
	clientFactory func(token string) *github.Client
	userCache     *githubUserCache
}

func (c *githubResourcesCondition) markDynamic() {}

func (c *githubResourcesCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, ok := extractGitHubToken(m)
	if !ok {
		return false, nil
	}

	res, err := c.userCache.fetch(ctx, githubClientFor(ctx, c.clientFactory, token), token)
	if ready, ferr := userFetchReady(res, err); !ready {
		return false, ferr
	}

	client := githubClientFor(ctx, c.clientFactory, token)

	repos, _, err := client.Repositories.List(ctx, "", &github.RepositoryListOptions{
		Sort:        "pushed",
		ListOptions: github.ListOptions{PerPage: maxResourcesPerType},
	})
	if err == nil {
		for _, r := range repos {
			m.Resources = append(m.Resources, types.ResourceInfo{
				Service: "github",
				Type:    "repo",
				Name:    r.GetFullName(),
			})
		}
	}

	orgs, _, err := client.Organizations.List(ctx, "", &github.ListOptions{PerPage: maxResourcesPerType})
	if err == nil {
		for _, o := range orgs {
			m.Resources = append(m.Resources, types.ResourceInfo{
				Service: "github",
				Type:    "org",
				Name:    o.GetLogin(),
			})
		}
	}

	return len(m.Resources) > 0, nil
}
