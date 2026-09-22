package scoring

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/praetorian-inc/titus/pkg/types"
)

type gitlabGroupInfo struct {
	FullPath string `json:"full_path"`
}

type gitlabProjectInfo struct {
	PathWithNamespace string `json:"path_with_namespace"`
}

// gitlabResourcesCondition enumerates groups and projects accessible at
// Maintainer+ level and populates m.Resources.
type gitlabResourcesCondition struct {
	client gitlabHTTPClient
}

func (c *gitlabResourcesCondition) markDynamic() {}

func (c *gitlabResourcesCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
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

	groups := gitlabListGroups(ctx, cl, host, token)
	for _, g := range groups {
		m.Resources = append(m.Resources, types.ResourceInfo{
			Service: "gitlab",
			Type:    "group",
			Name:    g,
		})
	}

	projects := gitlabListProjects(ctx, cl, host, token)
	for _, p := range projects {
		m.Resources = append(m.Resources, types.ResourceInfo{
			Service: "gitlab",
			Type:    "project",
			Name:    p,
		})
	}

	return len(m.Resources) > 0, nil
}

func (c *gitlabResourcesCondition) httpClient() gitlabHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

func gitlabListGroups(ctx context.Context, client gitlabHTTPClient, host, token string) []string {
	url := fmt.Sprintf("https://%s/api/v4/groups?min_access_level=40&per_page=%d", host, maxResourcesPerType)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}

	var groups []gitlabGroupInfo
	if json.Unmarshal(body, &groups) != nil {
		return nil
	}

	var names []string
	for _, g := range groups {
		if g.FullPath != "" {
			names = append(names, g.FullPath)
		}
	}
	return names
}

func gitlabListProjects(ctx context.Context, client gitlabHTTPClient, host, token string) []string {
	url := fmt.Sprintf("https://%s/api/v4/projects?min_access_level=40&per_page=%d", host, maxResourcesPerType)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}

	var projects []gitlabProjectInfo
	if json.Unmarshal(body, &projects) != nil {
		return nil
	}

	var names []string
	for _, p := range projects {
		if p.PathWithNamespace != "" {
			names = append(names, p.PathWithNamespace)
		}
	}
	return names
}
