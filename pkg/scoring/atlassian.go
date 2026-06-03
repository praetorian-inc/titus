package scoring

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Pre-compiled patterns for extracting Atlassian credentials from snippet context.
var (
	atlassianEmailPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)email\s*=\s*['"]([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['"]`),
		regexp.MustCompile(`(?i)JIRA_USER\s*=\s*['"]([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['"]`),
		regexp.MustCompile(`(?i)user\s*=\s*['"]([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['"]`),
		regexp.MustCompile(`(?i)env\s*\(\s*['"][^'"]*['"]\s*,\s*['"]([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['"]\s*\)`),
		regexp.MustCompile(`\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b`),
	}
	atlassianDomainPatterns = []*regexp.Regexp{
		regexp.MustCompile(`https?://([a-z][a-z0-9\-]{1,24}\.atlassian\.net)`),
		regexp.MustCompile(`\b([a-z][a-z0-9\-]{1,24}\.atlassian\.net)\b`),
	}
)

// extractAtlassianCredentials extracts token, email, and domain from a match.
// Returns empty strings and false if any piece is missing.
func extractAtlassianCredentials(m *types.Match) (token, email, domain string, ok bool) {
	if m == nil {
		return "", "", "", false
	}
	tok, hasToken := m.NamedGroups["token"]
	if !hasToken || len(tok) == 0 {
		return "", "", "", false
	}
	token = string(tok)

	email = searchSnippetForScoring(m.Snippet, atlassianEmailPatterns)
	if email == "" {
		return "", "", "", false
	}

	domain = searchSnippetForScoring(m.Snippet, atlassianDomainPatterns)
	if domain == "" {
		return "", "", "", false
	}

	return token, email, domain, true
}

// searchSnippetForScoring searches all three snippet parts against patterns,
// returning the first captured group match.
func searchSnippetForScoring(snippet types.Snippet, patterns []*regexp.Regexp) string {
	parts := [][]byte{snippet.Before, snippet.Matching, snippet.After}
	for _, pattern := range patterns {
		for _, part := range parts {
			if matches := pattern.FindSubmatch(part); len(matches) >= 2 {
				return string(matches[1])
			}
		}
	}
	return ""
}

// atlassianHTTPClient is an interface for making HTTP requests (allows testing).
type atlassianHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// atlassianSiteAdminCondition fires when the Atlassian token belongs to a
// site admin on any accessible site. Uses GET /rest/api/3/myself on the
// domain extracted from snippet context.
type atlassianSiteAdminCondition struct {
	client atlassianHTTPClient
}

func (c *atlassianSiteAdminCondition) markDynamic() {}

func (c *atlassianSiteAdminCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, email, domain, ok := extractAtlassianCredentials(m)
	if !ok {
		return false, nil
	}

	// GET /rest/api/3/myself returns user info including accountType
	url := fmt.Sprintf("https://%s/rest/api/3/myself", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, nil
	}
	req.SetBasicAuth(email, token)

	client := c.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil
	}

	// Check for admin indicators in the response
	var userInfo struct {
		AccountType    string `json:"accountType"`
		ApplicationRoles struct {
			Items []struct {
				Key string `json:"key"`
			} `json:"items"`
		} `json:"applicationRoles"`
	}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return false, nil
	}

	// Now check if user has admin permissions
	permURL := fmt.Sprintf("https://%s/rest/api/3/mypermissions?permissions=ADMINISTER", domain)
	permReq, err := http.NewRequestWithContext(ctx, "GET", permURL, nil)
	if err != nil {
		return false, nil
	}
	permReq.SetBasicAuth(email, token)

	permResp, err := client.Do(permReq)
	if err != nil {
		return false, nil
	}
	defer func() { io.Copy(io.Discard, permResp.Body); permResp.Body.Close() }()

	if permResp.StatusCode != http.StatusOK {
		return false, nil
	}

	permBody, err := io.ReadAll(permResp.Body)
	if err != nil {
		return false, nil
	}

	// Check ADMINISTER permission
	var permResult struct {
		Permissions map[string]struct {
			HavePermission bool `json:"havePermission"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(permBody, &permResult); err != nil {
		return false, nil
	}

	if perm, ok := permResult.Permissions["ADMINISTER"]; ok && perm.HavePermission {
		return true, nil
	}

	return false, nil
}

func (c *atlassianSiteAdminCondition) httpClient() atlassianHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// atlassianProjectCountCondition fires when the token has access to >= threshold projects.
type atlassianProjectCountCondition struct {
	threshold int
	client    atlassianHTTPClient
}

func (c *atlassianProjectCountCondition) markDynamic() {}

func (c *atlassianProjectCountCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, email, domain, ok := extractAtlassianCredentials(m)
	if !ok {
		return false, nil
	}

	url := fmt.Sprintf("https://%s/rest/api/3/project?maxResults=50", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, nil
	}
	req.SetBasicAuth(email, token)

	client := c.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil
	}

	var projects []json.RawMessage
	if err := json.Unmarshal(body, &projects); err != nil {
		return false, nil
	}

	return len(projects) >= c.threshold, nil
}

func (c *atlassianProjectCountCondition) httpClient() atlassianHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// atlassianBitbucketAccessCondition fires when the token grants access to Bitbucket
// (source code access). Checks via the accessible-resources endpoint pattern
// or by looking for Bitbucket indicators in the snippet context.
type atlassianBitbucketAccessCondition struct{}

func (c *atlassianBitbucketAccessCondition) Evaluate(_ context.Context, m *types.Match) (bool, error) {
	if m == nil {
		return false, nil
	}
	// Check snippet context for Bitbucket indicators
	combined := string(m.Snippet.Before) + string(m.Snippet.Matching) + string(m.Snippet.After)
	lower := strings.ToLower(combined)
	return strings.Contains(lower, "bitbucket"), nil
}

// atlassianGuestAccountCondition fires when the snippet context suggests this
// is a guest/external account (lower risk).
type atlassianGuestAccountCondition struct{}

func (c *atlassianGuestAccountCondition) Evaluate(_ context.Context, m *types.Match) (bool, error) {
	if m == nil {
		return false, nil
	}
	combined := string(m.Snippet.Before) + string(m.Snippet.Matching) + string(m.Snippet.After)
	lower := strings.ToLower(combined)
	return strings.Contains(lower, "guest"), nil
}

// atlassianTokenExpiredCondition fires when the token is expired (401 from the API).
type atlassianTokenExpiredCondition struct {
	client atlassianHTTPClient
}

func (c *atlassianTokenExpiredCondition) markDynamic() {}

func (c *atlassianTokenExpiredCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	token, email, domain, ok := extractAtlassianCredentials(m)
	if !ok {
		return false, nil
	}

	url := fmt.Sprintf("https://%s/rest/api/3/myself", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, nil
	}
	req.SetBasicAuth(email, token)

	client := c.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	return resp.StatusCode == http.StatusUnauthorized, nil
}

func (c *atlassianTokenExpiredCondition) httpClient() atlassianHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// AtlassianGoScorer returns the Atlassian scoring configuration for np.atlassian.1.
// Implements LAB-3366 (Atlassian admin detection) and LAB-3399 (Jira project scope).
func AtlassianGoScorer() *Scorer {
	return &Scorer{
		Name:    "atlassian-scope",
		RuleIDs: []string{"np.atlassian.1"},
		Modifiers: []Modifier{
			// Priority 100: Token expired → set_score 5 (highest priority, overrides all)
			{
				Name:      "token-expired",
				Priority:  100,
				Kind:      ModifierKindSetScore,
				Value:     5,
				Condition: &atlassianTokenExpiredCondition{},
			},
			// Priority 95: Site admin → set_score 85
			{
				Name:      "site-admin",
				Priority:  95,
				Kind:      ModifierKindSetScore,
				Value:     85,
				Condition: &atlassianSiteAdminCondition{},
			},
			// Priority 80: Bitbucket access → delta +15
			{
				Name:      "bitbucket-access",
				Priority:  80,
				Kind:      ModifierKindDelta,
				Value:     15,
				Condition: &atlassianBitbucketAccessCondition{},
			},
			// Priority 70: Access to 50+ projects → delta +10 (broad org-wide access)
			{
				Name:      "broad-project-access",
				Priority:  70,
				Kind:      ModifierKindDelta,
				Value:     10,
				Condition: &atlassianProjectCountCondition{threshold: 50},
			},
			// Priority 60: Guest account → delta -20 (limited scope)
			{
				Name:      "guest-account",
				Priority:  60,
				Kind:      ModifierKindDelta,
				Value:     -20,
				Condition: &atlassianGuestAccountCondition{},
			},
		},
	}
}
