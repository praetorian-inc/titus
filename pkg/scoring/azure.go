package scoring

import (
	"context"
	"regexp"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

var (
	azureTenantIDRe = regexp.MustCompile(
		`(?i)(?:azure[_-]?tenant[_-]?id|arm[_-]?tenant[_-]?id|tenant[_-]?id)["']?\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)
	azureClientIDRe = regexp.MustCompile(
		`(?i)(?:azure[_-]?client[_-]?id|arm[_-]?client[_-]?id|client[_-]?id|app[_-]?id|application[_-]?id)["']?\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)
)

func extractAzureCredentials(m *types.Match) (*azureCredentials, bool) {
	if m == nil {
		return nil, false
	}
	secret, ok := m.NamedGroups["client_secret"]
	if !ok || len(secret) == 0 {
		return nil, false
	}

	surrounding := make([]byte, 0, len(m.Snippet.Before)+len(m.Snippet.Matching)+len(m.Snippet.After))
	surrounding = append(surrounding, m.Snippet.Before...)
	surrounding = append(surrounding, m.Snippet.Matching...)
	surrounding = append(surrounding, m.Snippet.After...)

	creds := &azureCredentials{ClientSecret: string(secret)}
	if match := azureTenantIDRe.FindSubmatch(surrounding); len(match) > 1 {
		creds.TenantID = string(match[1])
	}
	if match := azureClientIDRe.FindSubmatch(surrounding); len(match) > 1 {
		creds.ClientID = string(match[1])
	}
	return creds, true
}

func isSubscriptionScope(scope string) bool {
	trimmed := strings.TrimPrefix(scope, "/")
	parts := strings.Split(trimmed, "/")
	return len(parts) == 2 && strings.EqualFold(parts[0], "subscriptions")
}

// isManagementGroupScope returns true for scopes like
// /providers/Microsoft.Management/managementGroups/<name>.
func isManagementGroupScope(scope string) bool {
	trimmed := strings.TrimPrefix(scope, "/")
	parts := strings.Split(trimmed, "/")
	return len(parts) == 4 &&
		strings.EqualFold(parts[0], "providers") &&
		strings.EqualFold(parts[1], "Microsoft.Management") &&
		strings.EqualFold(parts[2], "managementGroups")
}

// isAtOrAboveSubscriptionScope returns true for subscription-level scope or
// management group scope (which is above subscription level).
func isAtOrAboveSubscriptionScope(scope string) bool {
	return isSubscriptionScope(scope) || isManagementGroupScope(scope)
}

// hasPrivilegedDirectoryRole returns true if the SP holds Global Administrator
// or Privileged Role Administrator. Used by negative-delta conditions to avoid
// incorrectly reducing the score of a highly-privileged SP.
func hasPrivilegedDirectoryRole(ctx context.Context, api azureAPI) bool {
	roles, err := api.GetDirectoryRoleMemberships(ctx)
	if err != nil {
		return false
	}
	for _, r := range roles {
		if r == azureDirRoleGlobalAdmin || r == azureDirRolePrivRoleAdmin {
			return true
		}
	}
	return false
}

// --- Static conditions ---

// azureIncompleteCredentialsCondition fires when client_secret is present but
// tenant_id or client_id cannot be extracted from the surrounding context.
type azureIncompleteCredentialsCondition struct{}

func (c *azureIncompleteCredentialsCondition) Evaluate(_ context.Context, m *types.Match) (bool, error) {
	creds, ok := extractAzureCredentials(m)
	if !ok {
		return false, nil
	}
	return !creds.complete(), nil
}

// --- Dynamic conditions ---

// azureExpiredCondition fires when authentication fails with an Azure AD error
// code indicating invalid or expired credentials.
type azureExpiredCondition struct {
	clientFactory azureClientFactory
}

func (c *azureExpiredCondition) markDynamic() {}

func (c *azureExpiredCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	creds, ok := extractAzureCredentials(m)
	if !ok || !creds.complete() {
		return false, nil
	}
	factory := c.clientFactory
	if factory == nil {
		factory = defaultAzureClientFactory
	}
	_, err := factory(ctx, creds)
	if err != nil {
		lower := strings.ToLower(err.Error())
		for _, code := range []string{
			"aadsts70011", "aadsts700016", "aadsts7000215", "aadsts700027",
			"invalid_client", "unauthorized_client",
		} {
			if strings.Contains(lower, code) {
				return true, nil
			}
		}
	}
	return false, nil
}

// azureGlobalAdminCondition fires when the SP holds Global Administrator
// or Privileged Role Administrator directory roles.
type azureGlobalAdminCondition struct {
	clientFactory azureClientFactory
}

func (c *azureGlobalAdminCondition) markDynamic() {}

func (c *azureGlobalAdminCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	creds, ok := extractAzureCredentials(m)
	if !ok || !creds.complete() {
		return false, nil
	}
	factory := c.clientFactory
	if factory == nil {
		factory = defaultAzureClientFactory
	}
	api, err := factory(ctx, creds)
	if err != nil {
		return false, nil
	}
	return hasPrivilegedDirectoryRole(ctx, api), nil
}

// azureRBACCondition fires when RBAC role assignments match specified criteria.
//
// Fields:
//   - matchRoles: role definition GUIDs to match against
//   - excludeRoles: if any assignment has one of these, don't fire
//   - onlyIfExclusive: when true, ALL roles must be in matchRoles
//   - subscriptionLevel: when true, at least one match must be at subscription scope
//   - resourceGroupOnly: when true (with onlyIfExclusive), all must be below subscription scope
//   - skipIfPrivilegedDir: when true, skip if SP has Global Admin or Privileged Role Admin
type azureRBACCondition struct {
	matchRoles          []string
	excludeRoles        []string
	onlyIfExclusive     bool
	subscriptionLevel   bool
	resourceGroupOnly   bool
	skipIfPrivilegedDir bool
	clientFactory       azureClientFactory
}

func (c *azureRBACCondition) markDynamic() {}

func (c *azureRBACCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	creds, ok := extractAzureCredentials(m)
	if !ok || !creds.complete() {
		return false, nil
	}
	factory := c.clientFactory
	if factory == nil {
		factory = defaultAzureClientFactory
	}
	api, err := factory(ctx, creds)
	if err != nil {
		return false, nil
	}

	if c.skipIfPrivilegedDir && hasPrivilegedDirectoryRole(ctx, api) {
		return false, nil
	}

	subs, err := api.ListSubscriptions(ctx)
	if err != nil || len(subs) == 0 {
		return false, nil
	}

	matchSet := make(map[string]bool, len(c.matchRoles))
	for _, r := range c.matchRoles {
		matchSet[r] = true
	}

	var allAssignments []azureRoleAssignment
	for _, sub := range subs {
		assignments, err := api.ListRoleAssignments(ctx, sub.ID)
		if err != nil {
			continue
		}
		allAssignments = append(allAssignments, assignments...)
	}

	if len(allAssignments) == 0 {
		return false, nil
	}

	if len(c.excludeRoles) > 0 {
		excludeSet := make(map[string]bool, len(c.excludeRoles))
		for _, r := range c.excludeRoles {
			excludeSet[r] = true
		}
		for _, a := range allAssignments {
			if excludeSet[a.RoleDefinitionID] {
				return false, nil
			}
		}
	}

	if c.onlyIfExclusive {
		for _, a := range allAssignments {
			if !matchSet[a.RoleDefinitionID] {
				return false, nil
			}
		}
		if c.resourceGroupOnly {
			for _, a := range allAssignments {
				if isAtOrAboveSubscriptionScope(a.Scope) {
					return false, nil
				}
			}
		}
		return true, nil
	}

	for _, a := range allAssignments {
		if matchSet[a.RoleDefinitionID] {
			if c.subscriptionLevel && !isAtOrAboveSubscriptionScope(a.Scope) {
				continue
			}
			return true, nil
		}
	}
	return false, nil
}

// azureMultiSubCondition fires when the SP can access minSubs or more subscriptions.
type azureMultiSubCondition struct {
	minSubs       int
	clientFactory azureClientFactory
}

func (c *azureMultiSubCondition) markDynamic() {}

func (c *azureMultiSubCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	creds, ok := extractAzureCredentials(m)
	if !ok || !creds.complete() {
		return false, nil
	}
	factory := c.clientFactory
	if factory == nil {
		factory = defaultAzureClientFactory
	}
	api, err := factory(ctx, creds)
	if err != nil {
		return false, nil
	}
	subs, err := api.ListSubscriptions(ctx)
	if err != nil {
		return false, nil
	}
	return len(subs) >= c.minSubs, nil
}

// azureGraphReadOnlyCondition fires when the SP's app role assignments are
// limited to minimal/read-only Microsoft Graph permissions (e.g. User.Read.All)
// or when the SP has no app role assignments at all.
type azureGraphReadOnlyCondition struct {
	clientFactory azureClientFactory
}

func (c *azureGraphReadOnlyCondition) markDynamic() {}

func (c *azureGraphReadOnlyCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	creds, ok := extractAzureCredentials(m)
	if !ok || !creds.complete() {
		return false, nil
	}
	factory := c.clientFactory
	if factory == nil {
		factory = defaultAzureClientFactory
	}
	api, err := factory(ctx, creds)
	if err != nil {
		return false, nil
	}
	if hasPrivilegedDirectoryRole(ctx, api) {
		return false, nil
	}

	// Don't penalize an SP that holds non-Reader ARM RBAC roles; the
	// graph-read-only discount is only meaningful when the SP has no
	// significant ARM access either.
	if hasNonReaderARMRole(ctx, api) {
		return false, nil
	}

	assignments, err := api.GetAppRoleAssignments(ctx)
	if err != nil {
		return false, nil
	}
	for _, a := range assignments {
		if !graphMinimalAppRoles[a.AppRoleID] {
			return false, nil
		}
	}
	return true, nil
}

// hasNonReaderARMRole returns true if the SP holds any ARM RBAC role other
// than Reader across all accessible subscriptions.
func hasNonReaderARMRole(ctx context.Context, api azureAPI) bool {
	subs, err := api.ListSubscriptions(ctx)
	if err != nil {
		return false
	}
	for _, sub := range subs {
		assignments, err := api.ListRoleAssignments(ctx, sub.ID)
		if err != nil {
			continue
		}
		for _, a := range assignments {
			if a.RoleDefinitionID != azureRoleReader {
				return true
			}
		}
	}
	return false
}

// azureSingleNonProdSubCondition fires when the SP has access to exactly one
// subscription and its display name matches a non-production pattern.
type azureSingleNonProdSubCondition struct {
	clientFactory azureClientFactory
}

func (c *azureSingleNonProdSubCondition) markDynamic() {}

func (c *azureSingleNonProdSubCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	creds, ok := extractAzureCredentials(m)
	if !ok || !creds.complete() {
		return false, nil
	}
	factory := c.clientFactory
	if factory == nil {
		factory = defaultAzureClientFactory
	}
	api, err := factory(ctx, creds)
	if err != nil {
		return false, nil
	}
	if hasPrivilegedDirectoryRole(ctx, api) {
		return false, nil
	}
	subs, err := api.ListSubscriptions(ctx)
	if err != nil || len(subs) != 1 {
		return false, nil
	}
	lower := strings.ToLower(subs[0].DisplayName)
	for _, pat := range nonProdPatterns {
		if strings.Contains(lower, pat) {
			return true, nil
		}
	}
	return false, nil
}

// AzureGoScorer returns a *Scorer targeting Azure SP client secret rules.
func AzureGoScorer() *Scorer {
	return &Scorer{
		Name:    "azure-sp-rbac-scope",
		RuleIDs: []string{"np.azure.7", "np.azure.8"},
		Modifiers: []Modifier{
			{Name: "expired-credentials", Priority: 100, Kind: ModifierKindSetScore, Value: 5,
				Condition: &azureExpiredCondition{}},
			{Name: "global-admin", Priority: 95, Kind: ModifierKindSetScore, Value: 99,
				Condition: &azureGlobalAdminCondition{}},
			{Name: "owner-sub-level", Priority: 90, Kind: ModifierKindSetScore, Value: 95,
				Condition: &azureRBACCondition{
					matchRoles:          []string{azureRoleOwner},
					subscriptionLevel:   true,
					skipIfPrivilegedDir: true,
				}},
			{Name: "contributor-sub-level", Priority: 85, Kind: ModifierKindSetScore, Value: 85,
				Condition: &azureRBACCondition{
					matchRoles:          []string{azureRoleContributor},
					excludeRoles:        []string{azureRoleOwner},
					subscriptionLevel:   true,
					skipIfPrivilegedDir: true,
				}},
			{Name: "keyvault-secret-access", Priority: 75, Kind: ModifierKindDelta, Value: 15,
				Condition: &azureRBACCondition{
					matchRoles: []string{azureRoleKVAdmin, azureRoleKVSecretsOfficer, azureRoleKVSecretsUser},
				}},
			{Name: "multi-subscription", Priority: 70, Kind: ModifierKindDelta, Value: 10,
				Condition: &azureMultiSubCondition{minSubs: 3}},
			{Name: "incomplete-credentials", Priority: 60, Kind: ModifierKindDelta, Value: -20,
				Condition: &azureIncompleteCredentialsCondition{}},
			{Name: "reader-only-rg-level", Priority: 55, Kind: ModifierKindDelta, Value: -25,
				Condition: &azureRBACCondition{
					matchRoles:          []string{azureRoleReader},
					onlyIfExclusive:     true,
					resourceGroupOnly:   true,
					skipIfPrivilegedDir: true,
				}},
			{Name: "graph-read-only", Priority: 50, Kind: ModifierKindDelta, Value: -20,
				Condition: &azureGraphReadOnlyCondition{}},
			{Name: "single-non-prod-sub", Priority: 45, Kind: ModifierKindDelta, Value: -10,
				Condition: &azureSingleNonProdSubCondition{}},
		},
	}
}
