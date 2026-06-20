package scoring

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

// extractGCPCredentials extracts service account fields from the match.
// Checks service_account group first, then service_account_nested.
func extractGCPCredentials(m *types.Match) (*gcpServiceAccountKey, bool) {
	if m == nil {
		return nil, false
	}
	for _, group := range []string{"service_account", "service_account_nested"} {
		raw, ok := m.NamedGroups[group]
		if !ok || len(raw) == 0 {
			continue
		}
		var key gcpServiceAccountKey
		if err := json.Unmarshal(raw, &key); err == nil {
			if key.ClientEmail != "" && key.PrivateKey != "" {
				return &key, true
			}
		}
		// Try recursive search for nested JSON objects
		var obj map[string]interface{}
		if err := json.Unmarshal(raw, &obj); err == nil {
			if key := findGCPServiceAccountKey(obj); key != nil {
				return key, true
			}
		}
	}
	return nil, false
}

// findGCPServiceAccountKey recursively searches a JSON object for a nested
// object containing both client_email and private_key string fields.
func findGCPServiceAccountKey(obj map[string]interface{}) *gcpServiceAccountKey {
	email, _ := obj["client_email"].(string)
	privKey, _ := obj["private_key"].(string)
	if email != "" && privKey != "" {
		projectID, _ := obj["project_id"].(string)
		return &gcpServiceAccountKey{
			ProjectID:   projectID,
			ClientEmail: email,
			PrivateKey:  privKey,
		}
	}
	for _, v := range obj {
		nested, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		if key := findGCPServiceAccountKey(nested); key != nil {
			return key
		}
	}
	return nil
}

// gcpSADisabledCondition fires when the service account is disabled.
// Detected by the factory's token exchange failing with a "disabled" error.
type gcpSADisabledCondition struct {
	clientFactory gcpClientFactory
}

func (c *gcpSADisabledCondition) markDynamic() {}

func (c *gcpSADisabledCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	key, ok := extractGCPCredentials(m)
	if !ok {
		return false, nil
	}
	factory := c.clientFactory
	if factory == nil {
		factory = defaultGCPClientFactory
	}
	_, err := factory(ctx, key)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "disabled") {
		return true, nil
	}
	return false, nil
}

// gcpRoleBindingCondition fires when the SA's project IAM bindings match
// specific roles. When onlyIfExclusive is true, ALL of the SA's roles must
// be in matchRoles (used for read-only detection).
type gcpRoleBindingCondition struct {
	matchRoles      []string
	onlyIfExclusive bool
	clientFactory   gcpClientFactory
}

func (c *gcpRoleBindingCondition) markDynamic() {}

func (c *gcpRoleBindingCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	key, ok := extractGCPCredentials(m)
	if !ok {
		return false, nil
	}
	factory := c.clientFactory
	if factory == nil {
		factory = defaultGCPClientFactory
	}
	api, err := factory(ctx, key)
	if err != nil {
		return false, nil
	}

	bindings, err := api.GetProjectIAMPolicy(ctx, key.ProjectID)
	if err != nil {
		return false, nil
	}

	member := "serviceAccount:" + key.ClientEmail
	matchSet := make(map[string]bool, len(c.matchRoles))
	for _, r := range c.matchRoles {
		matchSet[r] = true
	}

	var saRoles []string
	for _, b := range bindings {
		for _, mem := range b.Members {
			if mem == member {
				saRoles = append(saRoles, b.Role)
				break
			}
		}
	}

	if len(saRoles) == 0 {
		return false, nil
	}

	if c.onlyIfExclusive {
		for _, role := range saRoles {
			if !matchSet[role] {
				return false, nil
			}
		}
		return true, nil
	}

	for _, role := range saRoles {
		if matchSet[role] {
			return true, nil
		}
	}
	return false, nil
}

// gcpOrgLevelBindingCondition fires when the SA has any binding at the org level.
type gcpOrgLevelBindingCondition struct {
	clientFactory gcpClientFactory
}

func (c *gcpOrgLevelBindingCondition) markDynamic() {}

func (c *gcpOrgLevelBindingCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	key, ok := extractGCPCredentials(m)
	if !ok {
		return false, nil
	}
	factory := c.clientFactory
	if factory == nil {
		factory = defaultGCPClientFactory
	}
	api, err := factory(ctx, key)
	if err != nil {
		return false, nil
	}

	bindings, err := api.GetOrgIAMPolicy(ctx, key.ProjectID)
	if err != nil {
		return false, nil
	}

	member := "serviceAccount:" + key.ClientEmail
	for _, b := range bindings {
		for _, mem := range b.Members {
			if mem == member {
				return true, nil
			}
		}
	}
	return false, nil
}

// gcpMultiProjectCondition fires when the SA can access minProjects or more projects.
type gcpMultiProjectCondition struct {
	minProjects   int
	clientFactory gcpClientFactory
}

func (c *gcpMultiProjectCondition) markDynamic() {}

func (c *gcpMultiProjectCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	key, ok := extractGCPCredentials(m)
	if !ok {
		return false, nil
	}
	factory := c.clientFactory
	if factory == nil {
		factory = defaultGCPClientFactory
	}
	api, err := factory(ctx, key)
	if err != nil {
		return false, nil
	}

	count, err := api.CountAccessibleProjects(ctx)
	if err != nil {
		return false, nil
	}
	return count >= c.minProjects, nil
}

// gcpSingleNonProdCondition fires when the SA is scoped to exactly one project
// and that project appears to be non-production.
type gcpSingleNonProdCondition struct {
	clientFactory gcpClientFactory
}

func (c *gcpSingleNonProdCondition) markDynamic() {}

var nonProdPatterns = []string{
	"dev", "test", "staging", "sandbox", "nonprod", "non-prod", "demo", "tmp", "temp",
}

func (c *gcpSingleNonProdCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	key, ok := extractGCPCredentials(m)
	if !ok {
		return false, nil
	}
	factory := c.clientFactory
	if factory == nil {
		factory = defaultGCPClientFactory
	}
	api, err := factory(ctx, key)
	if err != nil {
		return false, nil
	}

	count, err := api.CountAccessibleProjects(ctx)
	if err != nil {
		return false, nil
	}
	if count != 1 {
		return false, nil
	}

	lower := strings.ToLower(key.ProjectID)
	for _, pat := range nonProdPatterns {
		if strings.Contains(lower, pat) {
			return true, nil
		}
	}
	return false, nil
}

// GCPGoScorer returns a *Scorer targeting the GCP service account key rule.
func GCPGoScorer() *Scorer {
	return &Scorer{
		Name:    "gcp-sa-iam-scope",
		RuleIDs: []string{"kingfisher.gcp.1"},
		Modifiers: []Modifier{
			{Name: "sa-disabled", Priority: 100, Kind: ModifierKindSetScore, Value: 5, Condition: &gcpSADisabledCondition{}},
			{Name: "owner-or-org-admin", Priority: 95, Kind: ModifierKindSetScore, Value: 99,
				Condition: &gcpRoleBindingCondition{matchRoles: []string{"roles/owner", "roles/resourcemanager.organizationAdmin"}}},
			{Name: "priv-escalation-path", Priority: 85, Kind: ModifierKindDelta, Value: 20,
				Condition: &gcpRoleBindingCondition{matchRoles: []string{"roles/iam.serviceAccountAdmin", "roles/iam.securityAdmin"}}},
			{Name: "secret-accessor", Priority: 80, Kind: ModifierKindDelta, Value: 15,
				Condition: &gcpRoleBindingCondition{matchRoles: []string{"roles/secretmanager.secretAccessor"}}},
			{Name: "storage-db-admin", Priority: 75, Kind: ModifierKindDelta, Value: 15,
				Condition: &gcpRoleBindingCondition{matchRoles: []string{"roles/storage.admin", "roles/cloudsql.admin"}}},
			{Name: "org-level-binding", Priority: 70, Kind: ModifierKindDelta, Value: 15, Condition: &gcpOrgLevelBindingCondition{}},
			{Name: "multi-project-access", Priority: 65, Kind: ModifierKindDelta, Value: 10,
				Condition: &gcpMultiProjectCondition{minProjects: 5}},
			{Name: "viewer-only", Priority: 60, Kind: ModifierKindDelta, Value: -20,
				Condition: &gcpRoleBindingCondition{matchRoles: []string{"roles/viewer", "roles/browser"}, onlyIfExclusive: true}},
			{Name: "observability-only", Priority: 55, Kind: ModifierKindDelta, Value: -15,
				Condition: &gcpRoleBindingCondition{matchRoles: []string{"roles/logging.viewer", "roles/monitoring.viewer"}, onlyIfExclusive: true}},
			{Name: "single-non-prod-project", Priority: 50, Kind: ModifierKindDelta, Value: -10, Condition: &gcpSingleNonProdCondition{}},
		},
	}
}
