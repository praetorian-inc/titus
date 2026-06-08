package scoring

import (
	"context"

	"github.com/praetorian-inc/titus/pkg/types"
)

// extractAtlasDigestCredentials extracts the public and private key pair used
// for kingfisher.mongodb.1 digest authentication.
//
// The private key is the main matched secret (Snippet.Matching).
// The public key is expected in NamedGroups["PUBKEY"] — populated by the
// depends_on_rule mechanism declared in the rule YAML.
func extractAtlasDigestCredentials(m *types.Match) (pubKey, privKey string, ok bool) {
	if m == nil {
		return "", "", false
	}
	pub, hasPub := m.NamedGroups["PUBKEY"]
	priv := m.Snippet.Matching
	if !hasPub || len(pub) == 0 || len(priv) == 0 {
		return "", "", false
	}
	return string(pub), string(priv), true
}

// extractAtlasServiceAccountToken extracts the bearer token used for
// kingfisher.mongodb.4 (service account) authentication.
// The token is the main matched secret (Snippet.Matching).
func extractAtlasServiceAccountToken(m *types.Match) (token string, ok bool) {
	if m == nil {
		return "", false
	}
	tok := m.Snippet.Matching
	if len(tok) == 0 {
		return "", false
	}
	return string(tok), true
}

// buildAtlasClient selects the auth strategy based on m.RuleID and creates a
// client via the given factory. Returns nil on any credential extraction failure.
func buildAtlasClient(ctx context.Context, m *types.Match, factory atlasClientFactory) atlasAPI {
	if factory == nil {
		factory = defaultAtlasClientFactory
	}
	switch m.RuleID {
	case "kingfisher.mongodb.1":
		pub, priv, ok := extractAtlasDigestCredentials(m)
		if !ok {
			return nil
		}
		client, err := factory(ctx, "digest", map[string]string{
			"publicKey":  pub,
			"privateKey": priv,
		})
		if err != nil {
			return nil
		}
		return client
	case "kingfisher.mongodb.4":
		tok, ok := extractAtlasServiceAccountToken(m)
		if !ok {
			return nil
		}
		client, err := factory(ctx, "bearer", map[string]string{
			"token": tok,
		})
		if err != nil {
			return nil
		}
		return client
	default:
		return nil
	}
}

// atlasOrgOwnerCondition fires when the key holds the ORG_OWNER role in any
// organization. Implements networkCondition (requires --score-scope).
type atlasOrgOwnerCondition struct {
	clientFactory atlasClientFactory
}

func (c *atlasOrgOwnerCondition) markDynamic() {}

func (c *atlasOrgOwnerCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	if m == nil {
		return false, nil
	}
	client := buildAtlasClient(ctx, m, c.clientFactory)
	if client == nil {
		return false, nil
	}
	orgs, err := client.ListOrgs(ctx)
	if err != nil {
		return false, nil
	}
	for _, org := range orgs {
		for _, role := range org.Roles {
			if role == "ORG_OWNER" {
				return true, nil
			}
		}
	}
	return false, nil
}

// atlasProjectReadOnlyCondition fires when the key has access to at least one
// project AND every role across every project is read-only.
// Read-only project roles: GROUP_READ_ONLY, GROUP_DATA_ACCESS_READ_ONLY.
// Implements networkCondition (requires --score-scope).
type atlasProjectReadOnlyCondition struct {
	clientFactory atlasClientFactory
}

func (c *atlasProjectReadOnlyCondition) markDynamic() {}

func (c *atlasProjectReadOnlyCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	if m == nil {
		return false, nil
	}
	client := buildAtlasClient(ctx, m, c.clientFactory)
	if client == nil {
		return false, nil
	}
	projects, err := client.ListProjects(ctx)
	if err != nil {
		return false, nil
	}
	if len(projects) == 0 {
		return false, nil
	}
	for _, proj := range projects {
		for _, role := range proj.Roles {
			if !isAtlasReadOnlyProjectRole(role) {
				return false, nil
			}
		}
	}
	return true, nil
}

// isAtlasReadOnlyProjectRole reports whether a project role grants only
// read-level access.
func isAtlasReadOnlyProjectRole(role string) bool {
	switch role {
	case "GROUP_READ_ONLY", "GROUP_DATA_ACCESS_READ_ONLY":
		return true
	default:
		return false
	}
}

// MongoDBAtlasGoScorer returns a *Scorer targeting MongoDB Atlas API key rules.
//
// Targets kingfisher.mongodb.1 (API key pair, digest auth) and
// kingfisher.mongodb.4 (service account token, bearer auth).
//
// Modifiers:
//   - atlas-org-admin (Priority 90, set_score=90): key holds ORG_OWNER on any org.
//   - atlas-project-read-only (Priority 70, delta=-20): key only has read-only project roles.
func MongoDBAtlasGoScorer() *Scorer {
	return &Scorer{
		Name:    "mongodb-atlas-scope",
		RuleIDs: []string{"kingfisher.mongodb.1", "kingfisher.mongodb.4"},
		Modifiers: []Modifier{
			// Dynamic (network, requires --score-scope)
			{
				Name:      "atlas-org-admin",
				Priority:  90,
				Kind:      ModifierKindSetScore,
				Value:     90,
				Condition: &atlasOrgOwnerCondition{},
			},
			{
				Name:      "atlas-project-read-only",
				Priority:  70,
				Kind:      ModifierKindDelta,
				Value:     -20,
				Condition: &atlasProjectReadOnlyCondition{},
			},
		},
	}
}
