package scoring

import (
	"bytes"
	"context"
	"regexp"

	"github.com/praetorian-inc/titus/pkg/types"
)

// atlasPublicKeyPatterns recover an Atlas programmatic public key from the
// context surrounding a private key match.
//
// An Atlas public key is 8 lowercase letters (e.g. "yhltsvan"), paired with a
// lowercase-UUID private key. Every pattern therefore requires mongodb/atlas or
// an explicit public-key label: [a-z]{8} on its own matches ordinary prose, and
// an unanchored version would pair the private key with any nearby word.
//
// The third form covers `curl --user "{PUBLIC}:{PRIVATE}" --digest`, which is
// how the Atlas documentation demonstrates every API call and which places both
// halves adjacent.
var atlasPublicKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:mongodb|atlas)[_\-.]?(?:public|pub)(?:[_\-.]?key)?\s*[=:]\s*["']?([a-z]{8})\b`),
	regexp.MustCompile(`(?i)\bpublic[_\-.]?key\s*[=:]\s*["']?([a-z]{8})\b`),
	regexp.MustCompile(`--user\s+["']?([a-z]{8}):`),
}

// atlasPrivateKeyPattern is the UUID an Atlas private key consists of.
var atlasPrivateKeyPattern = regexp.MustCompile(`(?i)\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`)

// atlasPrivateKey returns the private key UUID from a kingfisher.mongodb.1 match.
//
// It is NOT Snippet.Matching. That field holds the whole matched span, and the
// rule's pattern deliberately spans from the mongodb/atlas keyword through the
// private-key label to the UUID, so Matching looks like
//
//	ATLAS_PUBLIC_KEY=yhltsvan\nATLAS_PRIVATE_KEY=2c130c23-...-a8bf33218830
//
// Using it directly would authenticate with that entire blob as the password.
//
// Groups holds the positional captures with the full match already stripped
// (extractCaptureGroups starts at index 1), so the rule's single capture lands
// at Groups[0]. The UUID shape is verified rather than assumed, and the matched
// span is searched as a fallback, so this cannot silently pick up the wrong
// value if capture indexing differs between matcher backends.
func atlasPrivateKey(m *types.Match) string {
	for _, g := range m.Groups {
		if v := atlasPrivateKeyPattern.Find(g); v != nil {
			return string(v)
		}
	}
	if v := atlasPrivateKeyPattern.Find(m.Snippet.Matching); v != nil {
		return string(v)
	}
	return ""
}

// extractAtlasDigestCredentials extracts the public and private key pair used
// for kingfisher.mongodb.1 digest authentication.
//
// The public key is a SEPARATE rule's match (kingfisher.mongodb.2), so it can
// never appear in this match's NamedGroups: the matcher populates those only
// from the matching rule's own regex, and mongodb.yml declares no named capture
// groups.
//
// This previously read NamedGroups["PUBKEY"], described in the rule YAML as
// populated by depends_on_rule. No Go code parses depends_on_rule, so the key
// was never present and the digest path never produced credentials -- silently,
// since buildAtlasClient returns nil and the condition then reports (false, nil)
// with no error, warning or stat (LAB-6095).
//
// Pairing from the snippet is how every other split credential in this repo is
// handled: see pkg/validator/helpscout.go for a client ID, and the AWS session
// token extraction in pkg/scoring/aws.go.
//
// When several credential pairs sit within the same snippet, the public key
// NEAREST the private key wins, preferring one that precedes it. Taking the
// first match in the context would pair a private key with an earlier,
// unrelated public key and authenticate with a mismatched pair.
func extractAtlasDigestCredentials(m *types.Match) (pubKey, privKey string, ok bool) {
	if m == nil {
		return "", "", false
	}
	priv := atlasPrivateKey(m)
	if priv == "" {
		return "", "", false
	}

	// Reassemble the contiguous context so candidate positions are comparable.
	ctx := make([]byte, 0, len(m.Snippet.Before)+len(m.Snippet.Matching)+len(m.Snippet.After))
	ctx = append(ctx, m.Snippet.Before...)
	ctx = append(ctx, m.Snippet.Matching...)
	ctx = append(ctx, m.Snippet.After...)

	privPos := bytes.Index(ctx, []byte(priv))
	if privPos < 0 {
		privPos = len(m.Snippet.Before)
	}

	best, bestDist := "", -1
	for _, re := range atlasPublicKeyPatterns {
		for _, loc := range re.FindAllSubmatchIndex(ctx, -1) {
			if len(loc) < 4 || loc[2] < 0 {
				continue
			}
			cand := string(ctx[loc[2]:loc[3]])
			dist := privPos - loc[3]
			if dist < 0 {
				// Candidate follows the private key: same distance measure, but
				// preferred only when nothing precedes it.
				dist = (loc[2] - privPos) + 1
			}
			if bestDist < 0 || dist < bestDist {
				best, bestDist = cand, dist
			}
		}
	}
	if best == "" {
		return "", "", false
	}
	return best, priv, true
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
