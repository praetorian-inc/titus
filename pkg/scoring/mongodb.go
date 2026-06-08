package scoring

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

// extractMongoCredentialsNP extracts from np.mongodb.1 named groups (username,
// password, host). Reconstructs a mongodb:// URI from parts.
func extractMongoCredentialsNP(m *types.Match) (uri string, ok bool) {
	if m == nil {
		return "", false
	}
	username, hasUser := m.NamedGroups["username"]
	password, hasPass := m.NamedGroups["password"]
	host, hasHost := m.NamedGroups["host"]
	if !hasUser || !hasPass || !hasHost || len(username) == 0 || len(password) == 0 || len(host) == 0 {
		return "", false
	}
	return fmt.Sprintf("mongodb://%s:%s@%s", username, password, host), true
}

// extractMongoCredentialsKF extracts from kingfisher.mongodb.3 (full URI in
// the matched snippet). The whole match is the URI.
func extractMongoCredentialsKF(m *types.Match) (uri string, ok bool) {
	if m == nil {
		return "", false
	}
	raw := m.Snippet.Matching
	if len(raw) == 0 {
		return "", false
	}
	u := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(u, "mongodb") {
		return "", false
	}
	return u, true
}

// extractMongoURI tries both extraction paths, returning the first that succeeds.
func extractMongoURI(m *types.Match) (string, bool) {
	if uri, ok := extractMongoCredentialsNP(m); ok {
		return uri, true
	}
	return extractMongoCredentialsKF(m)
}

// mongoRoleCondition fires when any authenticated role matches a set of role names.
type mongoRoleCondition struct {
	matchRoles    []string
	clientFactory mongoClientFactory
}

func (c *mongoRoleCondition) markDynamic() {}

func (c *mongoRoleCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	uri, ok := extractMongoURI(m)
	if !ok {
		return false, nil
	}

	factory := c.clientFactory
	if factory == nil {
		factory = defaultMongoClientFactory
	}
	client, cleanup, err := factory(ctx, uri)
	if err != nil {
		return false, nil
	}
	defer cleanup()

	status, err := client.ConnectionStatus(ctx)
	if err != nil {
		return false, nil
	}

	matchSet := make(map[string]bool, len(c.matchRoles))
	for _, r := range c.matchRoles {
		matchSet[r] = true
	}
	for _, role := range status.AuthenticatedRoles {
		if matchSet[role.Role] {
			return true, nil
		}
	}
	return false, nil
}

// mongoAdminDBCondition fires when the admin database is accessible.
type mongoAdminDBCondition struct {
	clientFactory mongoClientFactory
}

func (c *mongoAdminDBCondition) markDynamic() {}

func (c *mongoAdminDBCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	uri, ok := extractMongoURI(m)
	if !ok {
		return false, nil
	}

	factory := c.clientFactory
	if factory == nil {
		factory = defaultMongoClientFactory
	}
	client, cleanup, err := factory(ctx, uri)
	if err != nil {
		return false, nil
	}
	defer cleanup()

	dbs, err := client.ListDatabases(ctx)
	if err != nil {
		return false, nil
	}
	for _, db := range dbs {
		if db == "admin" {
			return true, nil
		}
	}
	return false, nil
}

// mongoSensitiveDBCondition fires when any database name matches a sensitive pattern.
type mongoSensitiveDBCondition struct {
	pattern       *regexp.Regexp
	clientFactory mongoClientFactory
}

func (c *mongoSensitiveDBCondition) markDynamic() {}

func (c *mongoSensitiveDBCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	uri, ok := extractMongoURI(m)
	if !ok {
		return false, nil
	}

	factory := c.clientFactory
	if factory == nil {
		factory = defaultMongoClientFactory
	}
	client, cleanup, err := factory(ctx, uri)
	if err != nil {
		return false, nil
	}
	defer cleanup()

	dbs, err := client.ListDatabases(ctx)
	if err != nil {
		return false, nil
	}
	for _, db := range dbs {
		if c.pattern.MatchString(db) {
			return true, nil
		}
	}
	return false, nil
}

// prodPatternMongoDB matches production-like database name prefixes.
var prodPatternMongoDB = regexp.MustCompile(`(?i)prod|staging|production`)

// mongoReadOnlySingleDBCondition fires when the user has only the read role on
// a single non-production database.
type mongoReadOnlySingleDBCondition struct {
	clientFactory mongoClientFactory
}

func (c *mongoReadOnlySingleDBCondition) markDynamic() {}

func (c *mongoReadOnlySingleDBCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	uri, ok := extractMongoURI(m)
	if !ok {
		return false, nil
	}

	factory := c.clientFactory
	if factory == nil {
		factory = defaultMongoClientFactory
	}
	client, cleanup, err := factory(ctx, uri)
	if err != nil {
		return false, nil
	}
	defer cleanup()

	status, err := client.ConnectionStatus(ctx)
	if err != nil {
		return false, nil
	}

	if len(status.AuthenticatedRoles) != 1 {
		return false, nil
	}
	role := status.AuthenticatedRoles[0]
	if role.Role != "read" {
		return false, nil
	}
	if prodPatternMongoDB.MatchString(role.DB) {
		return false, nil
	}
	return true, nil
}

// mongoWriteRoles is the set of roles indicating write or elevated privileges.
var mongoWriteRoles = map[string]bool{
	"readWrite":              true,
	"readWriteAnyDatabase":   true,
	"dbAdmin":                true,
	"dbAdminAnyDatabase":     true,
	"dbOwner":                true,
	"userAdmin":              true,
	"userAdminAnyDatabase":   true,
	"root":                   true,
	"__system":               true,
}

// mongoReadAnyNoWriteCondition fires when the user has readAnyDatabase but no
// write roles.
type mongoReadAnyNoWriteCondition struct {
	clientFactory mongoClientFactory
}

func (c *mongoReadAnyNoWriteCondition) markDynamic() {}

func (c *mongoReadAnyNoWriteCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	uri, ok := extractMongoURI(m)
	if !ok {
		return false, nil
	}

	factory := c.clientFactory
	if factory == nil {
		factory = defaultMongoClientFactory
	}
	client, cleanup, err := factory(ctx, uri)
	if err != nil {
		return false, nil
	}
	defer cleanup()

	status, err := client.ConnectionStatus(ctx)
	if err != nil {
		return false, nil
	}

	hasReadAny := false
	for _, role := range status.AuthenticatedRoles {
		if role.Role == "readAnyDatabase" {
			hasReadAny = true
		}
		if mongoWriteRoles[role.Role] {
			return false, nil
		}
	}
	return hasReadAny, nil
}

// MongoDBGoScorer returns a *Scorer targeting MongoDB credential rules.
func MongoDBGoScorer() *Scorer {
	return &Scorer{
		Name:    "mongodb-role-scope",
		RuleIDs: []string{"np.mongodb.1", "kingfisher.mongodb.3"},
		Modifiers: []Modifier{
			// Static: Atlas-hosted indicator (np.mongodb.1 only — kingfisher.mongodb.3
			// captures the full URI in Snippet.Matching, not named groups)
			{
				Name:     "srv-scheme",
				Priority: 100,
				Kind:     ModifierKindDelta,
				Value:    5,
				Condition: &matchGroupCondition{
					Name:  "host",
					Regex: regexp.MustCompile(`\.mongodb\.net$`),
				},
			},
			// Dynamic (network, requires --score-scope)
			{
				Name:     "root-or-system-role",
				Priority: 90,
				Kind:     ModifierKindSetScore,
				Value:    99,
				Condition: &mongoRoleCondition{
					matchRoles: []string{"root", "__system"},
				},
			},
			{
				Name:     "user-admin-any-db",
				Priority: 85,
				Kind:     ModifierKindSetScore,
				Value:    90,
				Condition: &mongoRoleCondition{
					matchRoles: []string{"userAdminAnyDatabase"},
				},
			},
			{
				Name:     "admin-db-access",
				Priority: 80,
				Kind:     ModifierKindDelta,
				Value:    15,
				Condition: &mongoAdminDBCondition{},
			},
			{
				Name:     "sensitive-db-names",
				Priority: 75,
				Kind:     ModifierKindDelta,
				Value:    10,
				Condition: &mongoSensitiveDBCondition{
					pattern: regexp.MustCompile(`(?i)prod|customer|pii|payment`),
				},
			},
			{
				Name:     "read-only-single-db",
				Priority: 70,
				Kind:     ModifierKindDelta,
				Value:    -25,
				Condition: &mongoReadOnlySingleDBCondition{},
			},
			{
				Name:     "read-any-no-write",
				Priority: 65,
				Kind:     ModifierKindDelta,
				Value:    -15,
				Condition: &mongoReadAnyNoWriteCondition{},
			},
		},
	}
}
