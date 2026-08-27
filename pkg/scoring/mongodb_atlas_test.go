package scoring

import (
	"context"
	"fmt"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Credential extraction tests
// ---------------------------------------------------------------------------

func TestExtractAtlasDigestCredentials_BothPresent(t *testing.T) {
	// This previously supplied NamedGroups["PUBKEY"], a state the matcher cannot
	// produce: NamedGroups comes only from the matching rule's own regex, and
	// mongodb.yml declares no named capture groups. The fixture made a mechanism
	// that never worked look tested (LAB-6095). The public key now comes from the
	// snippet, which is where it actually is.
	m := &types.Match{
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before:   []byte("ATLAS_PUBLIC_KEY=yhltsvan\nATLAS_PRIVATE_KEY="),
			Matching: []byte("2c130c23-e6b6-4da8-a93f-a8bf33218830"),
		},
	}
	pubKey, privKey, ok := extractAtlasDigestCredentials(m)
	assert.True(t, ok)
	assert.Equal(t, "yhltsvan", pubKey)
	assert.Equal(t, "2c130c23-e6b6-4da8-a93f-a8bf33218830", privKey)
}

func TestExtractAtlasDigestCredentials_MissingPubKey(t *testing.T) {
	m := &types.Match{
		// No PUBKEY in NamedGroups
		Snippet: types.Snippet{
			Matching: []byte("privkey-uuid"),
		},
	}
	_, _, ok := extractAtlasDigestCredentials(m)
	assert.False(t, ok, "should return false when PUBKEY is missing")
}

func TestExtractAtlasServiceAccountToken_Present(t *testing.T) {
	m := &types.Match{
		Snippet: types.Snippet{
			Matching: []byte("mdb_sa_sk_BdIX_jLzut2WTgglKzKvSgWMDDj5hEoTqdwOyLOL"),
		},
	}
	token, ok := extractAtlasServiceAccountToken(m)
	assert.True(t, ok)
	assert.Equal(t, "mdb_sa_sk_BdIX_jLzut2WTgglKzKvSgWMDDj5hEoTqdwOyLOL", token)
}

func TestExtractAtlasServiceAccountToken_Empty(t *testing.T) {
	m := &types.Match{
		Snippet: types.Snippet{
			Matching: []byte(""),
		},
	}
	_, ok := extractAtlasServiceAccountToken(m)
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// IsDynamic tests
// ---------------------------------------------------------------------------

func TestAtlasOrgOwnerCondition_IsDynamic(t *testing.T) {
	cond := &atlasOrgOwnerCondition{}
	mod := Modifier{Condition: cond}
	assert.True(t, mod.IsDynamic())
}

func TestAtlasProjectReadOnlyCondition_IsDynamic(t *testing.T) {
	cond := &atlasProjectReadOnlyCondition{}
	mod := Modifier{Condition: cond}
	assert.True(t, mod.IsDynamic())
}

// ---------------------------------------------------------------------------
// Mock implementation
// ---------------------------------------------------------------------------

type mockAtlasAPI struct {
	orgs        []AtlasOrgMembership
	orgsErr     error
	projects    []AtlasProjectMembership
	projectsErr error
}

func (m *mockAtlasAPI) ListOrgs(_ context.Context) ([]AtlasOrgMembership, error) {
	return m.orgs, m.orgsErr
}

func (m *mockAtlasAPI) ListProjects(_ context.Context) ([]AtlasProjectMembership, error) {
	return m.projects, m.projectsErr
}

func fakeAtlasFactory(api atlasAPI) atlasClientFactory {
	return func(_ context.Context, _ string, _ map[string]string) (atlasAPI, error) {
		return api, nil
	}
}

// atlasDigestTestMatch builds a kingfisher.mongodb.1 match shaped as the
// matcher actually produces one: NamedGroups empty (mongodb.yml declares no
// named capture groups) and the public key present only in the surrounding
// context.
//
// It previously supplied NamedGroups["PUBKEY"], which the matcher can never
// populate. Every test built on this fixture therefore exercised a code path
// that could not run in production (LAB-6095).
func atlasDigestTestMatch() *types.Match {
	return &types.Match{
		RuleID:      "kingfisher.mongodb.1",
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before:   []byte("ATLAS_PUBLIC_KEY=yhltsvan\nATLAS_PRIVATE_KEY="),
			Matching: []byte("2c130c23-e6b6-4da8-a93f-a8bf33218830"),
		},
	}
}

func atlasServiceAccountTestMatch() *types.Match {
	return &types.Match{
		RuleID: "kingfisher.mongodb.4",
		Snippet: types.Snippet{
			Matching: []byte("mdb_sa_sk_BdIX_jLzut2WTgglKzKvSgWMDDj5hEoTqdwOyLOL"),
		},
	}
}

// ---------------------------------------------------------------------------
// atlasOrgOwnerCondition tests
// ---------------------------------------------------------------------------

func TestAtlasOrgOwnerCondition_FiresWhenOrgOwner(t *testing.T) {
	cond := &atlasOrgOwnerCondition{
		clientFactory: fakeAtlasFactory(&mockAtlasAPI{
			orgs: []AtlasOrgMembership{
				{OrgID: "org1", Roles: []string{"ORG_OWNER"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), atlasDigestTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAtlasOrgOwnerCondition_DoesNotFireForMember(t *testing.T) {
	cond := &atlasOrgOwnerCondition{
		clientFactory: fakeAtlasFactory(&mockAtlasAPI{
			orgs: []AtlasOrgMembership{
				{OrgID: "org1", Roles: []string{"ORG_MEMBER"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), atlasDigestTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

// ---------------------------------------------------------------------------
// atlasProjectReadOnlyCondition tests
// ---------------------------------------------------------------------------

func TestAtlasProjectReadOnlyCondition_FiresWhenAllReadOnly(t *testing.T) {
	cond := &atlasProjectReadOnlyCondition{
		clientFactory: fakeAtlasFactory(&mockAtlasAPI{
			projects: []AtlasProjectMembership{
				{GroupID: "p1", Roles: []string{"GROUP_READ_ONLY"}},
				{GroupID: "p2", Roles: []string{"GROUP_DATA_ACCESS_READ_ONLY"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), atlasDigestTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAtlasProjectReadOnlyCondition_DoesNotFireWhenOwner(t *testing.T) {
	cond := &atlasProjectReadOnlyCondition{
		clientFactory: fakeAtlasFactory(&mockAtlasAPI{
			projects: []AtlasProjectMembership{
				{GroupID: "p1", Roles: []string{"GROUP_OWNER"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), atlasDigestTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAtlasProjectReadOnlyCondition_DoesNotFireWhenNoProjects(t *testing.T) {
	cond := &atlasProjectReadOnlyCondition{
		clientFactory: fakeAtlasFactory(&mockAtlasAPI{
			projects: []AtlasProjectMembership{},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), atlasDigestTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAtlasOrgOwnerCondition_FiresWithServiceAccountToken(t *testing.T) {
	cond := &atlasOrgOwnerCondition{
		clientFactory: fakeAtlasFactory(&mockAtlasAPI{
			orgs: []AtlasOrgMembership{
				{OrgID: "org1", Roles: []string{"ORG_OWNER"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), atlasServiceAccountTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

// ---------------------------------------------------------------------------
// Error handling tests
// ---------------------------------------------------------------------------

func TestAtlasOrgOwnerCondition_ReturnsFalseOnError(t *testing.T) {
	cond := &atlasOrgOwnerCondition{
		clientFactory: fakeAtlasFactory(&mockAtlasAPI{
			orgsErr: fmt.Errorf("unauthorized"),
		}),
	}
	fired, err := cond.Evaluate(context.Background(), atlasDigestTestMatch())
	assert.NoError(t, err)
	assert.False(t, fired)
}

// ---------------------------------------------------------------------------
// buildAtlasClient dispatch tests
// ---------------------------------------------------------------------------

func TestBuildAtlasClient_UnknownRuleID_ReturnsNil(t *testing.T) {
	m := &types.Match{
		RuleID: "unknown.rule.99",
	}
	client := buildAtlasClient(context.Background(), m, nil)
	assert.Nil(t, client)
}
