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
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"PUBKEY": []byte("MYPUBKEY"),
		},
		Snippet: types.Snippet{
			Matching: []byte("privkey-uuid"),
		},
	}
	pubKey, privKey, ok := extractAtlasDigestCredentials(m)
	assert.True(t, ok)
	assert.Equal(t, "MYPUBKEY", pubKey)
	assert.Equal(t, "privkey-uuid", privKey)
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

func atlasDigestTestMatch() *types.Match {
	return &types.Match{
		RuleID: "kingfisher.mongodb.1",
		NamedGroups: map[string][]byte{
			"PUBKEY": []byte("MYPUBLICKEY"),
		},
		Snippet: types.Snippet{
			Matching: []byte("4b18315e-6b7d-4337-b449-5d38f5a189ec"),
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
