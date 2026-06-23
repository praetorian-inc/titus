package scoring

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockAzureAPI struct {
	subscriptions      []azureSubscription
	roleAssignments    map[string][]azureRoleAssignment
	directoryRoles     []string
	appRoleAssignments []azureAppRoleAssignment
	subsErr            error
	roleErr            error
	dirRoleErr         error
	appRoleErr         error
}

func (m *mockAzureAPI) ListSubscriptions(_ context.Context) ([]azureSubscription, error) {
	return m.subscriptions, m.subsErr
}

func (m *mockAzureAPI) ListRoleAssignments(_ context.Context, subscriptionID string) ([]azureRoleAssignment, error) {
	if m.roleErr != nil {
		return nil, m.roleErr
	}
	return m.roleAssignments[subscriptionID], nil
}

func (m *mockAzureAPI) GetDirectoryRoleMemberships(_ context.Context) ([]string, error) {
	return m.directoryRoles, m.dirRoleErr
}

func (m *mockAzureAPI) GetAppRoleAssignments(_ context.Context) ([]azureAppRoleAssignment, error) {
	return m.appRoleAssignments, m.appRoleErr
}

func fakeAzureFactory(api azureAPI) azureClientFactory {
	return func(_ context.Context, _ *azureCredentials) (azureAPI, error) {
		return api, nil
	}
}

func fakeAzureFactoryErr(err error) azureClientFactory {
	return func(_ context.Context, _ *azureCredentials) (azureAPI, error) {
		return nil, err
	}
}

func azureTestMatch() *types.Match {
	return &types.Match{
		NamedGroups: map[string][]byte{
			"client_secret": []byte("ArE8Q~1pQL_W_8IZiTnG6TNB-.kGWlfzN61fUa2U"),
		},
		Snippet: types.Snippet{
			Before:   []byte("AZURE_TENANT_ID=12345678-1234-1234-1234-123456789abc\nAZURE_CLIENT_ID=87654321-4321-4321-4321-cba987654321\n"),
			Matching: []byte("AZURE_CLIENT_SECRET=ArE8Q~1pQL_W_8IZiTnG6TNB-.kGWlfzN61fUa2U"),
			After:    []byte("\n"),
		},
	}
}

func azureIncompleteMatch() *types.Match {
	return &types.Match{
		NamedGroups: map[string][]byte{
			"client_secret": []byte("ArE8Q~1pQL_W_8IZiTnG6TNB-.kGWlfzN61fUa2U"),
		},
		Snippet: types.Snippet{
			Before:   []byte("some unrelated context\n"),
			Matching: []byte("ArE8Q~1pQL_W_8IZiTnG6TNB-.kGWlfzN61fUa2U"),
			After:    []byte("\n"),
		},
	}
}

// --- extractAzureCredentials tests ---

func TestExtractAzureCredentials_Complete(t *testing.T) {
	creds, ok := extractAzureCredentials(azureTestMatch())
	require.True(t, ok)
	assert.Equal(t, "12345678-1234-1234-1234-123456789abc", creds.TenantID)
	assert.Equal(t, "87654321-4321-4321-4321-cba987654321", creds.ClientID)
	assert.Equal(t, "ArE8Q~1pQL_W_8IZiTnG6TNB-.kGWlfzN61fUa2U", creds.ClientSecret)
	assert.True(t, creds.complete())
}

func TestExtractAzureCredentials_Incomplete(t *testing.T) {
	creds, ok := extractAzureCredentials(azureIncompleteMatch())
	require.True(t, ok)
	assert.Equal(t, "", creds.TenantID)
	assert.Equal(t, "", creds.ClientID)
	assert.False(t, creds.complete())
}

func TestExtractAzureCredentials_NilMatch(t *testing.T) {
	_, ok := extractAzureCredentials(nil)
	assert.False(t, ok)
}

func TestExtractAzureCredentials_MissingSecret(t *testing.T) {
	m := &types.Match{NamedGroups: map[string][]byte{}}
	_, ok := extractAzureCredentials(m)
	assert.False(t, ok)
}

func TestExtractAzureCredentials_ARMEnvVars(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{"client_secret": []byte("test-secret")},
		Snippet: types.Snippet{
			Before:   []byte("ARM_TENANT_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\nARM_CLIENT_ID=11111111-2222-3333-4444-555555555555\n"),
			Matching: []byte("ARM_CLIENT_SECRET=test-secret"),
		},
	}
	creds, ok := extractAzureCredentials(m)
	require.True(t, ok)
	assert.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", creds.TenantID)
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", creds.ClientID)
}

func TestExtractAzureCredentials_JSONFormat(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{"client_secret": []byte("test-secret")},
		Snippet: types.Snippet{
			Before:   []byte("\"tenant_id\": \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\",\n\"client_id\": \"11111111-2222-3333-4444-555555555555\",\n"),
			Matching: []byte("\"client_secret\": \"test-secret\""),
		},
	}
	creds, ok := extractAzureCredentials(m)
	require.True(t, ok)
	assert.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", creds.TenantID)
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", creds.ClientID)
}

func TestExtractAzureCredentials_InAfterContext(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{"client_secret": []byte("test-secret")},
		Snippet: types.Snippet{
			Matching: []byte("AZURE_CLIENT_SECRET=test-secret"),
			After:    []byte("\nAZURE_TENANT_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\nAZURE_CLIENT_ID=11111111-2222-3333-4444-555555555555"),
		},
	}
	creds, ok := extractAzureCredentials(m)
	require.True(t, ok)
	assert.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", creds.TenantID)
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", creds.ClientID)
}

func TestExtractAzureCredentials_TerraformFormat(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{"client_secret": []byte("test-secret")},
		Snippet: types.Snippet{
			Before: []byte("  tenant_id     = \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"\n  client_id     = \"11111111-2222-3333-4444-555555555555\"\n"),
			Matching: []byte("  client_secret = \"test-secret\""),
		},
	}
	creds, ok := extractAzureCredentials(m)
	require.True(t, ok)
	assert.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", creds.TenantID)
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", creds.ClientID)
}

func TestExtractAzureCredentials_CamelCase(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{"client_secret": []byte("test-secret")},
		Snippet: types.Snippet{
			Before: []byte("\"tenantId\": \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\",\n\"clientId\": \"11111111-2222-3333-4444-555555555555\",\n"),
			Matching: []byte("\"clientSecret\": \"test-secret\""),
		},
	}
	creds, ok := extractAzureCredentials(m)
	require.True(t, ok)
	assert.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", creds.TenantID)
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", creds.ClientID)
}

func TestExtractAzureCredentials_AppIdVariant(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{"client_secret": []byte("test-secret")},
		Snippet: types.Snippet{
			Before: []byte("tenant_id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\napp_id=11111111-2222-3333-4444-555555555555\n"),
			Matching: []byte("AZURE_CLIENT_SECRET=test-secret"),
		},
	}
	creds, ok := extractAzureCredentials(m)
	require.True(t, ok)
	assert.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", creds.TenantID)
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", creds.ClientID)
}

// --- isSubscriptionScope tests ---

func TestIsSubscriptionScope(t *testing.T) {
	tests := []struct {
		scope string
		want  bool
	}{
		{"/subscriptions/12345678-1234-1234-1234-123456789abc", true},
		{"/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/rg1", false},
		{"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1", false},
		{"/", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.scope, func(t *testing.T) {
			assert.Equal(t, tc.want, isSubscriptionScope(tc.scope))
		})
	}
}

func TestIsAtOrAboveSubscriptionScope(t *testing.T) {
	tests := []struct {
		scope string
		want  bool
	}{
		// Subscription scope
		{"/subscriptions/12345678-1234-1234-1234-123456789abc", true},
		// Management group scopes
		{"/providers/Microsoft.Management/managementGroups/my-mg", true},
		{"/providers/Microsoft.Management/managementGroups/root-mg-group", true},
		// Resource group (below subscription)
		{"/subscriptions/sub1/resourceGroups/rg1", false},
		// Deep resource scope
		{"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1", false},
		// Edge cases
		{"/", false},
		{"", false},
		// Not a management group even though it has providers prefix
		{"/providers/Microsoft.Compute/virtualMachines/vm1", false},
	}
	for _, tc := range tests {
		t.Run(tc.scope, func(t *testing.T) {
			assert.Equal(t, tc.want, isAtOrAboveSubscriptionScope(tc.scope))
		})
	}
}

// --- Condition unit tests ---

func TestAzureIncompleteCredentials_FiresWhenMissingIDs(t *testing.T) {
	cond := &azureIncompleteCredentialsCondition{}
	fired, err := cond.Evaluate(context.Background(), azureIncompleteMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAzureIncompleteCredentials_DoesNotFireWhenComplete(t *testing.T) {
	cond := &azureIncompleteCredentialsCondition{}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureIncompleteCredentials_DoesNotFireWhenNoSecret(t *testing.T) {
	cond := &azureIncompleteCredentialsCondition{}
	m := &types.Match{NamedGroups: map[string][]byte{}}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureExpiredCondition_IsDynamic(t *testing.T) {
	mod := Modifier{Condition: &azureExpiredCondition{}}
	assert.True(t, mod.IsDynamic())
}

func TestAzureExpiredCondition_FiresOnAADSTSError(t *testing.T) {
	cond := &azureExpiredCondition{
		clientFactory: fakeAzureFactoryErr(errors.New("invalid_client: AADSTS7000215: Invalid client secret")),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAzureExpiredCondition_FiresOnAADSTS700016(t *testing.T) {
	cond := &azureExpiredCondition{
		clientFactory: fakeAzureFactoryErr(errors.New("unauthorized_client: AADSTS700016: Application not found")),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAzureExpiredCondition_DoesNotFireWhenActive(t *testing.T) {
	cond := &azureExpiredCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureExpiredCondition_DoesNotFireOnNetworkError(t *testing.T) {
	cond := &azureExpiredCondition{
		clientFactory: fakeAzureFactoryErr(errors.New("connection refused")),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureExpiredCondition_DoesNotFireOnIncompleteCredentials(t *testing.T) {
	cond := &azureExpiredCondition{
		clientFactory: fakeAzureFactoryErr(errors.New("AADSTS7000215: Invalid client secret")),
	}
	fired, err := cond.Evaluate(context.Background(), azureIncompleteMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureGlobalAdminCondition_FiresWhenGlobalAdmin(t *testing.T) {
	cond := &azureGlobalAdminCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			directoryRoles: []string{azureDirRoleGlobalAdmin},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAzureGlobalAdminCondition_FiresWhenPrivRoleAdmin(t *testing.T) {
	cond := &azureGlobalAdminCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			directoryRoles: []string{azureDirRolePrivRoleAdmin},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAzureGlobalAdminCondition_DoesNotFireWithoutAdminRoles(t *testing.T) {
	cond := &azureGlobalAdminCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			directoryRoles: []string{"some-other-role-template-id"},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureGlobalAdminCondition_DoesNotFireOnGraphError(t *testing.T) {
	cond := &azureGlobalAdminCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			dirRoleErr: fmt.Errorf("insufficient privileges"),
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureRBACCondition_OwnerAtSubLevel(t *testing.T) {
	cond := &azureRBACCondition{
		matchRoles:        []string{azureRoleOwner},
		subscriptionLevel: true,
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "sub1", DisplayName: "Production"}},
			roleAssignments: map[string][]azureRoleAssignment{
				"sub1": {{RoleDefinitionID: azureRoleOwner, Scope: "/subscriptions/sub1"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAzureRBACCondition_OwnerAtRGLevelDoesNotMatchSubLevel(t *testing.T) {
	cond := &azureRBACCondition{
		matchRoles:        []string{azureRoleOwner},
		subscriptionLevel: true,
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "sub1"}},
			roleAssignments: map[string][]azureRoleAssignment{
				"sub1": {{RoleDefinitionID: azureRoleOwner, Scope: "/subscriptions/sub1/resourceGroups/rg1"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureRBACCondition_ContributorExcludesOwner(t *testing.T) {
	cond := &azureRBACCondition{
		matchRoles:        []string{azureRoleContributor},
		excludeRoles:      []string{azureRoleOwner},
		subscriptionLevel: true,
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "sub1"}},
			roleAssignments: map[string][]azureRoleAssignment{
				"sub1": {
					{RoleDefinitionID: azureRoleOwner, Scope: "/subscriptions/sub1"},
					{RoleDefinitionID: azureRoleContributor, Scope: "/subscriptions/sub1"},
				},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureRBACCondition_ContributorWithoutOwner(t *testing.T) {
	cond := &azureRBACCondition{
		matchRoles:        []string{azureRoleContributor},
		excludeRoles:      []string{azureRoleOwner},
		subscriptionLevel: true,
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "sub1"}},
			roleAssignments: map[string][]azureRoleAssignment{
				"sub1": {{RoleDefinitionID: azureRoleContributor, Scope: "/subscriptions/sub1"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAzureRBACCondition_KeyVaultRoles(t *testing.T) {
	for _, roleID := range []string{azureRoleKVAdmin, azureRoleKVSecretsOfficer, azureRoleKVSecretsUser} {
		t.Run(roleID, func(t *testing.T) {
			cond := &azureRBACCondition{
				matchRoles: []string{azureRoleKVAdmin, azureRoleKVSecretsOfficer, azureRoleKVSecretsUser},
				clientFactory: fakeAzureFactory(&mockAzureAPI{
					subscriptions: []azureSubscription{{ID: "sub1"}},
					roleAssignments: map[string][]azureRoleAssignment{
						"sub1": {{RoleDefinitionID: roleID, Scope: "/subscriptions/sub1/resourceGroups/rg1"}},
					},
				}),
			}
			fired, err := cond.Evaluate(context.Background(), azureTestMatch())
			require.NoError(t, err)
			assert.True(t, fired)
		})
	}
}

func TestAzureRBACCondition_ReaderOnlyRGLevel(t *testing.T) {
	cond := &azureRBACCondition{
		matchRoles:      []string{azureRoleReader},
		onlyIfExclusive: true,
		resourceGroupOnly: true,
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "sub1"}},
			roleAssignments: map[string][]azureRoleAssignment{
				"sub1": {{RoleDefinitionID: azureRoleReader, Scope: "/subscriptions/sub1/resourceGroups/rg1"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAzureRBACCondition_ReaderAtSubLevelDoesNotMatchRGOnly(t *testing.T) {
	cond := &azureRBACCondition{
		matchRoles:        []string{azureRoleReader},
		onlyIfExclusive:   true,
		resourceGroupOnly: true,
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "sub1"}},
			roleAssignments: map[string][]azureRoleAssignment{
				"sub1": {{RoleDefinitionID: azureRoleReader, Scope: "/subscriptions/sub1"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureRBACCondition_ReaderPlusOtherRoleNotExclusive(t *testing.T) {
	cond := &azureRBACCondition{
		matchRoles:        []string{azureRoleReader},
		onlyIfExclusive:   true,
		resourceGroupOnly: true,
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "sub1"}},
			roleAssignments: map[string][]azureRoleAssignment{
				"sub1": {
					{RoleDefinitionID: azureRoleReader, Scope: "/subscriptions/sub1/resourceGroups/rg1"},
					{RoleDefinitionID: azureRoleContributor, Scope: "/subscriptions/sub1/resourceGroups/rg2"},
				},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureRBACCondition_SkipsWhenGlobalAdmin(t *testing.T) {
	cond := &azureRBACCondition{
		matchRoles:          []string{azureRoleOwner},
		subscriptionLevel:   true,
		skipIfPrivilegedDir: true,
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "sub1"}},
			roleAssignments: map[string][]azureRoleAssignment{
				"sub1": {{RoleDefinitionID: azureRoleOwner, Scope: "/subscriptions/sub1"}},
			},
			directoryRoles: []string{azureDirRoleGlobalAdmin},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureRBACCondition_NoAssignments(t *testing.T) {
	cond := &azureRBACCondition{
		matchRoles: []string{azureRoleOwner},
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions:   []azureSubscription{{ID: "sub1"}},
			roleAssignments: map[string][]azureRoleAssignment{"sub1": {}},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureRBACCondition_NoSubscriptions(t *testing.T) {
	cond := &azureRBACCondition{
		matchRoles: []string{azureRoleOwner},
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureRBACCondition_ReturnsFalseOnSubscriptionError(t *testing.T) {
	cond := &azureRBACCondition{
		matchRoles: []string{azureRoleOwner},
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subsErr: fmt.Errorf("permission denied"),
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureRBACCondition_SkipsBadSubscriptionGracefully(t *testing.T) {
	calls := 0
	cond := &azureRBACCondition{
		matchRoles:        []string{azureRoleOwner},
		subscriptionLevel: true,
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "sub1"}, {ID: "sub2"}},
			roleAssignments: map[string][]azureRoleAssignment{
				"sub2": {{RoleDefinitionID: azureRoleOwner, Scope: "/subscriptions/sub2"}},
			},
			roleErr: nil,
		}),
	}
	_ = calls
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAzureMultiSubCondition_FiresAtThreshold(t *testing.T) {
	for _, tc := range []struct {
		count int
		want  bool
	}{
		{2, false},
		{3, true},
		{4, true},
	} {
		t.Run(fmt.Sprintf("count=%d", tc.count), func(t *testing.T) {
			subs := make([]azureSubscription, tc.count)
			for i := range subs {
				subs[i] = azureSubscription{ID: fmt.Sprintf("sub%d", i)}
			}
			cond := &azureMultiSubCondition{
				minSubs:       3,
				clientFactory: fakeAzureFactory(&mockAzureAPI{subscriptions: subs}),
			}
			fired, err := cond.Evaluate(context.Background(), azureTestMatch())
			require.NoError(t, err)
			assert.Equal(t, tc.want, fired)
		})
	}
}

func TestAzureMultiSubCondition_ReturnsFalseOnError(t *testing.T) {
	cond := &azureMultiSubCondition{
		minSubs:       3,
		clientFactory: fakeAzureFactory(&mockAzureAPI{subsErr: fmt.Errorf("permission denied")}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureGraphReadOnlyCondition_FiresWhenNoAppRoles(t *testing.T) {
	cond := &azureGraphReadOnlyCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			appRoleAssignments: []azureAppRoleAssignment{},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAzureGraphReadOnlyCondition_FiresWhenOnlyUserRead(t *testing.T) {
	cond := &azureGraphReadOnlyCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			appRoleAssignments: []azureAppRoleAssignment{
				{AppRoleID: "df021288-bdef-4463-88db-98f22de89214", ResourceDisplayName: "Microsoft Graph"},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAzureGraphReadOnlyCondition_DoesNotFireWithPowerfulRoles(t *testing.T) {
	cond := &azureGraphReadOnlyCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			appRoleAssignments: []azureAppRoleAssignment{
				{AppRoleID: "df021288-bdef-4463-88db-98f22de89214", ResourceDisplayName: "Microsoft Graph"},
				{AppRoleID: "62a82d76-70ea-41e2-9197-370581804d09", ResourceDisplayName: "Microsoft Graph"},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureGraphReadOnlyCondition_SkipsWhenGlobalAdmin(t *testing.T) {
	cond := &azureGraphReadOnlyCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			appRoleAssignments: []azureAppRoleAssignment{},
			directoryRoles:     []string{azureDirRoleGlobalAdmin},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureGraphReadOnlyCondition_DoesNotFireOnGraphError(t *testing.T) {
	cond := &azureGraphReadOnlyCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			appRoleErr: fmt.Errorf("no graph token"),
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureGraphReadOnlyCondition_DoesNotFireWhenNonReaderARMRole(t *testing.T) {
	cond := &azureGraphReadOnlyCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "sub1"}},
			roleAssignments: map[string][]azureRoleAssignment{
				"sub1": {{RoleDefinitionID: azureRoleContributor, Scope: "/subscriptions/sub1"}},
			},
			appRoleAssignments: []azureAppRoleAssignment{
				{AppRoleID: "df021288-bdef-4463-88db-98f22de89214", ResourceDisplayName: "Microsoft Graph"},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureGraphReadOnlyCondition_FiresWhenOnlyReaderARMRole(t *testing.T) {
	cond := &azureGraphReadOnlyCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "sub1"}},
			roleAssignments: map[string][]azureRoleAssignment{
				"sub1": {{RoleDefinitionID: azureRoleReader, Scope: "/subscriptions/sub1"}},
			},
			appRoleAssignments: []azureAppRoleAssignment{
				{AppRoleID: "df021288-bdef-4463-88db-98f22de89214", ResourceDisplayName: "Microsoft Graph"},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAzureSingleNonProdSubCondition_FiresForDevSub(t *testing.T) {
	cond := &azureSingleNonProdSubCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "sub1", DisplayName: "my-dev-subscription"}},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestAzureSingleNonProdSubCondition_DoesNotFireForProd(t *testing.T) {
	cond := &azureSingleNonProdSubCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "sub1", DisplayName: "Production"}},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureSingleNonProdSubCondition_DoesNotFireForMultipleSubs(t *testing.T) {
	cond := &azureSingleNonProdSubCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions: []azureSubscription{{ID: "s1", DisplayName: "dev"}, {ID: "s2", DisplayName: "staging"}},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAzureSingleNonProdSubCondition_AllPatterns(t *testing.T) {
	for _, pat := range nonProdPatterns {
		t.Run(pat, func(t *testing.T) {
			cond := &azureSingleNonProdSubCondition{
				clientFactory: fakeAzureFactory(&mockAzureAPI{
					subscriptions: []azureSubscription{{ID: "sub1", DisplayName: "my-" + pat + "-sub"}},
				}),
			}
			fired, err := cond.Evaluate(context.Background(), azureTestMatch())
			require.NoError(t, err)
			assert.True(t, fired, "pattern %q should fire", pat)
		})
	}
}

func TestAzureSingleNonProdSubCondition_SkipsWhenGlobalAdmin(t *testing.T) {
	cond := &azureSingleNonProdSubCondition{
		clientFactory: fakeAzureFactory(&mockAzureAPI{
			subscriptions:  []azureSubscription{{ID: "sub1", DisplayName: "my-dev-sub"}},
			directoryRoles: []string{azureDirRoleGlobalAdmin},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), azureTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

// --- injectAzureFactory helper ---

func injectAzureFactory(m *Modifier, factory azureClientFactory) {
	switch c := m.Condition.(type) {
	case *azureExpiredCondition:
		c.clientFactory = factory
	case *azureGlobalAdminCondition:
		c.clientFactory = factory
	case *azureRBACCondition:
		c.clientFactory = factory
	case *azureMultiSubCondition:
		c.clientFactory = factory
	case *azureGraphReadOnlyCondition:
		c.clientFactory = factory
	case *azureSingleNonProdSubCondition:
		c.clientFactory = factory
	}
}

// --- Scorer structure tests ---

func TestAzureGoScorer_Structure(t *testing.T) {
	s := AzureGoScorer()
	assert.Equal(t, "azure-sp-rbac-scope", s.Name)
	assert.Equal(t, []string{"np.azure.7", "np.azure.8"}, s.RuleIDs)
	require.Len(t, s.Modifiers, 10)

	names := make([]string, len(s.Modifiers))
	for i, mod := range s.Modifiers {
		names[i] = mod.Name
	}
	expected := []string{
		"expired-credentials", "global-admin", "owner-sub-level",
		"contributor-sub-level", "keyvault-secret-access", "multi-subscription",
		"incomplete-credentials", "reader-only-rg-level", "graph-read-only",
		"single-non-prod-sub",
	}
	for _, name := range expected {
		assert.Contains(t, names, name)
	}
}

func TestAzureGoScorer_DynamicModifiersAreDynamic(t *testing.T) {
	s := AzureGoScorer()
	for _, mod := range s.Modifiers {
		if mod.Name == "incomplete-credentials" {
			assert.False(t, mod.IsDynamic(), "incomplete-credentials must be static")
			continue
		}
		assert.True(t, mod.IsDynamic(), "modifier %s must be dynamic", mod.Name)
	}
}

func TestAzureGoScorer_MissingCredentials(t *testing.T) {
	s := AzureGoScorer()
	m := &types.Match{NamedGroups: map[string][]byte{}}
	for _, mod := range s.Modifiers {
		fired, err := mod.Condition.Evaluate(context.Background(), m)
		assert.NoError(t, err, "modifier %s should not error", mod.Name)
		assert.False(t, fired, "modifier %s should not fire without credentials", mod.Name)
	}
}

// --- Engine scenario tests ---

func TestAzureScorer_ExpiredSetsScoreTo5(t *testing.T) {
	s := AzureGoScorer()
	factory := fakeAzureFactoryErr(errors.New("invalid_client: AADSTS7000215: invalid client secret"))
	for i := range s.Modifiers {
		injectAzureFactory(&s.Modifiers[i], factory)
	}

	engine := NewEngine([]*Scorer{s}, EngineConfig{ScopeEnabled: true, Timeout: 5 * time.Second})
	rule := &types.Rule{ID: "np.azure.7", BaseScore: 80}
	match := azureTestMatch()
	match.RuleID = "np.azure.7"

	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{match}, rule)
	assert.Equal(t, 5, score.Final)
	require.NotEmpty(t, score.Applied)
	assert.Equal(t, "expired-credentials", score.Applied[0].Name)
}

func TestAzureScorer_GlobalAdminSetsTo99(t *testing.T) {
	s := AzureGoScorer()
	mock := &mockAzureAPI{
		subscriptions: []azureSubscription{{ID: "sub1", DisplayName: "Production"}},
		roleAssignments: map[string][]azureRoleAssignment{
			"sub1": {{RoleDefinitionID: azureRoleContributor, Scope: "/subscriptions/sub1"}},
		},
		directoryRoles: []string{azureDirRoleGlobalAdmin},
	}
	factory := fakeAzureFactory(mock)
	for i := range s.Modifiers {
		injectAzureFactory(&s.Modifiers[i], factory)
	}

	engine := NewEngine([]*Scorer{s}, EngineConfig{ScopeEnabled: true, Timeout: 5 * time.Second})
	rule := &types.Rule{ID: "np.azure.7", BaseScore: 80}
	match := azureTestMatch()
	match.RuleID = "np.azure.7"

	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{match}, rule)
	assert.Equal(t, 99, score.Final)
	require.NotEmpty(t, score.Applied)
	assert.Equal(t, "global-admin", score.Applied[0].Name)
}

func TestAzureScorer_OwnerSetsTo95(t *testing.T) {
	s := AzureGoScorer()
	mock := &mockAzureAPI{
		subscriptions: []azureSubscription{{ID: "sub1", DisplayName: "Production"}},
		roleAssignments: map[string][]azureRoleAssignment{
			"sub1": {{RoleDefinitionID: azureRoleOwner, Scope: "/subscriptions/sub1"}},
		},
		appRoleAssignments: []azureAppRoleAssignment{
			{AppRoleID: "62a82d76-70ea-41e2-9197-370581804d09", ResourceDisplayName: "Microsoft Graph"},
		},
	}
	factory := fakeAzureFactory(mock)
	for i := range s.Modifiers {
		injectAzureFactory(&s.Modifiers[i], factory)
	}

	engine := NewEngine([]*Scorer{s}, EngineConfig{ScopeEnabled: true, Timeout: 5 * time.Second})
	rule := &types.Rule{ID: "np.azure.7", BaseScore: 80}
	match := azureTestMatch()
	match.RuleID = "np.azure.7"

	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{match}, rule)
	assert.Equal(t, 95, score.Final)
}

func TestAzureScorer_ContributorSetsTo85(t *testing.T) {
	s := AzureGoScorer()
	mock := &mockAzureAPI{
		subscriptions: []azureSubscription{{ID: "sub1", DisplayName: "Production"}},
		roleAssignments: map[string][]azureRoleAssignment{
			"sub1": {{RoleDefinitionID: azureRoleContributor, Scope: "/subscriptions/sub1"}},
		},
		appRoleAssignments: []azureAppRoleAssignment{
			{AppRoleID: "62a82d76-70ea-41e2-9197-370581804d09", ResourceDisplayName: "Microsoft Graph"},
		},
	}
	factory := fakeAzureFactory(mock)
	for i := range s.Modifiers {
		injectAzureFactory(&s.Modifiers[i], factory)
	}

	engine := NewEngine([]*Scorer{s}, EngineConfig{ScopeEnabled: true, Timeout: 5 * time.Second})
	rule := &types.Rule{ID: "np.azure.8", BaseScore: 70}
	match := azureTestMatch()
	match.RuleID = "np.azure.8"

	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{match}, rule)
	assert.Equal(t, 85, score.Final)
}

func TestAzureScorer_IncompleteCredentialsDelta(t *testing.T) {
	s := AzureGoScorer()
	engine := NewEngine([]*Scorer{s}, EngineConfig{ScopeEnabled: true, Timeout: 5 * time.Second})
	rule := &types.Rule{ID: "np.azure.7", BaseScore: 80}
	match := azureIncompleteMatch()
	match.RuleID = "np.azure.7"

	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{match}, rule)
	assert.Equal(t, 60, score.Final)
	require.Len(t, score.Applied, 1)
	assert.Equal(t, "incomplete-credentials", score.Applied[0].Name)
}

func TestAzureScorer_ReaderOnlyRGLevel(t *testing.T) {
	s := AzureGoScorer()
	mock := &mockAzureAPI{
		subscriptions: []azureSubscription{{ID: "sub1", DisplayName: "Production"}},
		roleAssignments: map[string][]azureRoleAssignment{
			"sub1": {{RoleDefinitionID: azureRoleReader, Scope: "/subscriptions/sub1/resourceGroups/rg1"}},
		},
		appRoleAssignments: []azureAppRoleAssignment{
			{AppRoleID: "62a82d76-70ea-41e2-9197-370581804d09", ResourceDisplayName: "Microsoft Graph"},
		},
	}
	factory := fakeAzureFactory(mock)
	for i := range s.Modifiers {
		injectAzureFactory(&s.Modifiers[i], factory)
	}

	engine := NewEngine([]*Scorer{s}, EngineConfig{ScopeEnabled: true, Timeout: 5 * time.Second})
	rule := &types.Rule{ID: "np.azure.7", BaseScore: 80}
	match := azureTestMatch()
	match.RuleID = "np.azure.7"

	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{match}, rule)
	assert.Equal(t, 55, score.Final)
}

func TestAzureScorer_ScopeDisabled_OnlyStaticFires(t *testing.T) {
	s := AzureGoScorer()
	engine := NewEngine([]*Scorer{s}, EngineConfig{ScopeEnabled: false, Timeout: 5 * time.Second})
	rule := &types.Rule{ID: "np.azure.7", BaseScore: 80}

	completeMatch := azureTestMatch()
	completeMatch.RuleID = "np.azure.7"
	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{completeMatch}, rule)
	assert.Equal(t, 80, score.Final)
	assert.Empty(t, score.Applied)

	incompleteMatch := azureIncompleteMatch()
	incompleteMatch.RuleID = "np.azure.7"
	score2 := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{incompleteMatch}, rule)
	assert.Equal(t, 60, score2.Final)
	require.Len(t, score2.Applied, 1)
	assert.Equal(t, "incomplete-credentials", score2.Applied[0].Name)
}

func TestAzureScorer_SeverityScenarios(t *testing.T) {
	tests := []struct {
		name          string
		ruleID        string
		baseScore     int
		match         *types.Match
		mock          *mockAzureAPI
		expectedScore int
		appliedNames  []string
	}{
		{
			name:      "keyvault-access-delta",
			ruleID:    "np.azure.7",
			baseScore: 80,
			match:     azureTestMatch(),
			mock: &mockAzureAPI{
				subscriptions: []azureSubscription{{ID: "sub1", DisplayName: "prod"}},
				roleAssignments: map[string][]azureRoleAssignment{
					"sub1": {{RoleDefinitionID: azureRoleKVSecretsUser, Scope: "/subscriptions/sub1/resourceGroups/rg1"}},
				},
				appRoleAssignments: []azureAppRoleAssignment{
					{AppRoleID: "62a82d76-70ea-41e2-9197-370581804d09", ResourceDisplayName: "Microsoft Graph"},
				},
			},
			expectedScore: 95,
			appliedNames:  []string{"keyvault-secret-access"},
		},
		{
			name:      "contributor-plus-multi-sub",
			ruleID:    "np.azure.7",
			baseScore: 80,
			match:     azureTestMatch(),
			mock: &mockAzureAPI{
				subscriptions: []azureSubscription{
					{ID: "sub1", DisplayName: "prod"},
					{ID: "sub2", DisplayName: "staging"},
					{ID: "sub3", DisplayName: "dev"},
				},
				roleAssignments: map[string][]azureRoleAssignment{
					"sub1": {{RoleDefinitionID: azureRoleContributor, Scope: "/subscriptions/sub1"}},
					"sub2": {},
					"sub3": {},
				},
				appRoleAssignments: []azureAppRoleAssignment{
					{AppRoleID: "62a82d76-70ea-41e2-9197-370581804d09", ResourceDisplayName: "Microsoft Graph"},
				},
			},
			expectedScore: 95,
			appliedNames:  []string{"contributor-sub-level", "multi-subscription"},
		},
		{
			name:      "graph-read-only-delta",
			ruleID:    "np.azure.8",
			baseScore: 70,
			match:     azureTestMatch(),
			mock: &mockAzureAPI{
				subscriptions: []azureSubscription{{ID: "sub1", DisplayName: "Production"}},
				roleAssignments: map[string][]azureRoleAssignment{
					"sub1": {{RoleDefinitionID: azureRoleReader, Scope: "/subscriptions/sub1/resourceGroups/rg1"}},
				},
				appRoleAssignments: []azureAppRoleAssignment{
					{AppRoleID: "df021288-bdef-4463-88db-98f22de89214", ResourceDisplayName: "Microsoft Graph"},
				},
			},
			expectedScore: 25,
			appliedNames:  []string{"reader-only-rg-level", "graph-read-only"},
		},
		{
			name:      "contributor-single-non-prod",
			ruleID:    "np.azure.8",
			baseScore: 70,
			match:     azureTestMatch(),
			mock: &mockAzureAPI{
				subscriptions: []azureSubscription{{ID: "sub1", DisplayName: "my-dev-environment"}},
				roleAssignments: map[string][]azureRoleAssignment{
					"sub1": {{RoleDefinitionID: azureRoleContributor, Scope: "/subscriptions/sub1"}},
				},
				appRoleAssignments: []azureAppRoleAssignment{
					{AppRoleID: "62a82d76-70ea-41e2-9197-370581804d09", ResourceDisplayName: "Microsoft Graph"},
				},
			},
			expectedScore: 75,
			appliedNames:  []string{"contributor-sub-level", "single-non-prod-sub"},
		},
		{
			name:      "reader-only-single-non-prod",
			ruleID:    "np.azure.7",
			baseScore: 80,
			match:     azureTestMatch(),
			mock: &mockAzureAPI{
				subscriptions: []azureSubscription{{ID: "sub1", DisplayName: "sandbox-env"}},
				roleAssignments: map[string][]azureRoleAssignment{
					"sub1": {{RoleDefinitionID: azureRoleReader, Scope: "/subscriptions/sub1/resourceGroups/rg1"}},
				},
				appRoleAssignments: []azureAppRoleAssignment{
					{AppRoleID: "62a82d76-70ea-41e2-9197-370581804d09", ResourceDisplayName: "Microsoft Graph"},
				},
			},
			expectedScore: 45,
			appliedNames:  []string{"reader-only-rg-level", "single-non-prod-sub"},
		},
		{
			name:      "owner-with-keyvault-and-multi-sub",
			ruleID:    "np.azure.7",
			baseScore: 80,
			match:     azureTestMatch(),
			mock: &mockAzureAPI{
				subscriptions: []azureSubscription{
					{ID: "sub1", DisplayName: "prod"},
					{ID: "sub2", DisplayName: "staging"},
					{ID: "sub3", DisplayName: "dev"},
				},
				roleAssignments: map[string][]azureRoleAssignment{
					"sub1": {
						{RoleDefinitionID: azureRoleOwner, Scope: "/subscriptions/sub1"},
						{RoleDefinitionID: azureRoleKVSecretsOfficer, Scope: "/subscriptions/sub1/resourceGroups/kv-rg"},
					},
					"sub2": {},
					"sub3": {},
				},
				appRoleAssignments: []azureAppRoleAssignment{
					{AppRoleID: "62a82d76-70ea-41e2-9197-370581804d09", ResourceDisplayName: "Microsoft Graph"},
				},
			},
			expectedScore: 100,
			appliedNames:  []string{"owner-sub-level", "keyvault-secret-access", "multi-subscription"},
		},
		{
			name:      "global-admin-overrides-all-rbac",
			ruleID:    "np.azure.7",
			baseScore: 80,
			match:     azureTestMatch(),
			mock: &mockAzureAPI{
				subscriptions: []azureSubscription{{ID: "sub1", DisplayName: "Production"}},
				roleAssignments: map[string][]azureRoleAssignment{
					"sub1": {
						{RoleDefinitionID: azureRoleOwner, Scope: "/subscriptions/sub1"},
					},
				},
				directoryRoles: []string{azureDirRoleGlobalAdmin},
				appRoleAssignments: []azureAppRoleAssignment{
					{AppRoleID: "62a82d76-70ea-41e2-9197-370581804d09", ResourceDisplayName: "Microsoft Graph"},
				},
			},
			expectedScore: 99,
			appliedNames:  []string{"global-admin"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := AzureGoScorer()
			factory := fakeAzureFactory(tc.mock)
			for i := range s.Modifiers {
				injectAzureFactory(&s.Modifiers[i], factory)
			}

			engine := NewEngine([]*Scorer{s}, EngineConfig{ScopeEnabled: true, Timeout: 5 * time.Second})
			rule := &types.Rule{ID: tc.ruleID, BaseScore: tc.baseScore}
			match := tc.match
			match.RuleID = tc.ruleID

			score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{match}, rule)

			assert.Equal(t, tc.expectedScore, score.Final, "unexpected final score")

			appliedNames := make([]string, len(score.Applied))
			for i, a := range score.Applied {
				appliedNames[i] = a.Name
			}
			for _, expected := range tc.appliedNames {
				assert.Contains(t, appliedNames, expected, "expected modifier %s to be applied", expected)
			}
		})
	}
}

// --- extractObjectIDFromJWT tests ---

func TestExtractObjectIDFromJWT_Valid(t *testing.T) {
	// header.payload.signature — payload decodes to {"oid":"test-object-id"}
	// base64url("{}") = "e30"
	// base64url('{"oid":"test-object-id"}') = "eyJvaWQiOiJ0ZXN0LW9iamVjdC1pZCJ9"
	token := "e30.eyJvaWQiOiJ0ZXN0LW9iamVjdC1pZCJ9.sig"
	oid, err := extractObjectIDFromJWT(token)
	require.NoError(t, err)
	assert.Equal(t, "test-object-id", oid)
}

func TestExtractObjectIDFromJWT_InvalidFormat(t *testing.T) {
	_, err := extractObjectIDFromJWT("not-a-jwt")
	assert.Error(t, err)
}

func TestExtractObjectIDFromJWT_MissingOID(t *testing.T) {
	// base64url('{"sub":"test"}') = "eyJzdWIiOiJ0ZXN0In0"
	token := "e30.eyJzdWIiOiJ0ZXN0In0.sig"
	_, err := extractObjectIDFromJWT(token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oid claim missing")
}
