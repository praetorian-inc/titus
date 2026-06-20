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

type mockGCPAPI struct {
	projectBindings []gcpIAMBinding
	orgBindings     []gcpIAMBinding
	projectCount    int
	projectErr      error
	orgErr          error
	countErr        error
}

func (m *mockGCPAPI) GetProjectIAMPolicy(_ context.Context, _ string) ([]gcpIAMBinding, error) {
	return m.projectBindings, m.projectErr
}

func (m *mockGCPAPI) GetOrgIAMPolicy(_ context.Context, _ string) ([]gcpIAMBinding, error) {
	return m.orgBindings, m.orgErr
}

func (m *mockGCPAPI) CountAccessibleProjects(_ context.Context) (int, error) {
	return m.projectCount, m.countErr
}

func fakeGCPFactory(api gcpAPI) gcpClientFactory {
	return func(_ context.Context, _ *gcpServiceAccountKey) (gcpAPI, error) {
		return api, nil
	}
}

func fakeGCPFactoryErr(err error) gcpClientFactory {
	return func(_ context.Context, _ *gcpServiceAccountKey) (gcpAPI, error) {
		return nil, err
	}
}

func gcpTestMatch() *types.Match {
	return &types.Match{
		NamedGroups: map[string][]byte{
			"service_account": []byte(`{"project_id":"test-project","client_email":"sa@test-project.iam.gserviceaccount.com","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}`),
		},
	}
}

func TestExtractGCPCredentials_SimpleJSON(t *testing.T) {
	m := gcpTestMatch()
	key, ok := extractGCPCredentials(m)
	require.True(t, ok)
	assert.Equal(t, "test-project", key.ProjectID)
	assert.Equal(t, "sa@test-project.iam.gserviceaccount.com", key.ClientEmail)
	assert.NotEmpty(t, key.PrivateKey)
}

func TestExtractGCPCredentials_NestedJSON(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"service_account_nested": []byte(`{"wrapper":{"project_id":"nested-project","client_email":"sa@nested-project.iam.gserviceaccount.com","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}}`),
		},
	}
	key, ok := extractGCPCredentials(m)
	require.True(t, ok)
	assert.Equal(t, "nested-project", key.ProjectID)
	assert.Equal(t, "sa@nested-project.iam.gserviceaccount.com", key.ClientEmail)
}

func TestExtractGCPCredentials_NilMatch(t *testing.T) {
	_, ok := extractGCPCredentials(nil)
	assert.False(t, ok)
}

func TestExtractGCPCredentials_MissingPrivateKey(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"service_account": []byte(`{"project_id":"test-project","client_email":"sa@test-project.iam.gserviceaccount.com"}`),
		},
	}
	_, ok := extractGCPCredentials(m)
	assert.False(t, ok)
}

func TestGCPSADisabledCondition_IsDynamic(t *testing.T) {
	mod := Modifier{Condition: &gcpSADisabledCondition{}}
	assert.True(t, mod.IsDynamic())
}

func TestGCPSADisabledCondition_FiresWhenDisabled(t *testing.T) {
	cond := &gcpSADisabledCondition{
		clientFactory: fakeGCPFactoryErr(errors.New("account is disabled")),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGCPSADisabledCondition_DoesNotFireWhenActive(t *testing.T) {
	cond := &gcpSADisabledCondition{
		clientFactory: fakeGCPFactory(&mockGCPAPI{}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGCPRoleBindingCondition_IsDynamic(t *testing.T) {
	mod := Modifier{Condition: &gcpRoleBindingCondition{matchRoles: []string{"roles/owner"}}}
	assert.True(t, mod.IsDynamic())
}

func TestGCPRoleBindingCondition_FiresWhenOwnerRoleAttached(t *testing.T) {
	cond := &gcpRoleBindingCondition{
		matchRoles: []string{"roles/owner"},
		clientFactory: fakeGCPFactory(&mockGCPAPI{
			projectBindings: []gcpIAMBinding{
				{Role: "roles/owner", Members: []string{"serviceAccount:sa@test-project.iam.gserviceaccount.com"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGCPRoleBindingCondition_DoesNotFireWhenNoMatchingRoles(t *testing.T) {
	cond := &gcpRoleBindingCondition{
		matchRoles: []string{"roles/owner"},
		clientFactory: fakeGCPFactory(&mockGCPAPI{
			projectBindings: []gcpIAMBinding{
				{Role: "roles/viewer", Members: []string{"serviceAccount:sa@test-project.iam.gserviceaccount.com"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGCPRoleBindingCondition_ExclusiveFiresWhenOnlyMatchingRoles(t *testing.T) {
	cond := &gcpRoleBindingCondition{
		matchRoles:      []string{"roles/viewer", "roles/browser"},
		onlyIfExclusive: true,
		clientFactory: fakeGCPFactory(&mockGCPAPI{
			projectBindings: []gcpIAMBinding{
				{Role: "roles/viewer", Members: []string{"serviceAccount:sa@test-project.iam.gserviceaccount.com"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGCPRoleBindingCondition_ExclusiveDoesNotFireWhenMixed(t *testing.T) {
	cond := &gcpRoleBindingCondition{
		matchRoles:      []string{"roles/viewer", "roles/browser"},
		onlyIfExclusive: true,
		clientFactory: fakeGCPFactory(&mockGCPAPI{
			projectBindings: []gcpIAMBinding{
				{Role: "roles/viewer", Members: []string{"serviceAccount:sa@test-project.iam.gserviceaccount.com"}},
				{Role: "roles/editor", Members: []string{"serviceAccount:sa@test-project.iam.gserviceaccount.com"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGCPOrgLevelBindingCondition_FiresWhenSABoundAtOrg(t *testing.T) {
	cond := &gcpOrgLevelBindingCondition{
		clientFactory: fakeGCPFactory(&mockGCPAPI{
			orgBindings: []gcpIAMBinding{
				{Role: "roles/viewer", Members: []string{"serviceAccount:sa@test-project.iam.gserviceaccount.com"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGCPOrgLevelBindingCondition_DoesNotFireWhenNoOrgBindings(t *testing.T) {
	cond := &gcpOrgLevelBindingCondition{
		clientFactory: fakeGCPFactory(&mockGCPAPI{
			orgBindings: []gcpIAMBinding{},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGCPMultiProjectCondition_FiresWhenFiveOrMoreProjects(t *testing.T) {
	cond := &gcpMultiProjectCondition{
		minProjects:   5,
		clientFactory: fakeGCPFactory(&mockGCPAPI{projectCount: 5}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGCPMultiProjectCondition_DoesNotFireWhenFewer(t *testing.T) {
	cond := &gcpMultiProjectCondition{
		minProjects:   5,
		clientFactory: fakeGCPFactory(&mockGCPAPI{projectCount: 3}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGCPSingleNonProdCondition_FiresForDevProject(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"service_account": []byte(`{"project_id":"my-dev-project","client_email":"sa@my-dev-project.iam.gserviceaccount.com","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}`),
		},
	}
	cond := &gcpSingleNonProdCondition{
		clientFactory: fakeGCPFactory(&mockGCPAPI{projectCount: 1}),
	}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGCPSingleNonProdCondition_DoesNotFireForMultipleProjects(t *testing.T) {
	cond := &gcpSingleNonProdCondition{
		clientFactory: fakeGCPFactory(&mockGCPAPI{projectCount: 3}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGCPSingleNonProdCondition_DoesNotFireForProdProject(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"service_account": []byte(`{"project_id":"production-app","client_email":"sa@production-app.iam.gserviceaccount.com","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}`),
		},
	}
	cond := &gcpSingleNonProdCondition{
		clientFactory: fakeGCPFactory(&mockGCPAPI{projectCount: 1}),
	}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGCPRoleBindingCondition_ReturnsFalseOnAPIError(t *testing.T) {
	cond := &gcpRoleBindingCondition{
		matchRoles:    []string{"roles/owner"},
		clientFactory: fakeGCPFactory(&mockGCPAPI{projectErr: fmt.Errorf("permission denied")}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGCPOrgLevelBindingCondition_ReturnsFalseOnAPIError(t *testing.T) {
	cond := &gcpOrgLevelBindingCondition{
		clientFactory: fakeGCPFactory(&mockGCPAPI{orgErr: fmt.Errorf("permission denied")}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGCPMultiProjectCondition_ReturnsFalseOnAPIError(t *testing.T) {
	cond := &gcpMultiProjectCondition{
		minProjects:   5,
		clientFactory: fakeGCPFactory(&mockGCPAPI{countErr: fmt.Errorf("permission denied")}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

// injectGCPFactory sets the clientFactory field on the underlying condition of a
// Modifier, supporting all five GCP condition types used in engine scenario tests.
func injectGCPFactory(m *Modifier, factory gcpClientFactory) {
	switch c := m.Condition.(type) {
	case *gcpSADisabledCondition:
		c.clientFactory = factory
	case *gcpRoleBindingCondition:
		c.clientFactory = factory
	case *gcpOrgLevelBindingCondition:
		c.clientFactory = factory
	case *gcpMultiProjectCondition:
		c.clientFactory = factory
	case *gcpSingleNonProdCondition:
		c.clientFactory = factory
	}
}

// --- Scorer structure tests ---

func TestGCPGoScorer_Structure(t *testing.T) {
	s := GCPGoScorer()
	assert.Equal(t, "gcp-sa-iam-scope", s.Name)
	assert.Equal(t, []string{"kingfisher.gcp.1"}, s.RuleIDs)
	require.Len(t, s.Modifiers, 10)

	names := make([]string, len(s.Modifiers))
	for i, mod := range s.Modifiers {
		names[i] = mod.Name
	}
	assert.Contains(t, names, "sa-disabled")
	assert.Contains(t, names, "owner-or-org-admin")
	assert.Contains(t, names, "priv-escalation-path")
	assert.Contains(t, names, "secret-accessor")
	assert.Contains(t, names, "storage-db-admin")
	assert.Contains(t, names, "org-level-binding")
	assert.Contains(t, names, "multi-project-access")
	assert.Contains(t, names, "viewer-only")
	assert.Contains(t, names, "observability-only")
	assert.Contains(t, names, "single-non-prod-project")
}

func TestGCPGoScorer_AllModifiersAreDynamic(t *testing.T) {
	s := GCPGoScorer()
	for _, mod := range s.Modifiers {
		assert.True(t, mod.IsDynamic(), "modifier %s must be dynamic", mod.Name)
	}
}

func TestGCPGoScorer_MissingCredentials(t *testing.T) {
	s := GCPGoScorer()
	m := &types.Match{
		NamedGroups: map[string][]byte{},
	}
	for _, mod := range s.Modifiers {
		fired, err := mod.Condition.Evaluate(context.Background(), m)
		assert.NoError(t, err, "modifier %s should not error", mod.Name)
		assert.False(t, fired, "modifier %s should not fire without credentials", mod.Name)
	}
}

// --- extractGCPCredentials edge cases ---

func TestExtractGCPCredentials_MissingClientEmail(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"service_account": []byte(`{"project_id":"p","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}`),
		},
	}
	_, ok := extractGCPCredentials(m)
	assert.False(t, ok)
}

func TestExtractGCPCredentials_InvalidJSON(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"service_account": []byte(`{not-valid-json}`),
		},
	}
	_, ok := extractGCPCredentials(m)
	assert.False(t, ok)
}

func TestExtractGCPCredentials_EmptyNamedGroups(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"other_group": []byte(`{"some":"data"}`),
		},
	}
	_, ok := extractGCPCredentials(m)
	assert.False(t, ok)
}

func TestExtractGCPCredentials_PrefersServiceAccountOverNested(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"service_account":        []byte(`{"project_id":"primary","client_email":"sa@primary.iam.gserviceaccount.com","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}`),
			"service_account_nested": []byte(`{"wrapper":{"project_id":"nested","client_email":"sa@nested.iam.gserviceaccount.com","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}}`),
		},
	}
	key, ok := extractGCPCredentials(m)
	require.True(t, ok)
	assert.Equal(t, "primary", key.ProjectID)
}

func TestExtractGCPCredentials_DeeplyNestedJSON(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"service_account_nested": []byte(`{"level1":{"level2":{"project_id":"deep","client_email":"sa@deep.iam.gserviceaccount.com","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}}}`),
		},
	}
	key, ok := extractGCPCredentials(m)
	require.True(t, ok)
	assert.Equal(t, "deep", key.ProjectID)
}

// --- gcpSADisabledCondition edge cases ---

func TestGCPSADisabledCondition_DoesNotFireOnNonDisabledError(t *testing.T) {
	cond := &gcpSADisabledCondition{
		clientFactory: fakeGCPFactoryErr(errors.New("connection refused")),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGCPSADisabledCondition_ReturnsFalseOnBadCredentials(t *testing.T) {
	cond := &gcpSADisabledCondition{}
	m := &types.Match{NamedGroups: map[string][]byte{}}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.False(t, fired)
}

// --- gcpRoleBindingCondition edge cases ---

func TestGCPRoleBindingCondition_DoesNotFireWhenSANotInMembers(t *testing.T) {
	cond := &gcpRoleBindingCondition{
		matchRoles: []string{"roles/owner"},
		clientFactory: fakeGCPFactory(&mockGCPAPI{
			projectBindings: []gcpIAMBinding{
				{Role: "roles/owner", Members: []string{"serviceAccount:other-sa@other-project.iam.gserviceaccount.com"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGCPRoleBindingCondition_ExclusiveReturnsFalseWhenNoRoles(t *testing.T) {
	cond := &gcpRoleBindingCondition{
		matchRoles:      []string{"roles/viewer"},
		onlyIfExclusive: true,
		clientFactory: fakeGCPFactory(&mockGCPAPI{
			projectBindings: []gcpIAMBinding{},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGCPRoleBindingCondition_MultipleMatchRoles(t *testing.T) {
	cond := &gcpRoleBindingCondition{
		matchRoles: []string{"roles/owner", "roles/resourcemanager.organizationAdmin"},
		clientFactory: fakeGCPFactory(&mockGCPAPI{
			projectBindings: []gcpIAMBinding{
				{Role: "roles/resourcemanager.organizationAdmin", Members: []string{"serviceAccount:sa@test-project.iam.gserviceaccount.com"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

// --- gcpOrgLevelBindingCondition edge cases ---

func TestGCPOrgLevelBindingCondition_DoesNotFireWhenSANotInOrgBindingMembers(t *testing.T) {
	cond := &gcpOrgLevelBindingCondition{
		clientFactory: fakeGCPFactory(&mockGCPAPI{
			orgBindings: []gcpIAMBinding{
				{Role: "roles/viewer", Members: []string{"serviceAccount:other@other.iam.gserviceaccount.com"}},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

// --- gcpSingleNonProdCondition edge cases ---

func TestGCPSingleNonProdCondition_AllNonProdPatterns(t *testing.T) {
	patterns := []string{"dev", "test", "staging", "sandbox", "nonprod", "non-prod", "demo", "tmp", "temp"}
	for _, pat := range patterns {
		t.Run(pat, func(t *testing.T) {
			m := &types.Match{
				NamedGroups: map[string][]byte{
					"service_account": []byte(fmt.Sprintf(`{"project_id":"my-%s-project","client_email":"sa@my-%s-project.iam.gserviceaccount.com","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}`, pat, pat)),
				},
			}
			cond := &gcpSingleNonProdCondition{
				clientFactory: fakeGCPFactory(&mockGCPAPI{projectCount: 1}),
			}
			fired, err := cond.Evaluate(context.Background(), m)
			require.NoError(t, err)
			assert.True(t, fired, "pattern %q should fire", pat)
		})
	}
}

func TestGCPSingleNonProdCondition_CaseInsensitive(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"service_account": []byte(`{"project_id":"MY-STAGING-PROJECT","client_email":"sa@MY-STAGING-PROJECT.iam.gserviceaccount.com","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}`),
		},
	}
	cond := &gcpSingleNonProdCondition{
		clientFactory: fakeGCPFactory(&mockGCPAPI{projectCount: 1}),
	}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGCPSingleNonProdCondition_ReturnsFalseOnAPIError(t *testing.T) {
	cond := &gcpSingleNonProdCondition{
		clientFactory: fakeGCPFactory(&mockGCPAPI{countErr: fmt.Errorf("permission denied")}),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGCPSingleNonProdCondition_ReturnsFalseOnFactoryError(t *testing.T) {
	cond := &gcpSingleNonProdCondition{
		clientFactory: fakeGCPFactoryErr(fmt.Errorf("auth failed")),
	}
	fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

// --- gcpMultiProjectCondition boundary ---

func TestGCPMultiProjectCondition_ExactBoundary(t *testing.T) {
	for _, tc := range []struct {
		count int
		want  bool
	}{
		{4, false},
		{5, true},
		{6, true},
	} {
		t.Run(fmt.Sprintf("count=%d", tc.count), func(t *testing.T) {
			cond := &gcpMultiProjectCondition{
				minProjects:   5,
				clientFactory: fakeGCPFactory(&mockGCPAPI{projectCount: tc.count}),
			}
			fired, err := cond.Evaluate(context.Background(), gcpTestMatch())
			require.NoError(t, err)
			assert.Equal(t, tc.want, fired)
		})
	}
}

// --- Engine scenario tests ---

func TestGCPScorer_OwnerSetsScoreTo99(t *testing.T) {
	s := GCPGoScorer()
	// Use projectCount > 1 to prevent single-non-prod-project from firing
	// (that modifier requires exactly 1 accessible project).
	mockAPI := &mockGCPAPI{
		projectBindings: []gcpIAMBinding{
			{Role: "roles/owner", Members: []string{"serviceAccount:sa@prod-project.iam.gserviceaccount.com"}},
		},
		projectCount: 3,
	}
	factory := fakeGCPFactory(mockAPI)
	for i := range s.Modifiers {
		injectGCPFactory(&s.Modifiers[i], factory)
	}

	engine := NewEngine([]*Scorer{s}, EngineConfig{ScopeEnabled: true, Timeout: 5 * time.Second})
	rule := &types.Rule{ID: "kingfisher.gcp.1", BaseScore: 92}
	// Use a production-named project so non-prod patterns don't match.
	match := &types.Match{
		RuleID: "kingfisher.gcp.1",
		NamedGroups: map[string][]byte{
			"service_account": []byte(`{"project_id":"prod-project","client_email":"sa@prod-project.iam.gserviceaccount.com","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}`),
		},
	}

	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{match}, rule)

	assert.Equal(t, 99, score.Final)
	require.NotEmpty(t, score.Applied)
	assert.Equal(t, "owner-or-org-admin", score.Applied[0].Name)
}

func TestGCPScorer_DisabledSAOverridesEverything(t *testing.T) {
	s := GCPGoScorer()
	factory := fakeGCPFactoryErr(errors.New("account is disabled"))
	for i := range s.Modifiers {
		injectGCPFactory(&s.Modifiers[i], factory)
	}

	engine := NewEngine([]*Scorer{s}, EngineConfig{ScopeEnabled: true, Timeout: 5 * time.Second})
	rule := &types.Rule{ID: "kingfisher.gcp.1", BaseScore: 92}
	match := gcpTestMatch()
	match.RuleID = "kingfisher.gcp.1"

	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{match}, rule)

	assert.Equal(t, 5, score.Final)
	require.Len(t, score.Applied, 1)
	assert.Equal(t, "sa-disabled", score.Applied[0].Name)
}

func TestGCPScorer_SeverityScenarios(t *testing.T) {
	makeMatch := func(projectID, email string) *types.Match {
		return &types.Match{
			RuleID: "kingfisher.gcp.1",
			NamedGroups: map[string][]byte{
				"service_account": []byte(fmt.Sprintf(
					`{"project_id":"%s","client_email":"%s","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}`,
					projectID, email)),
			},
		}
	}

	prodMatch := makeMatch("prod-project", "sa@prod-project.iam.gserviceaccount.com")
	devMatch := makeMatch("my-dev-project", "sa@my-dev-project.iam.gserviceaccount.com")

	const prodEmail = "sa@prod-project.iam.gserviceaccount.com"
	const devEmail = "sa@my-dev-project.iam.gserviceaccount.com"

	tests := []struct {
		name          string
		match         *types.Match
		mock          *mockGCPAPI
		expectedScore int
		appliedNames  []string
	}{
		// --- Score UP scenarios ---
		{
			name:  "priv-escalation-iam-admin",
			match: prodMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/iam.serviceAccountAdmin", Members: []string{"serviceAccount:" + prodEmail}},
				},
				projectCount: 3,
			},
			expectedScore: 100, // 92 + 20 = 112, clamped
			appliedNames:  []string{"priv-escalation-path"},
		},
		{
			name:  "priv-escalation-security-admin",
			match: prodMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/iam.securityAdmin", Members: []string{"serviceAccount:" + prodEmail}},
				},
				projectCount: 3,
			},
			expectedScore: 100, // 92 + 20 = 112, clamped
			appliedNames:  []string{"priv-escalation-path"},
		},
		{
			name:  "secret-accessor",
			match: prodMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/secretmanager.secretAccessor", Members: []string{"serviceAccount:" + prodEmail}},
				},
				projectCount: 3,
			},
			expectedScore: 100, // 92 + 15 = 107, clamped
			appliedNames:  []string{"secret-accessor"},
		},
		{
			name:  "storage-admin",
			match: prodMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/storage.admin", Members: []string{"serviceAccount:" + prodEmail}},
				},
				projectCount: 3,
			},
			expectedScore: 100, // 92 + 15 = 107, clamped
			appliedNames:  []string{"storage-db-admin"},
		},
		{
			name:  "cloudsql-admin",
			match: prodMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/cloudsql.admin", Members: []string{"serviceAccount:" + prodEmail}},
				},
				projectCount: 3,
			},
			expectedScore: 100, // 92 + 15 = 107, clamped
			appliedNames:  []string{"storage-db-admin"},
		},
		{
			name:  "org-level-binding",
			match: prodMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/editor", Members: []string{"serviceAccount:" + prodEmail}},
				},
				orgBindings: []gcpIAMBinding{
					{Role: "roles/viewer", Members: []string{"serviceAccount:" + prodEmail}},
				},
				projectCount: 3,
			},
			expectedScore: 100, // 92 + 15 = 107, clamped
			appliedNames:  []string{"org-level-binding"},
		},
		{
			name:  "multi-project-access",
			match: prodMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/editor", Members: []string{"serviceAccount:" + prodEmail}},
				},
				projectCount: 5,
			},
			expectedScore: 100, // 92 + 10 = 102, clamped
			appliedNames:  []string{"multi-project-access"},
		},
		// --- Score DOWN scenarios ---
		{
			name:  "viewer-only",
			match: prodMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/viewer", Members: []string{"serviceAccount:" + prodEmail}},
				},
				projectCount: 3,
			},
			expectedScore: 72, // 92 - 20
			appliedNames:  []string{"viewer-only"},
		},
		{
			name:  "browser-only",
			match: prodMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/browser", Members: []string{"serviceAccount:" + prodEmail}},
				},
				projectCount: 3,
			},
			expectedScore: 72, // 92 - 20
			appliedNames:  []string{"viewer-only"},
		},
		{
			name:  "observability-only",
			match: prodMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/logging.viewer", Members: []string{"serviceAccount:" + prodEmail}},
				},
				projectCount: 3,
			},
			expectedScore: 77, // 92 - 15
			appliedNames:  []string{"observability-only"},
		},
		{
			name:  "monitoring-viewer-only",
			match: prodMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/monitoring.viewer", Members: []string{"serviceAccount:" + prodEmail}},
				},
				projectCount: 3,
			},
			expectedScore: 77, // 92 - 15
			appliedNames:  []string{"observability-only"},
		},
		{
			name:  "single-non-prod-project",
			match: devMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/editor", Members: []string{"serviceAccount:" + devEmail}},
				},
				projectCount: 1,
			},
			expectedScore: 82, // 92 - 10
			appliedNames:  []string{"single-non-prod-project"},
		},
		// --- Combination scenarios ---
		{
			name:  "viewer-only-single-non-prod",
			match: devMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/viewer", Members: []string{"serviceAccount:" + devEmail}},
				},
				projectCount: 1,
			},
			expectedScore: 62, // 92 - 20 - 10
			appliedNames:  []string{"viewer-only", "single-non-prod-project"},
		},
		{
			name:  "owner-with-org-and-multi-project",
			match: prodMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/owner", Members: []string{"serviceAccount:" + prodEmail}},
				},
				orgBindings: []gcpIAMBinding{
					{Role: "roles/viewer", Members: []string{"serviceAccount:" + prodEmail}},
				},
				projectCount: 7,
			},
			expectedScore: 100, // set_score=99 + 15 + 10 = 124, clamped
			appliedNames:  []string{"owner-or-org-admin", "org-level-binding", "multi-project-access"},
		},
		{
			name:  "priv-escalation-with-secret-access",
			match: prodMatch,
			mock: &mockGCPAPI{
				projectBindings: []gcpIAMBinding{
					{Role: "roles/iam.serviceAccountAdmin", Members: []string{"serviceAccount:" + prodEmail}},
					{Role: "roles/secretmanager.secretAccessor", Members: []string{"serviceAccount:" + prodEmail}},
				},
				projectCount: 3,
			},
			expectedScore: 100, // 92 + 20 + 15 = 127, clamped
			appliedNames:  []string{"priv-escalation-path", "secret-accessor"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := GCPGoScorer()
			factory := fakeGCPFactory(tc.mock)
			for i := range s.Modifiers {
				injectGCPFactory(&s.Modifiers[i], factory)
			}

			engine := NewEngine([]*Scorer{s}, EngineConfig{ScopeEnabled: true, Timeout: 5 * time.Second})
			rule := &types.Rule{ID: "kingfisher.gcp.1", BaseScore: 92}

			score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{tc.match}, rule)

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

func TestGCPScorer_ScopeDisabled_NoModifiersFire(t *testing.T) {
	s := GCPGoScorer()

	engine := NewEngine([]*Scorer{s}, EngineConfig{ScopeEnabled: false, Timeout: 5 * time.Second})
	rule := &types.Rule{ID: "kingfisher.gcp.1", BaseScore: 92}
	match := gcpTestMatch()
	match.RuleID = "kingfisher.gcp.1"

	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{match}, rule)

	assert.Equal(t, 92, score.Final, "scope disabled: all dynamic modifiers must be skipped")
	assert.Empty(t, score.Applied)
}
