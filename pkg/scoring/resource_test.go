package scoring

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Engine: resources copied from match to finding
// ---------------------------------------------------------------------------

func TestEngine_CopiesResourcesToFinding(t *testing.T) {
	scorer := &Scorer{
		Name:    "test",
		RuleIDs: []string{"np.test.1"},
		Modifiers: []Modifier{
			{
				Name:     "always",
				Priority: 100,
				Kind:     ModifierKindDelta,
				Value:    5,
				Condition: condFunc(func(_ context.Context, m *types.Match) (bool, error) {
					m.Resources = []types.ResourceInfo{
						{Service: "aws", Type: "s3_bucket", Name: "prod-data"},
					}
					return true, nil
				}),
			},
		},
	}
	e := NewEngine([]*Scorer{scorer}, EngineConfig{ScopeEnabled: true})

	f := &types.Finding{RuleID: "np.test.1"}
	m := &types.Match{}
	rule := &types.Rule{BaseScore: 50}

	e.Score(context.Background(), f, []*types.Match{m}, rule)

	require.Len(t, f.Resources, 1)
	assert.Equal(t, "s3_bucket", f.Resources[0].Type)
	assert.Equal(t, "prod-data", f.Resources[0].Name)
}

func TestEngine_DoesNotOverwriteExistingResources(t *testing.T) {
	scorer := &Scorer{
		Name:    "test",
		RuleIDs: []string{"np.test.1"},
		Modifiers: []Modifier{
			{
				Name:     "always",
				Priority: 100,
				Kind:     ModifierKindDelta,
				Value:    0,
				Condition: condFunc(func(_ context.Context, m *types.Match) (bool, error) {
					m.Resources = []types.ResourceInfo{
						{Service: "aws", Type: "s3_bucket", Name: "new-bucket"},
					}
					return true, nil
				}),
			},
		},
	}
	e := NewEngine([]*Scorer{scorer}, EngineConfig{ScopeEnabled: true})

	f := &types.Finding{
		RuleID: "np.test.1",
		Resources: []types.ResourceInfo{
			{Service: "github", Type: "repo", Name: "org/existing"},
		},
	}
	m := &types.Match{}
	rule := &types.Rule{BaseScore: 50}

	e.Score(context.Background(), f, []*types.Match{m}, rule)

	require.Len(t, f.Resources, 1)
	assert.Equal(t, "org/existing", f.Resources[0].Name, "existing resources should not be overwritten")
}

func TestEngine_NilResourcesWhenNoneSet(t *testing.T) {
	scorer := &Scorer{
		Name:    "test",
		RuleIDs: []string{"np.test.1"},
		Modifiers: []Modifier{
			{Name: "noop", Priority: 100, Kind: ModifierKindDelta, Value: 0,
				Condition: condFunc(func(_ context.Context, _ *types.Match) (bool, error) { return true, nil })},
		},
	}
	e := NewEngine([]*Scorer{scorer}, EngineConfig{ScopeEnabled: true})

	f := &types.Finding{RuleID: "np.test.1"}
	m := &types.Match{}
	rule := &types.Rule{BaseScore: 50}

	e.Score(context.Background(), f, []*types.Match{m}, rule)
	assert.Nil(t, f.Resources)
}

// ---------------------------------------------------------------------------
// AWS S3 condition
// ---------------------------------------------------------------------------

type mockS3 struct {
	buckets []string
	err     error
}

func (m *mockS3) ListBuckets(_ context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := &s3.ListBucketsOutput{}
	for _, name := range m.buckets {
		n := name
		out.Buckets = append(out.Buckets, s3types.Bucket{Name: &n})
	}
	return out, nil
}

type mockSecretsManager struct {
	secrets []string
	err     error
}

func (m *mockSecretsManager) ListSecrets(_ context.Context, _ *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := &secretsmanager.ListSecretsOutput{}
	for _, name := range m.secrets {
		n := name
		out.SecretList = append(out.SecretList, smtypes.SecretListEntry{Name: &n})
	}
	return out, nil
}

func fakeResourceFactory(s3Client s3API, smClient secretsManagerAPI) awsResourceClientFactory {
	return func(_ context.Context, _, _, _ string) (s3API, secretsManagerAPI, error) {
		return s3Client, smClient, nil
	}
}

func TestAWSS3BucketsCondition_PopulatesResources(t *testing.T) {
	cond := &awsS3BucketsCondition{
		clientFactory: fakeFactory(
			&mockSTS{identity: &sts.GetCallerIdentityOutput{}},
			&mockIAM{},
		),
		resourceClientFactory: fakeResourceFactory(
			&mockS3{buckets: []string{"dev-logs", "prod-customer-data", "staging-assets"}},
			&mockSecretsManager{},
		),
	}

	m := testMatch()
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.True(t, fired, "should fire when prod-named bucket found")
	assert.Len(t, m.Resources, 3)
	assert.Equal(t, "s3_bucket", m.Resources[0].Type)
	assert.Equal(t, "dev-logs", m.Resources[0].Name)
}

func TestAWSS3BucketsCondition_DoesNotFireWithoutProdBuckets(t *testing.T) {
	cond := &awsS3BucketsCondition{
		clientFactory: fakeFactory(
			&mockSTS{identity: &sts.GetCallerIdentityOutput{}},
			&mockIAM{},
		),
		resourceClientFactory: fakeResourceFactory(
			&mockS3{buckets: []string{"dev-logs", "staging-assets"}},
			&mockSecretsManager{},
		),
	}

	m := testMatch()
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.False(t, fired, "should not fire without prod-named buckets")
	assert.Len(t, m.Resources, 2, "resources still populated even when condition doesn't fire")
}

func TestAWSS3BucketsCondition_TruncatesAtMax(t *testing.T) {
	buckets := make([]string, 15)
	for i := range buckets {
		buckets[i] = "bucket-" + string(rune('a'+i))
	}
	cond := &awsS3BucketsCondition{
		clientFactory: fakeFactory(
			&mockSTS{identity: &sts.GetCallerIdentityOutput{}},
			&mockIAM{},
		),
		resourceClientFactory: fakeResourceFactory(
			&mockS3{buckets: buckets},
			&mockSecretsManager{},
		),
	}

	m := testMatch()
	_, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.Equal(t, 11, len(m.Resources), "10 individual + 1 total summary")
	assert.Equal(t, "total", m.Resources[10].Name)
	assert.Equal(t, 15, m.Resources[10].Count)
}

func TestAWSSecretsManagerCondition_PopulatesResources(t *testing.T) {
	cond := &awsSecretsManagerCondition{
		clientFactory: fakeFactory(
			&mockSTS{identity: &sts.GetCallerIdentityOutput{}},
			&mockIAM{},
		),
		resourceClientFactory: fakeResourceFactory(
			&mockS3{},
			&mockSecretsManager{secrets: []string{"prod/db-password", "api-key"}},
		),
	}

	m := testMatch()
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.True(t, fired, "should fire when secrets are accessible")
	assert.Len(t, m.Resources, 2)
	assert.Equal(t, "secret", m.Resources[0].Type)
	assert.Equal(t, "prod/db-password", m.Resources[0].Name)
}

func TestAWSSecretsManagerCondition_DoesNotFireWhenEmpty(t *testing.T) {
	cond := &awsSecretsManagerCondition{
		clientFactory: fakeFactory(
			&mockSTS{identity: &sts.GetCallerIdentityOutput{}},
			&mockIAM{},
		),
		resourceClientFactory: fakeResourceFactory(
			&mockS3{},
			&mockSecretsManager{secrets: nil},
		),
	}

	m := testMatch()
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.False(t, fired)
	assert.Empty(t, m.Resources)
}

func TestAWSSecretsManagerCondition_DoesNotFireWhenKeyDead(t *testing.T) {
	cond := &awsSecretsManagerCondition{
		clientFactory: fakeFactory(
			&mockSTS{err: assert.AnError},
			&mockIAM{},
		),
		resourceClientFactory: fakeResourceFactory(
			&mockS3{},
			&mockSecretsManager{secrets: []string{"should-not-reach"}},
		),
	}

	m := testMatch()
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.False(t, fired)
	assert.Empty(t, m.Resources)
}

// ---------------------------------------------------------------------------
// containsSensitiveName
// ---------------------------------------------------------------------------

func TestContainsSensitiveName(t *testing.T) {
	assert.True(t, containsSensitiveName("prod-customer-data"))
	assert.True(t, containsSensitiveName("PROD-BACKUPS"))
	assert.True(t, containsSensitiveName("my-pii-bucket"))
	assert.True(t, containsSensitiveName("credential-store"))
	assert.False(t, containsSensitiveName("dev-logs"))
	assert.False(t, containsSensitiveName("staging-assets"))
}

// ---------------------------------------------------------------------------
// AWS resource conditions are dynamic
// ---------------------------------------------------------------------------

func TestAWSS3BucketsCondition_IsDynamic(t *testing.T) {
	mod := Modifier{Condition: &awsS3BucketsCondition{}}
	assert.True(t, mod.IsDynamic())
}

func TestAWSSecretsManagerCondition_IsDynamic(t *testing.T) {
	mod := Modifier{Condition: &awsSecretsManagerCondition{}}
	assert.True(t, mod.IsDynamic())
}

// condFunc is a test helper that wraps a function as a dynamic Condition.
type condFunc func(ctx context.Context, m *types.Match) (bool, error)

func (f condFunc) Evaluate(ctx context.Context, m *types.Match) (bool, error) { return f(ctx, m) }
func (f condFunc) markDynamic()                                                {}

// ---------------------------------------------------------------------------
// GitHub resources condition
// ---------------------------------------------------------------------------

func TestGitHubResourcesCondition_IsDynamic(t *testing.T) {
	mod := Modifier{Condition: &githubResourcesCondition{}}
	assert.True(t, mod.IsDynamic())
}

// ---------------------------------------------------------------------------
// GitLab resources condition
// ---------------------------------------------------------------------------

func TestGitLabResourcesCondition_IsDynamic(t *testing.T) {
	mod := Modifier{Condition: &gitlabResourcesCondition{}}
	assert.True(t, mod.IsDynamic())
}

// ---------------------------------------------------------------------------
// STS nil input handling
// ---------------------------------------------------------------------------

func TestAWSS3BucketsCondition_NilMatch(t *testing.T) {
	cond := &awsS3BucketsCondition{}
	fired, err := cond.Evaluate(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestAWSSecretsManagerCondition_NilMatch(t *testing.T) {
	cond := &awsSecretsManagerCondition{}
	fired, err := cond.Evaluate(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, fired)
}
