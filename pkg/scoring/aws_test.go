package scoring

import (
	"context"
	"fmt"
	"testing"

	awslib "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractAWSCredentials_BothGroupsPresent(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"key_id":     []byte("AKIAIOSFODNN7EXAMPLE"),
			"secret_key": []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
	}
	keyID, secretKey, ok := extractAWSCredentials(m)
	assert.True(t, ok)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", keyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", secretKey)
}

func TestExtractAWSCredentials_MissingSecretKey_ReturnsFalse(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"key_id": []byte("AKIAIOSFODNN7EXAMPLE"),
		},
	}
	_, _, ok := extractAWSCredentials(m)
	assert.False(t, ok, "should return false when secret_key is missing")
}

func TestExtractAWSCredentials_NilMatch_ReturnsFalse(t *testing.T) {
	_, _, ok := extractAWSCredentials(nil)
	assert.False(t, ok)
}

func TestSTSKeyActiveCondition_IsDynamic(t *testing.T) {
	cond := &stsKeyActiveCondition{}
	mod := Modifier{Condition: cond}
	assert.True(t, mod.IsDynamic(), "stsKeyActiveCondition should be dynamic (requires network)")
}

func TestIAMPolicyCondition_IsDynamic(t *testing.T) {
	cond := &iamPolicyCondition{matchPolicies: []string{"AdministratorAccess"}}
	mod := Modifier{Condition: cond}
	assert.True(t, mod.IsDynamic())
}

func TestExtractUsernameFromARN(t *testing.T) {
	assert.Equal(t, "MyUser", extractUsernameFromARN("arn:aws:iam::123456789012:user/MyUser"))
	assert.Equal(t, "", extractUsernameFromARN("arn:aws:sts::123456789012:assumed-role/MyRole/session"))
	assert.Equal(t, "", extractUsernameFromARN(""))
}

func TestIAMCanAssumeRolesCondition_IsDynamic(t *testing.T) {
	mod := Modifier{Condition: &iamCanAssumeRolesCondition{}}
	assert.True(t, mod.IsDynamic())
}

// ---------------------------------------------------------------------------
// Mock implementations for injectable client factory tests
// ---------------------------------------------------------------------------

type mockSTS struct {
	identity *sts.GetCallerIdentityOutput
	err      error
}

func (m *mockSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return m.identity, m.err
}

type mockIAM struct {
	policies    []string // policy names to return
	listRolesErr error
}

func (m *mockIAM) ListAttachedUserPolicies(_ context.Context, _ *iam.ListAttachedUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	out := &iam.ListAttachedUserPoliciesOutput{}
	for _, name := range m.policies {
		n := name
		out.AttachedPolicies = append(out.AttachedPolicies, iamtypes.AttachedPolicy{PolicyName: &n})
	}
	return out, nil
}

func (m *mockIAM) ListRoles(_ context.Context, _ *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if m.listRolesErr != nil {
		return nil, m.listRolesErr
	}
	return &iam.ListRolesOutput{}, nil
}

func fakeFactory(stsClient stsAPI, iamClient iamAPI) awsClientFactory {
	return func(_ context.Context, _, _ string) (stsAPI, iamAPI, error) {
		return stsClient, iamClient, nil
	}
}

func testMatch() *types.Match {
	return &types.Match{
		NamedGroups: map[string][]byte{
			"key_id":     []byte("AKIAIOSFODNN7EXAMPLE"),
			"secret_key": []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
	}
}

// ---------------------------------------------------------------------------
// Mock-based unit tests
// ---------------------------------------------------------------------------

func TestSTSKeyActiveCondition_FiresWhenKeyWorks(t *testing.T) {
	cond := &stsKeyActiveCondition{
		clientFactory: fakeFactory(
			&mockSTS{identity: &sts.GetCallerIdentityOutput{}},
			&mockIAM{},
		),
	}
	fired, err := cond.Evaluate(context.Background(), testMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestSTSKeyActiveCondition_DoesNotFireWhenKeyRejected(t *testing.T) {
	cond := &stsKeyActiveCondition{
		clientFactory: fakeFactory(
			&mockSTS{err: fmt.Errorf("InvalidClientTokenId")},
			&mockIAM{},
		),
	}
	fired, err := cond.Evaluate(context.Background(), testMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestIAMPolicyCondition_FiresWhenAdminPolicyAttached(t *testing.T) {
	cond := &iamPolicyCondition{
		matchPolicies: []string{"AdministratorAccess"},
		clientFactory: fakeFactory(
			&mockSTS{identity: &sts.GetCallerIdentityOutput{
				Arn: awslib.String("arn:aws:iam::123456789012:user/TestUser"),
			}},
			&mockIAM{policies: []string{"AdministratorAccess"}},
		),
	}
	fired, err := cond.Evaluate(context.Background(), testMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestIAMPolicyCondition_DoesNotFireWhenNoPoliciesMatch(t *testing.T) {
	cond := &iamPolicyCondition{
		matchPolicies: []string{"AdministratorAccess"},
		clientFactory: fakeFactory(
			&mockSTS{identity: &sts.GetCallerIdentityOutput{
				Arn: awslib.String("arn:aws:iam::123456789012:user/TestUser"),
			}},
			&mockIAM{policies: []string{"ReadOnlyAccess"}},
		),
	}
	fired, err := cond.Evaluate(context.Background(), testMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestIAMCanAssumeRolesCondition_FiresWhenListRolesSucceeds(t *testing.T) {
	cond := &iamCanAssumeRolesCondition{
		clientFactory: fakeFactory(&mockSTS{}, &mockIAM{}),
	}
	fired, err := cond.Evaluate(context.Background(), testMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestSTSKeyActiveCondition_SkipsASIAKey(t *testing.T) {
	// ASIA* keys require session token not in the match; condition must skip them.
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"key_id":     []byte("ASIARBRVNUL45ECBD7XM"),
			"secret_key": []byte("someSecretKey"),
		},
	}
	cond := &stsKeyActiveCondition{
		// If the factory is called it means the guard didn't fire — fail the test.
		clientFactory: func(_ context.Context, _, _ string) (stsAPI, iamAPI, error) {
			t.Fatal("factory should not be called for ASIA* keys")
			return nil, nil, nil
		},
	}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.False(t, fired, "ASIA* key should not fire stsKeyActiveCondition")
}

func TestIAMPolicyCondition_SkipsASIAKey(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"key_id":     []byte("ASIARBRVNUL45ECBD7XM"),
			"secret_key": []byte("someSecretKey"),
		},
	}
	cond := &iamPolicyCondition{
		matchPolicies: []string{"AdministratorAccess"},
		clientFactory: func(_ context.Context, _, _ string) (stsAPI, iamAPI, error) {
			t.Fatal("factory should not be called for ASIA* keys")
			return nil, nil, nil
		},
	}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.False(t, fired, "ASIA* key should not fire iamPolicyCondition")
}

func TestIAMCanAssumeRolesCondition_SkipsASIAKey(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"key_id":     []byte("ASIARBRVNUL45ECBD7XM"),
			"secret_key": []byte("someSecretKey"),
		},
	}
	cond := &iamCanAssumeRolesCondition{
		clientFactory: func(_ context.Context, _, _ string) (stsAPI, iamAPI, error) {
			t.Fatal("factory should not be called for ASIA* keys")
			return nil, nil, nil
		},
	}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.False(t, fired, "ASIA* key should not fire iamCanAssumeRolesCondition")
}
