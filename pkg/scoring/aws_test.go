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
	keyID, secretKey, sessionToken, ok := extractAWSCredentials(m)
	assert.True(t, ok)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", keyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", secretKey)
	assert.Equal(t, "", sessionToken, "no session token in Snippet.After")
}

func TestExtractAWSCredentials_MissingSecretKey_ReturnsFalse(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"key_id": []byte("AKIAIOSFODNN7EXAMPLE"),
		},
	}
	_, _, _, ok := extractAWSCredentials(m)
	assert.False(t, ok, "should return false when secret_key is missing")
}

func TestExtractAWSCredentials_NilMatch_ReturnsFalse(t *testing.T) {
	_, _, _, ok := extractAWSCredentials(nil)
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

func (m *mockIAM) ListAttachedRolePolicies(_ context.Context, _ *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	// Reuse the same policies list as the user mock for simplicity
	out := &iam.ListAttachedRolePoliciesOutput{}
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
	return func(_ context.Context, _, _, _ string) (stsAPI, iamAPI, error) {
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

func TestExtractSessionToken_Found(t *testing.T) {
	after := []byte("aws_session_token=IQoJb3JpZ2luX2Vj\nsome_other_field=value")
	assert.Equal(t, "IQoJb3JpZ2luX2Vj", extractSessionToken(after))
}

func TestExtractSessionToken_NotFound(t *testing.T) {
	assert.Equal(t, "", extractSessionToken([]byte("no_token_here")))
}

func TestExtractAWSCredentials_IncludesSessionToken(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"key_id":     []byte("ASIARBRVNUL45ECBD7XM"),
			"secret_key": []byte("someSecretKey"),
		},
		Snippet: types.Snippet{
			After: []byte("aws_session_token=MYTOKEN\nmore_stuff"),
		},
	}
	keyID, secretKey, sessionToken, ok := extractAWSCredentials(m)
	require.True(t, ok)
	assert.Equal(t, "ASIARBRVNUL45ECBD7XM", keyID)
	assert.Equal(t, "someSecretKey", secretKey)
	assert.Equal(t, "MYTOKEN", sessionToken)
}

func TestExtractRoleNameFromARN(t *testing.T) {
	assert.Equal(t, "AWSReservedSSO_AdministratorAccess_721c6f9ee1b6b207",
		extractRoleNameFromARN("arn:aws:sts::072052744953:assumed-role/AWSReservedSSO_AdministratorAccess_721c6f9ee1b6b207/michael.weber@praetorian.com"))
	assert.Equal(t, "", extractRoleNameFromARN("arn:aws:iam::123456789012:user/MyUser"))
	assert.Equal(t, "", extractRoleNameFromARN(""))
}

func TestIAMPolicyCondition_FiresForAssumedRoleWithAdminPolicy(t *testing.T) {
	cond := &iamPolicyCondition{
		matchPolicies: []string{"AdministratorAccess"},
		clientFactory: fakeFactory(
			&mockSTS{identity: &sts.GetCallerIdentityOutput{
				Arn: awslib.String("arn:aws:sts::072052744953:assumed-role/AWSReservedSSO_AdministratorAccess_721c6f9ee1b6b207/user"),
			}},
			&mockIAM{policies: []string{"AdministratorAccess"}},
		),
	}
	fired, err := cond.Evaluate(context.Background(), testMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestIAMPolicyCondition_FiresReadOnlyForViewOnlyRole(t *testing.T) {
	cond := &iamPolicyCondition{
		matchPolicies:   []string{"ReadOnlyAccess", "ViewOnlyAccess"},
		onlyIfExclusive: true,
		clientFactory: fakeFactory(
			&mockSTS{identity: &sts.GetCallerIdentityOutput{
				Arn: awslib.String("arn:aws:sts::072052744953:assumed-role/AWSReservedSSO_ViewOnlyAccess_31b2c92fb36ab54f/user"),
			}},
			&mockIAM{policies: []string{"ViewOnlyAccess"}},
		),
	}
	fired, err := cond.Evaluate(context.Background(), testMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestExtractSessionToken_StripsQuotes(t *testing.T) {
	assert.Equal(t, "TOKEN123", extractSessionToken([]byte(`AWS_SESSION_TOKEN="TOKEN123"`)))
	assert.Equal(t, "TOKEN123", extractSessionToken([]byte(`aws_session_token='TOKEN123'`)))
	assert.Equal(t, "TOKEN123", extractSessionToken([]byte("aws_session_token=TOKEN123\n")))
}

func TestExtractUsernameFromARN_WithPath(t *testing.T) {
	// Path-qualified users: only the final segment is the username
	assert.Equal(t, "division/MyUser", extractUsernameFromARN("arn:aws:iam::123456789012:user/division/MyUser"))
	// The iamPolicyCondition strips the path before calling ListAttachedUserPolicies
}
