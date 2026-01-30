// pkg/validator/aws_test.go
package validator

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestAWSValidator_Name(t *testing.T) {
	v := NewAWSValidator()
	assert.Equal(t, "aws", v.Name())
}

func TestAWSValidator_CanValidate(t *testing.T) {
	v := NewAWSValidator()

	// AWS rules it can potentially handle
	assert.True(t, v.CanValidate("np.aws.1"))
	assert.True(t, v.CanValidate("np.aws.2"))
	assert.True(t, v.CanValidate("np.aws.6"))

	// Non-AWS rules
	assert.False(t, v.CanValidate("np.github.1"))
	assert.False(t, v.CanValidate("np.slack.1"))
}

func TestAWSValidator_ExtractCredentials_AWS6(t *testing.T) {
	v := NewAWSValidator()

	// np.aws.6 has both key ID and secret
	match := &types.Match{
		RuleID: "np.aws.6",
		Groups: [][]byte{
			[]byte("AKIAIOSFODNN7EXAMPLE"),
			[]byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
	}

	keyID, secret, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", keyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", secret)
}

func TestAWSValidator_ExtractCredentials_AWS1_Partial(t *testing.T) {
	v := NewAWSValidator()

	// np.aws.1 only has access key ID
	match := &types.Match{
		RuleID: "np.aws.1",
		Groups: [][]byte{
			[]byte("AKIAIOSFODNN7EXAMPLE"),
		},
	}

	keyID, secret, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial")
	assert.Empty(t, keyID)
	assert.Empty(t, secret)
}

func TestAWSValidator_ExtractCredentials_AWS2_Partial(t *testing.T) {
	v := NewAWSValidator()

	// np.aws.2 only has secret
	match := &types.Match{
		RuleID: "np.aws.2",
		Groups: [][]byte{
			[]byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
	}

	keyID, secret, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial")
	assert.Empty(t, keyID)
	assert.Empty(t, secret)
}

// mockSTSClient implements STSClient for testing
type mockSTSClient struct {
	callerIdentity *sts.GetCallerIdentityOutput
	err            error
}

func (m *mockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return m.callerIdentity, m.err
}

func TestAWSValidator_WithSTSClient(t *testing.T) {
	mock := &mockSTSClient{
		callerIdentity: &sts.GetCallerIdentityOutput{
			Account: aws.String("123456789012"),
			Arn:     aws.String("arn:aws:iam::123456789012:user/test"),
			UserId:  aws.String("AIDAEXAMPLE"),
		},
	}

	v := NewAWSValidatorWithClient(mock)
	assert.NotNil(t, v)
}

func TestAWSValidator_Validate_Valid(t *testing.T) {
	mock := &mockSTSClient{
		callerIdentity: &sts.GetCallerIdentityOutput{
			Account: aws.String("123456789012"),
			Arn:     aws.String("arn:aws:iam::123456789012:user/testuser"),
			UserId:  aws.String("AIDAEXAMPLE"),
		},
	}

	v := NewAWSValidatorWithClient(mock)

	match := &types.Match{
		RuleID: "np.aws.6",
		Groups: [][]byte{
			[]byte("AKIAIOSFODNN7EXAMPLE"),
			[]byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "123456789012")
}

func TestAWSValidator_Validate_Invalid(t *testing.T) {
	mock := &mockSTSClient{
		err: fmt.Errorf("InvalidClientTokenId: The security token included in the request is invalid"),
	}

	v := NewAWSValidatorWithClient(mock)

	match := &types.Match{
		RuleID: "np.aws.6",
		Groups: [][]byte{
			[]byte("AKIAINVALIDKEYEXAMP"),
			[]byte("InvalidSecretKeyThatDoesNotExistInAWS1234"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
}

func TestAWSValidator_Validate_Partial(t *testing.T) {
	v := NewAWSValidator()

	// np.aws.1 only has access key ID
	match := &types.Match{
		RuleID: "np.aws.1",
		Groups: [][]byte{
			[]byte("AKIAIOSFODNN7EXAMPLE"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "partial")
}

func TestAWSValidator_Validate_ContextCancelled(t *testing.T) {
	mock := &mockSTSClient{
		err: context.Canceled,
	}

	v := NewAWSValidatorWithClient(mock)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	match := &types.Match{
		RuleID: "np.aws.6",
		Groups: [][]byte{
			[]byte("AKIAIOSFODNN7EXAMPLE"),
			[]byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
	}

	result, err := v.Validate(ctx, match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}
