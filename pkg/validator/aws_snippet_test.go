// pkg/validator/aws_snippet_test.go
package validator

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestAWSValidator_ExtractCredentials_AWS1_WithSnippet tests extraction from snippet context
func TestAWSValidator_ExtractCredentials_AWS1_WithSnippet(t *testing.T) {
	v := NewAWSValidator()

	// np.aws.1 with secret key in snippet.After
	match := &types.Match{
		RuleID: "np.aws.1",
		Groups: [][]byte{
			[]byte("AKIAIOSFODNN7EXAMPLE"),
		},
		Snippet: types.Snippet{
			Before:   []byte("export AWS_ACCESS_KEY_ID="),
			Matching: []byte("AKIAIOSFODNN7EXAMPLE"),
			After:    []byte("\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nexport AWS_SESSION_TOKEN=FwoGZXIvYXdzEBQaDMk"),
		},
	}

	keyID, secret, sessionToken, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", keyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", secret)
	assert.Equal(t, "FwoGZXIvYXdzEBQaDMk", sessionToken)
}

// TestAWSValidator_ExtractCredentials_AWS1_WithSnippet_NoSessionToken tests extraction without session token
func TestAWSValidator_ExtractCredentials_AWS1_WithSnippet_NoSessionToken(t *testing.T) {
	v := NewAWSValidator()

	// np.aws.1 with secret key but no session token in snippet.After
	match := &types.Match{
		RuleID: "np.aws.1",
		Groups: [][]byte{
			[]byte("AKIAIOSFODNN7EXAMPLE"),
		},
		Snippet: types.Snippet{
			Before:   []byte("export AWS_ACCESS_KEY_ID="),
			Matching: []byte("AKIAIOSFODNN7EXAMPLE"),
			After:    []byte("\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
		},
	}

	keyID, secret, sessionToken, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", keyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", secret)
	assert.Equal(t, "", sessionToken) // No session token
}

// TestAWSValidator_ExtractCredentials_AWS1_NoSnippetSecret tests when snippet doesn't contain secret
func TestAWSValidator_ExtractCredentials_AWS1_NoSnippetSecret(t *testing.T) {
	v := NewAWSValidator()

	// np.aws.1 without secret in snippet
	match := &types.Match{
		RuleID: "np.aws.1",
		Groups: [][]byte{
			[]byte("AKIAIOSFODNN7EXAMPLE"),
		},
		Snippet: types.Snippet{
			After: []byte("some other text"),
		},
	}

	keyID, secret, sessionToken, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial")
	assert.Empty(t, keyID)
	assert.Empty(t, secret)
	assert.Empty(t, sessionToken)
}

// TestAWSValidator_Validate_AWS1_WithSessionToken tests validation with session token
func TestAWSValidator_Validate_AWS1_WithSessionToken(t *testing.T) {
	mock := &mockSTSClient{
		callerIdentity: &sts.GetCallerIdentityOutput{
			Account: aws.String("123456789012"),
			Arn:     aws.String("arn:aws:sts::123456789012:assumed-role/test-role/session"),
			UserId:  aws.String("AROAEXAMPLE:session"),
		},
	}

	v := NewAWSValidatorWithClient(mock)

	match := &types.Match{
		RuleID: "np.aws.1",
		Groups: [][]byte{
			[]byte("ASIAIOSFODNN7EXAMPLE"), // Session token starts with ASIA
		},
		Snippet: types.Snippet{
			Before:   []byte("AWS_ACCESS_KEY_ID="),
			Matching: []byte("ASIAIOSFODNN7EXAMPLE"),
			After:    []byte("\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nAWS_SESSION_TOKEN=FwoGZXIvYXdzEBQaDMk"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "123456789012")
}
