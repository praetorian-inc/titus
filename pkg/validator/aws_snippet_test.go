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

	// np.aws.1 with key_id named group and secret key in snippet.After
	match := &types.Match{
		RuleID: "np.aws.1",
		NamedGroups: map[string][]byte{
			"key_id": []byte("AKIAIOSFODNN7EXAMPLE"),
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

	// np.aws.1 with key_id named group and secret key but no session token in snippet.After
	match := &types.Match{
		RuleID: "np.aws.1",
		NamedGroups: map[string][]byte{
			"key_id": []byte("AKIAIOSFODNN7EXAMPLE"),
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

	// np.aws.1 with key_id named group but without secret in snippet
	match := &types.Match{
		RuleID: "np.aws.1",
		NamedGroups: map[string][]byte{
			"key_id": []byte("AKIAIOSFODNN7EXAMPLE"),
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

// TestAWSValidator_ExtractCredentials_AWS1_SecretInBefore tests finding secret in snippet.Before
func TestAWSValidator_ExtractCredentials_AWS1_SecretInBefore(t *testing.T) {
	v := NewAWSValidator()

	match := &types.Match{
		RuleID: "np.aws.1",
		NamedGroups: map[string][]byte{
			"key_id": []byte("AKIAIOSFODNN7EXAMPLE"),
		},
		Snippet: types.Snippet{
			Before:   []byte("export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nexport AWS_ACCESS_KEY_ID="),
			Matching: []byte("AKIAIOSFODNN7EXAMPLE"),
			After:    []byte("\n"),
		},
	}

	keyID, secret, _, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", keyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", secret)
}

// TestAWSValidator_ExtractCredentials_AWS2_KeyIDInBefore tests np.aws.2 finding access key in Before
func TestAWSValidator_ExtractCredentials_AWS2_KeyIDInBefore(t *testing.T) {
	v := NewAWSValidator()

	match := &types.Match{
		RuleID: "np.aws.2",
		NamedGroups: map[string][]byte{
			"secret_key": []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
		Snippet: types.Snippet{
			Before:   []byte("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY="),
			Matching: []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
	}

	keyID, secret, _, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", keyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", secret)
}

// TestAWSValidator_ExtractCredentials_AWS2_KeyIDInAfter tests np.aws.2 finding access key in After
func TestAWSValidator_ExtractCredentials_AWS2_KeyIDInAfter(t *testing.T) {
	v := NewAWSValidator()

	match := &types.Match{
		RuleID: "np.aws.2",
		NamedGroups: map[string][]byte{
			"secret_key": []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
		Snippet: types.Snippet{
			Matching: []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
			After:    []byte("\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"),
		},
	}

	keyID, secret, _, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", keyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", secret)
}

// TestAWSValidator_ExtractCredentials_AWS2_WithSessionToken tests np.aws.2 with session token in snippet
func TestAWSValidator_ExtractCredentials_AWS2_WithSessionToken(t *testing.T) {
	v := NewAWSValidator()

	match := &types.Match{
		RuleID: "np.aws.2",
		NamedGroups: map[string][]byte{
			"secret_key": []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
		Snippet: types.Snippet{
			Before:   []byte("export AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY="),
			Matching: []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
			After:    []byte("\nexport AWS_SESSION_TOKEN=FwoGZXIvYXdzEBQaDMk"),
		},
	}

	keyID, secret, sessionToken, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "ASIAIOSFODNN7EXAMPLE", keyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", secret)
	assert.Equal(t, "FwoGZXIvYXdzEBQaDMk", sessionToken)
}

// TestAWSValidator_ExtractCredentials_AWS2_BareKeyID tests np.aws.2 finding bare access key (no label)
func TestAWSValidator_ExtractCredentials_AWS2_BareKeyID(t *testing.T) {
	v := NewAWSValidator()

	match := &types.Match{
		RuleID: "np.aws.2",
		NamedGroups: map[string][]byte{
			"secret_key": []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
		Snippet: types.Snippet{
			Before:   []byte("key: AKIAIOSFODNN7EXAMPLE\nsecret: "),
			Matching: []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
	}

	keyID, secret, _, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", keyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", secret)
}

// TestAWSValidator_ExtractCredentials_AWS6_FallbackToSnippet tests np.aws.6 falling back to snippet
func TestAWSValidator_ExtractCredentials_AWS6_FallbackToSnippet(t *testing.T) {
	v := NewAWSValidator()

	// np.aws.6 with only key_id in named groups, secret in snippet
	match := &types.Match{
		RuleID: "np.aws.6",
		NamedGroups: map[string][]byte{
			"key_id": []byte("AKIAIOSFODNN7EXAMPLE"),
		},
		Snippet: types.Snippet{
			After: []byte("\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
	}

	keyID, secret, _, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", keyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", secret)
}

// TestAWSValidator_ExtractCredentials_AWS4_FromSnippet tests np.aws.4 finding key_id + secret in snippet
func TestAWSValidator_ExtractCredentials_AWS4_FromSnippet(t *testing.T) {
	v := NewAWSValidator()

	match := &types.Match{
		RuleID: "np.aws.4",
		NamedGroups: map[string][]byte{
			"session_token": []byte("FwoGZXIvYXdzEBQaDMk"),
		},
		Snippet: types.Snippet{
			Before: []byte("export AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nexport AWS_SESSION_TOKEN="),
		},
	}

	keyID, secret, sessionToken, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "ASIAIOSFODNN7EXAMPLE", keyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", secret)
	assert.Equal(t, "FwoGZXIvYXdzEBQaDMk", sessionToken)
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
		NamedGroups: map[string][]byte{
			"key_id": []byte("ASIAIOSFODNN7EXAMPLE"), // Session token starts with ASIA
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

// TestAWSValidator_Validate_AWS2_WithSnippet tests end-to-end validation for np.aws.2 with mock STS
func TestAWSValidator_Validate_AWS2_WithSnippet(t *testing.T) {
	mock := &mockSTSClient{
		callerIdentity: &sts.GetCallerIdentityOutput{
			Account: aws.String("987654321098"),
			Arn:     aws.String("arn:aws:iam::987654321098:user/leaked-user"),
			UserId:  aws.String("AIDAEXAMPLE2"),
		},
	}

	v := NewAWSValidatorWithClient(mock)

	match := &types.Match{
		RuleID: "np.aws.2",
		NamedGroups: map[string][]byte{
			"secret_key": []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
		Snippet: types.Snippet{
			Before:   []byte("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY="),
			Matching: []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "987654321098")
}
