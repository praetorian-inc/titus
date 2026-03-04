// pkg/validator/aws.go
package validator

import (
	"context"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/titus/pkg/types"
)

// Pre-compiled patterns for extracting AWS credentials from snippet context.
var (
	awsAccessKeyIDPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)AWS_ACCESS_KEY_ID[=:"\s]+((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})`),
		regexp.MustCompile(`\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b`),
	}
	awsSecretKeyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)AWS_SECRET_ACCESS_KEY[=:"\s]+([A-Za-z0-9/+=]{40})`),
	}
	awsSessionTokenPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)AWS_SESSION_TOKEN[=:"\s]+([A-Za-z0-9/+=]+)`),
	}
)

// STSClient interface for STS operations (allows mocking in tests).
type STSClient interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// AWSValidator validates AWS credentials using STS GetCallerIdentity.
type AWSValidator struct {
	stsClient STSClient // nil means create client per-validation with provided credentials
}

// NewAWSValidator creates a new AWS credential validator.
func NewAWSValidator() *AWSValidator {
	return &AWSValidator{}
}

// NewAWSValidatorWithClient creates a validator with a custom STS client (for testing).
func NewAWSValidatorWithClient(client STSClient) *AWSValidator {
	return &AWSValidator{stsClient: client}
}

// Name returns the validator name.
func (v *AWSValidator) Name() string {
	return "aws"
}

// CanValidate returns true for AWS-related rule IDs.
func (v *AWSValidator) CanValidate(ruleID string) bool {
	switch ruleID {
	case "np.aws.1", "np.aws.2", "np.aws.4", "np.aws.6":
		return true
	default:
		return false
	}
}

// Validate checks AWS credentials against STS.
func (v *AWSValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials
	keyID, secret, sessionToken, err := v.extractCredentials(match)
	if err != nil {
		// Partial credentials - return undetermined
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	// Get STS client
	client := v.stsClient
	if client == nil {
		// Create client with provided credentials
		cfg, err := config.LoadDefaultConfig(ctx,
			config.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(keyID, secret, sessionToken),
			),
			config.WithRegion("us-east-1"),
		)
		if err != nil {
			return types.NewValidationResult(
				types.StatusUndetermined,
				0,
				fmt.Sprintf("failed to create AWS config: %v", err),
			), nil
		}
		client = sts.NewFromConfig(cfg)
	}

	// Call GetCallerIdentity
	identity, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		// Invalid credentials
		return types.NewValidationResult(
			types.StatusInvalid,
			1.0,
			fmt.Sprintf("credentials rejected: %v", err),
		), nil
	}

	// Valid credentials
	result := types.NewValidationResult(
		types.StatusValid,
		1.0,
		fmt.Sprintf("valid AWS credentials for account %s, user %s",
			aws.ToString(identity.Account),
			aws.ToString(identity.Arn)),
	)
	result.Details["account"] = aws.ToString(identity.Account)
	result.Details["arn"] = aws.ToString(identity.Arn)
	result.Details["user_id"] = aws.ToString(identity.UserId)
	return result, nil
}

// extractCredentials extracts AWS credentials from match using a unified flow.
// First extracts from NamedGroups, then fills gaps by searching snippet context.
// Returns error only if key_id or secret_key is still missing after both steps.
func (v *AWSValidator) extractCredentials(match *types.Match) (keyID, secret, sessionToken string, err error) {
	// Step 1: Extract whatever is available from NamedGroups.
	if match.NamedGroups != nil {
		if b, ok := match.NamedGroups["key_id"]; ok {
			keyID = string(b)
		}
		if b, ok := match.NamedGroups["secret_key"]; ok {
			secret = string(b)
		}
		if b, ok := match.NamedGroups["session_token"]; ok {
			sessionToken = string(b)
		}
	}

	// Step 2: Search snippet context for anything still missing.
	if keyID == "" {
		keyID = searchSnippet(match.Snippet, awsAccessKeyIDPatterns)
	}
	if secret == "" {
		secret = searchSnippet(match.Snippet, awsSecretKeyPatterns)
	}
	if sessionToken == "" {
		sessionToken = searchSnippet(match.Snippet, awsSessionTokenPatterns)
	}

	// Step 3: Require at least key_id and secret.
	if keyID == "" || secret == "" {
		return "", "", "", fmt.Errorf("partial credentials: need both key_id and secret_key")
	}

	return keyID, secret, sessionToken, nil
}

// searchSnippet searches all three snippet parts (Before, Matching, After) against
// a list of patterns, returning the first captured group match.
func searchSnippet(snippet types.Snippet, patterns []*regexp.Regexp) string {
	snippetParts := [][]byte{
		snippet.Before,
		snippet.Matching,
		snippet.After,
	}

	for _, pattern := range patterns {
		for _, part := range snippetParts {
			if matches := pattern.FindSubmatch(part); len(matches) >= 2 {
				return string(matches[1])
			}
		}
	}
	return ""
}
