// pkg/validator/aws.go
package validator

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/titus/pkg/types"
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
	case "np.aws.1", "np.aws.2", "np.aws.6":
		return true
	default:
		return false
	}
}

// Validate checks AWS credentials against STS.
func (v *AWSValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials
	keyID, secret, err := v.extractCredentials(match)
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
				credentials.NewStaticCredentialsProvider(keyID, secret, ""),
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
	return types.NewValidationResult(
		types.StatusValid,
		1.0,
		fmt.Sprintf("valid AWS credentials for account %s, user %s",
			aws.ToString(identity.Account),
			aws.ToString(identity.Arn)),
	), nil
}

// extractCredentials extracts AWS credentials from match based on rule ID.
// Returns error for partial credentials (np.aws.1, np.aws.2).
func (v *AWSValidator) extractCredentials(match *types.Match) (keyID, secret string, err error) {
	switch match.RuleID {
	case "np.aws.6":
		// np.aws.6 captures both: Group[0]=keyID, Group[1]=secret
		if len(match.Groups) < 2 {
			return "", "", fmt.Errorf("np.aws.6 expected 2 groups, got %d", len(match.Groups))
		}
		return string(match.Groups[0]), string(match.Groups[1]), nil

	case "np.aws.1":
		// np.aws.1 only captures access key ID - cannot validate
		return "", "", fmt.Errorf("partial credentials: np.aws.1 only contains access key ID")

	case "np.aws.2":
		// np.aws.2 only captures secret - cannot validate
		return "", "", fmt.Errorf("partial credentials: np.aws.2 only contains secret key")

	default:
		return "", "", fmt.Errorf("unsupported rule ID: %s", match.RuleID)
	}
}
