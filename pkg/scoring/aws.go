package scoring

import (
	"context"
	"fmt"
	"strings"

	awslib "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/titus/pkg/types"
)

// extractAWSCredentials extracts the key ID and secret access key from a
// match's NamedGroups. Returns (keyID, secretKey, true) on success.
// Both named groups must be non-empty.
func extractAWSCredentials(m *types.Match) (keyID, secretKey string, ok bool) {
	if m == nil {
		return "", "", false
	}
	kid, hasKey := m.NamedGroups["key_id"]
	sec, hasSecret := m.NamedGroups["secret_key"]
	if !hasKey || !hasSecret || len(kid) == 0 || len(sec) == 0 {
		return "", "", false
	}
	return string(kid), string(sec), true
}

// iamPolicyCondition fires when any of the listed managed policy names are
// attached to the IAM user associated with the given credentials.
// onlyIfExclusive=true fires only when the match policies are the ONLY ones
// attached (used for read-only detection).
type iamPolicyCondition struct {
	matchPolicies   []string // e.g. ["AdministratorAccess", "PowerUserAccess"]
	onlyIfExclusive bool     // true = fires only when no other policies are attached
}

func (c *iamPolicyCondition) markDynamic() {}

func (c *iamPolicyCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	keyID, secretKey, ok := extractAWSCredentials(m)
	if !ok {
		return false, nil
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(keyID, secretKey, ""),
		),
		awsconfig.WithRegion("us-east-1"),
	)
	if err != nil {
		return false, fmt.Errorf("aws config: %w", err)
	}

	// Get the caller's IAM username from STS
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return false, nil // credential doesn't work; upstream stsKeyActive handles this
	}

	// Extract username from ARN: arn:aws:iam::123456789012:user/MyUser
	username := extractUsernameFromARN(awslib.ToString(identity.Arn))
	if username == "" {
		return false, nil // not an IAM user (e.g. assumed role, root) — skip
	}

	// List attached managed policies with pagination
	iamClient := iam.NewFromConfig(cfg)
	var attached []string
	paginator := iam.NewListAttachedUserPoliciesPaginator(iamClient, &iam.ListAttachedUserPoliciesInput{
		UserName: awslib.String(username),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return false, nil // IAM permission denied — condition doesn't fire
		}
		for _, p := range page.AttachedPolicies {
			attached = append(attached, awslib.ToString(p.PolicyName))
		}
	}

	// Check for match policies
	matchSet := make(map[string]bool, len(c.matchPolicies))
	for _, p := range c.matchPolicies {
		matchSet[p] = true
	}

	found := false
	for _, name := range attached {
		if matchSet[name] {
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}

	// For exclusive-match (read-only detection): ensure no non-matching policies
	if c.onlyIfExclusive {
		for _, name := range attached {
			if !matchSet[name] {
				return false, nil // has additional policies beyond the read-only set
			}
		}
	}

	return true, nil
}

// extractUsernameFromARN parses "arn:aws:iam::123456789012:user/MyUser" → "MyUser".
// Returns empty string for non-user ARNs (root, assumed-role, etc.).
func extractUsernameFromARN(arn string) string {
	const prefix = ":user/"
	idx := strings.LastIndex(arn, prefix)
	if idx < 0 {
		return ""
	}
	return arn[idx+len(prefix):]
}

// stsKeyActiveCondition fires when the key is a live, working AWS credential.
// Uses STS GetCallerIdentity which requires no IAM permissions.
// Implements networkCondition so it is gated behind --score-scope.
type stsKeyActiveCondition struct{}

func (c *stsKeyActiveCondition) markDynamic() {}

func (c *stsKeyActiveCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	keyID, secretKey, ok := extractAWSCredentials(m)
	if !ok {
		return false, nil
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(keyID, secretKey, ""),
		),
		awsconfig.WithRegion("us-east-1"),
	)
	if err != nil {
		return false, fmt.Errorf("aws config: %w", err)
	}

	client := sts.NewFromConfig(cfg)
	_, err = client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		// Credential rejected — not an error in the scoring sense, just doesn't fire
		return false, nil
	}
	return true, nil
}
