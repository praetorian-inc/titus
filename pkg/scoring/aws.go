package scoring

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
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
