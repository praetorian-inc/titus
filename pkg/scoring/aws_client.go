package scoring

import (
	"context"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// stsAPI is the STS operation subset used by scorers.
type stsAPI interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// iamAPI is the IAM operation subset used by scorers.
type iamAPI interface {
	ListAttachedUserPolicies(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
}

// awsClientFactory creates STS and IAM clients from a key+secret.
// Inject a fake factory in tests; the default uses real AWS SDK.
type awsClientFactory func(ctx context.Context, keyID, secretKey, sessionToken string) (stsAPI, iamAPI, error)

func defaultAWSClientFactory(ctx context.Context, keyID, secretKey, sessionToken string) (stsAPI, iamAPI, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(keyID, secretKey, sessionToken),
		),
		awsconfig.WithRegion("us-east-1"),
	)
	if err != nil {
		return nil, nil, err
	}
	return sts.NewFromConfig(cfg), iam.NewFromConfig(cfg), nil
}
