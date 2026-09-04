package scoring

import (
	"context"

	awslib "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/praetorian-inc/titus/pkg/types"
)

const maxResourcesPerType = 10

type s3API interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
}

type secretsManagerAPI interface {
	ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

type awsResourceClientFactory func(ctx context.Context, keyID, secretKey, sessionToken string) (s3API, secretsManagerAPI, error)

func defaultAWSResourceClientFactory(ctx context.Context, keyID, secretKey, sessionToken string) (s3API, secretsManagerAPI, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(keyID, secretKey, sessionToken),
		),
		awsconfig.WithRegion("us-east-1"),
	)
	if err != nil {
		return nil, nil, err
	}
	return s3.NewFromConfig(cfg), secretsmanager.NewFromConfig(cfg), nil
}

// awsS3BucketsCondition enumerates accessible S3 buckets and populates
// m.Resources. Always fires true when buckets are found so it can apply
// a score delta for production-named buckets.
type awsS3BucketsCondition struct {
	clientFactory        awsClientFactory
	resourceClientFactory awsResourceClientFactory
}

func (c *awsS3BucketsCondition) markDynamic() {}

func (c *awsS3BucketsCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	keyID, secretKey, sessionToken, ok := extractAWSCredentials(m)
	if !ok {
		return false, nil
	}

	// Verify the key is active first via STS.
	factory := c.clientFactory
	if factory == nil {
		factory = defaultAWSClientFactory
	}
	stsClient, _, err := factory(ctx, keyID, secretKey, sessionToken)
	if err != nil {
		return false, nil
	}
	if _, err := stsClient.GetCallerIdentity(ctx, nil); err != nil {
		return false, nil
	}

	rcFactory := c.resourceClientFactory
	if rcFactory == nil {
		rcFactory = defaultAWSResourceClientFactory
	}
	s3Client, _, err := rcFactory(ctx, keyID, secretKey, sessionToken)
	if err != nil {
		return false, nil
	}

	out, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return false, nil
	}

	hasProd := false
	for i, b := range out.Buckets {
		if i >= maxResourcesPerType {
			break
		}
		name := awslib.ToString(b.Name)
		m.Resources = append(m.Resources, types.ResourceInfo{
			Service: "aws",
			Type:    "s3_bucket",
			Name:    name,
		})
		if containsSensitiveName(name) {
			hasProd = true
		}
	}
	if len(out.Buckets) > maxResourcesPerType {
		m.Resources = append(m.Resources, types.ResourceInfo{
			Service: "aws",
			Type:    "s3_bucket",
			Count:   len(out.Buckets),
			Name:    "total",
		})
	}

	return hasProd, nil
}

// awsSecretsManagerCondition checks if SecretsManager is accessible and
// populates m.Resources with secret names. Fires true when any secrets are
// found — this is high-severity (credential can reach other credentials).
type awsSecretsManagerCondition struct {
	clientFactory        awsClientFactory
	resourceClientFactory awsResourceClientFactory
}

func (c *awsSecretsManagerCondition) markDynamic() {}

func (c *awsSecretsManagerCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	keyID, secretKey, sessionToken, ok := extractAWSCredentials(m)
	if !ok {
		return false, nil
	}

	factory := c.clientFactory
	if factory == nil {
		factory = defaultAWSClientFactory
	}
	stsClient, _, err := factory(ctx, keyID, secretKey, sessionToken)
	if err != nil {
		return false, nil
	}
	if _, err := stsClient.GetCallerIdentity(ctx, nil); err != nil {
		return false, nil
	}

	rcFactory := c.resourceClientFactory
	if rcFactory == nil {
		rcFactory = defaultAWSResourceClientFactory
	}
	_, smClient, err := rcFactory(ctx, keyID, secretKey, sessionToken)
	if err != nil {
		return false, nil
	}

	maxResults := int32(maxResourcesPerType)
	out, err := smClient.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
		MaxResults: &maxResults,
	})
	if err != nil {
		return false, nil
	}

	for _, secret := range out.SecretList {
		m.Resources = append(m.Resources, types.ResourceInfo{
			Service: "aws",
			Type:    "secret",
			Name:    awslib.ToString(secret.Name),
		})
	}

	return len(out.SecretList) > 0, nil
}

func containsSensitiveName(name string) bool {
	for _, keyword := range []string{"prod", "customer", "backup", "pii", "secret", "credential"} {
		if containsIgnoreCase(name, keyword) {
			return true
		}
	}
	return false
}

func containsIgnoreCase(s, substr string) bool {
	ls, lsub := len(s), len(substr)
	if lsub > ls {
		return false
	}
	for i := 0; i <= ls-lsub; i++ {
		match := true
		for j := 0; j < lsub; j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			t := substr[j]
			if t >= 'A' && t <= 'Z' {
				t += 32
			}
			if c != t {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
