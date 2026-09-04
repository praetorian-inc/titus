package scoring

import (
	"bytes"
	"context"
	"regexp"
	"strings"

	awslib "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/titus/pkg/types"
)

// extractAWSCredentials extracts the key ID, secret access key, and optional
// session token from a match. Returns (keyID, secretKey, sessionToken, true)
// on success. Both named groups must be non-empty.
func extractAWSCredentials(m *types.Match) (keyID, secretKey, sessionToken string, ok bool) {
	if m == nil {
		return "", "", "", false
	}
	kid, hasKey := m.NamedGroups["key_id"]
	sec, hasSecret := m.NamedGroups["secret_key"]
	if !hasKey || !hasSecret || len(kid) == 0 || len(sec) == 0 {
		return "", "", "", false
	}
	return string(kid), string(sec), extractSessionToken(m.Snippet.After), true
}

// extractSessionToken scans after-context bytes for an AWS session token.
// Handles both "aws_session_token=" and "AWS_SESSION_TOKEN=" key names.
// Returns empty string if not found.
func extractSessionToken(after []byte) string {
	for _, prefix := range []string{"aws_session_token=", "AWS_SESSION_TOKEN="} {
		idx := bytes.Index(after, []byte(prefix))
		if idx < 0 {
			continue
		}
		val := after[idx+len(prefix):]
		// Token ends at whitespace or end of input
		end := bytes.IndexAny(val, " \t\r\n")
		raw := val
		if end >= 0 {
			raw = val[:end]
		}
		return strings.Trim(string(raw), `"'`)
	}
	return ""
}

// iamPolicyCondition fires when any of the listed managed policy names are
// attached to the IAM user associated with the given credentials.
// onlyIfExclusive=true fires only when the match policies are the ONLY ones
// attached (used for read-only detection).
type iamPolicyCondition struct {
	matchPolicies   []string // e.g. ["AdministratorAccess", "PowerUserAccess"]
	onlyIfExclusive bool     // true = fires only when no other policies are attached
	clientFactory   awsClientFactory
}

func (c *iamPolicyCondition) markDynamic() {}

func (c *iamPolicyCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	keyID, secretKey, sessionToken, ok := extractAWSCredentials(m)
	if !ok {
		return false, nil
	}

	factory := c.clientFactory
	if factory == nil {
		factory = defaultAWSClientFactory
	}
	stsClient, iamClient, err := factory(ctx, keyID, secretKey, sessionToken)
	if err != nil {
		return false, nil
	}

	// Get the caller's IAM username from STS
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return false, nil // credential doesn't work; upstream stsKeyActive handles this
	}

	identityARN := awslib.ToString(identity.Arn)

	// List attached managed policies — try IAM user first, fall back to assumed role.
	var attached []string
	if username := extractUsernameFromARN(identityARN); username != "" {
		// ARN may include an IAM path prefix (e.g. /division/team/Alice).
		// ListAttachedUserPolicies expects only the username, not the path.
		if slash := strings.LastIndex(username, "/"); slash >= 0 {
			username = username[slash+1:]
		}
		paginator := iam.NewListAttachedUserPoliciesPaginator(iamClient, &iam.ListAttachedUserPoliciesInput{
			UserName: awslib.String(username),
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return false, nil
			}
			for _, p := range page.AttachedPolicies {
				attached = append(attached, awslib.ToString(p.PolicyName))
			}
		}
	} else if roleName := extractRoleNameFromARN(identityARN); roleName != "" {
		paginator := iam.NewListAttachedRolePoliciesPaginator(iamClient, &iam.ListAttachedRolePoliciesInput{
			RoleName: awslib.String(roleName),
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return false, nil
			}
			for _, p := range page.AttachedPolicies {
				attached = append(attached, awslib.ToString(p.PolicyName))
			}
		}
	} else {
		return false, nil // root or unrecognised ARN format
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

// extractRoleNameFromARN parses "arn:aws:sts::AccountId:assumed-role/RoleName/SessionName" → "RoleName".
// Returns empty string for non-assumed-role ARNs.
func extractRoleNameFromARN(arn string) string {
	const prefix = ":assumed-role/"
	idx := strings.LastIndex(arn, prefix)
	if idx < 0 {
		return ""
	}
	rest := arn[idx+len(prefix):]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return rest
	}
	return rest[:slash]
}

// iamCanAssumeRolesCondition fires when the credential can enumerate IAM roles,
// indicating broad sts:AssumeRole scope is likely available.
type iamCanAssumeRolesCondition struct {
	clientFactory awsClientFactory
}

func (c *iamCanAssumeRolesCondition) markDynamic() {}

func (c *iamCanAssumeRolesCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	keyID, secretKey, sessionToken, ok := extractAWSCredentials(m)
	if !ok {
		return false, nil
	}

	factory := c.clientFactory
	if factory == nil {
		factory = defaultAWSClientFactory
	}
	_, iamClient, err := factory(ctx, keyID, secretKey, sessionToken)
	if err != nil {
		return false, nil
	}
	// ListRoles requires iam:ListRoles — if it succeeds, the key has broad IAM read
	_, err = iamClient.ListRoles(ctx, &iam.ListRolesInput{MaxItems: awslib.Int32(1)})
	return err == nil, nil
}

// stsKeyActiveCondition fires when the key is a live, working AWS credential.
// Uses STS GetCallerIdentity which requires no IAM permissions.
// Implements networkCondition so it is gated behind --score-scope.
type stsKeyActiveCondition struct {
	clientFactory awsClientFactory
}

func (c *stsKeyActiveCondition) markDynamic() {}

func (c *stsKeyActiveCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
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
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return false, nil
	}

	if m.Owner == nil {
		arn := awslib.ToString(identity.Arn)
		m.Owner = &types.OwnerInfo{
			Service:   "aws",
			AccountID: awslib.ToString(identity.Account),
			ARN:       arn,
		}
		if username := extractUsernameFromARN(arn); username != "" {
			m.Owner.User = username
		} else if roleName := extractRoleNameFromARN(arn); roleName != "" {
			m.Owner.User = roleName
		}
	}

	return true, nil
}

// AWSGoScorer returns a *Scorer targeting AWS credential rules.
// It supersedes the YAML aws-key-scope scorer when registered first
// in buildScoringEngine().
//
// Targets np.aws.6 (combined key+secret) since STS/IAM calls require both.
// Static AKIA/ASIA/AIDA prefix modifiers are included so the scorer remains
// useful even when --score-scope is disabled.
func AWSGoScorer() *Scorer {
	return &Scorer{
		Name:    "aws-iam-scope",
		RuleIDs: []string{"np.aws.6"},
		Modifiers: []Modifier{
			// Static (always run, no network)
			{
				Name:     "akia-long-term",
				Priority: 100,
				Kind:     ModifierKindDelta,
				Value:    10,
				Condition: &matchGroupCondition{
					Name:  "key_id",
					Regex: regexp.MustCompile(`(?i)^AKIA`),
				},
			},
			{
				Name:     "asia-temporary-session",
				Priority: 100,
				Kind:     ModifierKindDelta,
				Value:    -10,
				Condition: &matchGroupCondition{
					Name:  "key_id",
					Regex: regexp.MustCompile(`(?i)^ASIA`),
				},
			},
			{
				Name:     "aida-identifier-only",
				Priority: 100,
				Kind:     ModifierKindSetScore,
				Value:    10,
				Condition: &matchGroupCondition{
					Name:  "key_id",
					Regex: regexp.MustCompile(`(?i)^AIDA`),
				},
			},
			// Dynamic (network, requires --score-scope)
			{
				Name:      "key-active",
				Priority:  95,
				Kind:      ModifierKindDelta,
				Value:     5,
				Condition: &stsKeyActiveCondition{},
			},
			{
				Name:     "iam-admin",
				Priority: 90,
				Kind:     ModifierKindSetScore,
				Value:    99,
				Condition: &iamPolicyCondition{
					matchPolicies: []string{"AdministratorAccess", "PowerUserAccess"},
				},
			},
			{
				Name:     "iam-write-access",
				Priority: 80,
				Kind:     ModifierKindSetScore,
				Value:    85,
				Condition: &iamPolicyCondition{
					matchPolicies: []string{"IAMFullAccess", "AmazonEC2FullAccess",
						"AmazonS3FullAccess", "AmazonRDSFullAccess"},
				},
			},
			{
				Name:     "iam-read-only",
				Priority: 70,
				Kind:     ModifierKindDelta,
				Value:    -20,
				Condition: &iamPolicyCondition{
					matchPolicies:   []string{"ReadOnlyAccess", "ViewOnlyAccess"},
					onlyIfExclusive: true,
				},
			},
			{
				Name:      "iam-can-assume-roles",
				Priority:  60,
				Kind:      ModifierKindDelta,
				Value:     10,
				Condition: &iamCanAssumeRolesCondition{},
			},
			// Resource enumeration (low priority, runs after scoring)
			{
				Name:      "has-secrets-manager",
				Priority:  15,
				Kind:      ModifierKindDelta,
				Value:     15,
				Condition: &awsSecretsManagerCondition{},
			},
			{
				Name:      "has-prod-s3-buckets",
				Priority:  10,
				Kind:      ModifierKindDelta,
				Value:     10,
				Condition: &awsS3BucketsCondition{},
			},
		},
	}
}
