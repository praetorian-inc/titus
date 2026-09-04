package types

// OwnerInfo identifies who owns or created a detected credential.
// Populated as a best-effort side-effect of scorer API calls — fields
// are only set when the upstream API returns them.
type OwnerInfo struct {
	// Service is the provider name (e.g. "aws", "github", "gitlab", "slack").
	Service string `json:"service"`
	// User is the human-readable username or login (e.g. GitHub login, IAM username).
	User string `json:"user,omitempty"`
	// Email is the owner's email address, when available.
	Email string `json:"email,omitempty"`
	// AccountID is the provider-level account or org identifier (e.g. AWS account ID, Slack team ID).
	AccountID string `json:"account_id,omitempty"`
	// ARN is the full resource identifier for AWS credentials.
	ARN string `json:"arn,omitempty"`
	// DisplayName is the owner's display/full name, when available.
	DisplayName string `json:"display_name,omitempty"`
}
