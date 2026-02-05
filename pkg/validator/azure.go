// pkg/validator/azure.go
package validator

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/praetorian-inc/titus/pkg/types"
)

// AzureStorageValidator validates Azure Storage credentials.
type AzureStorageValidator struct{}

func NewAzureStorageValidator() *AzureStorageValidator {
	return &AzureStorageValidator{}
}

func (v *AzureStorageValidator) Name() string {
	return "azure-storage"
}

func (v *AzureStorageValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.azure.1" ||
		ruleID == "kingfisher.azurestorage.2" ||
		ruleID == "kingfisher.azurestorage.1a" ||
		ruleID == "kingfisher.azurestorage.1b" ||
		ruleID == "kingfisher.azurestorage.1c"
}

func (v *AzureStorageValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract credentials from named capture groups
	if match.NamedGroups == nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, "no named capture groups"), nil
	}

	accountName, hasName := match.NamedGroups["account_name"]
	accountKey, hasKey := match.NamedGroups["account_key"]

	if !hasName || !hasKey {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			fmt.Sprintf("missing required groups (found: %v)", keysOfBytes(match.NamedGroups))), nil
	}

	// Pad base64 key if needed
	keyStr := string(accountKey)
	if len(keyStr)%4 != 0 {
		padding := 4 - len(keyStr)%4
		keyStr = keyStr + strings.Repeat("=", padding)
	}

	// Build connection string
	connStr := fmt.Sprintf("DefaultEndpointsProtocol=https;AccountName=%s;AccountKey=%s;EndpointSuffix=core.windows.net",
		string(accountName), keyStr)

	// Create client and validate
	client, err := azblob.NewClientFromConnectionString(connStr, nil)
	if err != nil {
		return types.NewValidationResult(types.StatusInvalid, 1.0,
			fmt.Sprintf("failed to create client: %v", err)), nil
	}

	// Try to get account info (lightweight validation call)
	pager := client.NewListContainersPager(nil)
	_, err = pager.NextPage(ctx)
	if err != nil {
		// Check if it's an auth error
		if isAzureAuthError(err) {
			return types.NewValidationResult(types.StatusInvalid, 1.0, "invalid credentials"), nil
		}
		return types.NewValidationResult(types.StatusUndetermined, 0.5,
			fmt.Sprintf("validation error: %v", err)), nil
	}

	return types.NewValidationResult(types.StatusValid, 1.0,
		fmt.Sprintf("valid Azure Storage credentials for account %s", string(accountName))), nil
}

func isAzureAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "AuthenticationFailed") ||
		strings.Contains(errStr, "AuthorizationFailure") ||
		strings.Contains(errStr, "InvalidAuthenticationInfo")
}

// keysOfBytes returns the keys of a map[string][]byte as a slice (for error messages).
func keysOfBytes(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
