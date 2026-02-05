// pkg/validator/azure_test.go
package validator

import (
	"context"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestAzureStorageValidator_Name(t *testing.T) {
	v := NewAzureStorageValidator()
	assert.Equal(t, "azure-storage", v.Name())
}

func TestAzureStorageValidator_CanValidate(t *testing.T) {
	v := NewAzureStorageValidator()

	// Azure Storage rule (np.azure.1)
	assert.True(t, v.CanValidate("np.azure.1"))

	// Other Azure rules (not handled by this validator)
	assert.False(t, v.CanValidate("np.azure.2"))
	assert.False(t, v.CanValidate("np.azure.3"))
	assert.False(t, v.CanValidate("np.azure.4"))

	// Non-Azure rules
	assert.False(t, v.CanValidate("np.aws.1"))
	assert.False(t, v.CanValidate("np.github.1"))
}

func TestAzureStorageValidator_Validate_MissingNamedGroups(t *testing.T) {
	v := NewAzureStorageValidator()

	// Match without named groups
	match := &types.Match{
		RuleID:      "np.azure.1",
		NamedGroups: nil,
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "no named capture groups")
}

func TestAzureStorageValidator_Validate_MissingAccountName(t *testing.T) {
	v := NewAzureStorageValidator()

	// Match with only account_key named group
	match := &types.Match{
		RuleID: "np.azure.1",
		NamedGroups: map[string][]byte{
			"account_key": []byte("6jqh42QQjWWBwoPGGR/Jr0PZjhBMZVbHm/gkhEfHvOj8aV6+oI8ed6ZAAwB5a6993WqyQDiuJJB0QpseJwqYxw=="),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "missing required groups")
}

func TestAzureStorageValidator_Validate_MissingAccountKey(t *testing.T) {
	v := NewAzureStorageValidator()

	// Match with only account_name named group
	match := &types.Match{
		RuleID: "np.azure.1",
		NamedGroups: map[string][]byte{
			"account_name": []byte("testaccount"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "missing required groups")
}

func TestAzureStorageValidator_Validate_InvalidCredentials(t *testing.T) {
	v := NewAzureStorageValidator()

	// Match with invalid credentials
	match := &types.Match{
		RuleID: "np.azure.1",
		NamedGroups: map[string][]byte{
			"account_name": []byte("invalidaccount"),
			"account_key":  []byte("aW52YWxpZGtleXRoYXRkb2Vzbm90d29yaw=="), // "invalidkeythatdoesnotwork" base64
		},
	}

	ctx := context.Background()
	result, err := v.Validate(ctx, match)

	// Validation should complete without error, but mark credentials as invalid or undetermined
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// The result should be either Invalid or Undetermined (depending on network/service availability)
	assert.True(t, result.Status == types.StatusInvalid || result.Status == types.StatusUndetermined,
		"Expected Invalid or Undetermined, got %v", result.Status)
}

func TestIsAzureAuthError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected bool
	}{
		{
			name:     "AuthenticationFailed error",
			errMsg:   "Server failed to authenticate the request: AuthenticationFailed",
			expected: true,
		},
		{
			name:     "AuthorizationFailure error",
			errMsg:   "AuthorizationFailure: permission denied",
			expected: true,
		},
		{
			name:     "InvalidAuthenticationInfo error",
			errMsg:   "InvalidAuthenticationInfo: bad signature",
			expected: true,
		},
		{
			name:     "Network error (not auth)",
			errMsg:   "connection timeout",
			expected: false,
		},
		{
			name:     "Nil error",
			errMsg:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.errMsg != "" {
				err = &azureTestError{msg: tt.errMsg}
			}
			result := isAzureAuthError(err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// azureTestError is a test helper for simulating Azure errors
type azureTestError struct {
	msg string
}

func (e *azureTestError) Error() string {
	return e.msg
}
