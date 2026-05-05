package scoring

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestExtractAWSCredentials_BothGroupsPresent(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"key_id":     []byte("AKIAIOSFODNN7EXAMPLE"),
			"secret_key": []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
	}
	keyID, secretKey, ok := extractAWSCredentials(m)
	assert.True(t, ok)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", keyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", secretKey)
}

func TestExtractAWSCredentials_MissingSecretKey_ReturnsFalse(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"key_id": []byte("AKIAIOSFODNN7EXAMPLE"),
		},
	}
	_, _, ok := extractAWSCredentials(m)
	assert.False(t, ok, "should return false when secret_key is missing")
}

func TestExtractAWSCredentials_NilMatch_ReturnsFalse(t *testing.T) {
	_, _, ok := extractAWSCredentials(nil)
	assert.False(t, ok)
}

func TestSTSKeyActiveCondition_IsDynamic(t *testing.T) {
	cond := &stsKeyActiveCondition{}
	mod := Modifier{Condition: cond}
	assert.True(t, mod.IsDynamic(), "stsKeyActiveCondition should be dynamic (requires network)")
}

func TestIAMPolicyCondition_IsDynamic(t *testing.T) {
	cond := &iamPolicyCondition{matchPolicies: []string{"AdministratorAccess"}}
	mod := Modifier{Condition: cond}
	assert.True(t, mod.IsDynamic())
}

func TestExtractUsernameFromARN(t *testing.T) {
	assert.Equal(t, "MyUser", extractUsernameFromARN("arn:aws:iam::123456789012:user/MyUser"))
	assert.Equal(t, "", extractUsernameFromARN("arn:aws:sts::123456789012:assumed-role/MyRole/session"))
	assert.Equal(t, "", extractUsernameFromARN(""))
}
