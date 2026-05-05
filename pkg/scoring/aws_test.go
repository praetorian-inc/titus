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
