// pkg/types/validation_test.go
package types

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestValidationStatus_String(t *testing.T) {
	assert.Equal(t, "valid", string(StatusValid))
	assert.Equal(t, "invalid", string(StatusInvalid))
	assert.Equal(t, "undetermined", string(StatusUndetermined))
}

func TestValidationResult_New(t *testing.T) {
	result := NewValidationResult(StatusValid, 1.0, "credentials accepted")
	
	assert.Equal(t, StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Equal(t, "credentials accepted", result.Message)
	assert.False(t, result.ValidatedAt.IsZero())
}
