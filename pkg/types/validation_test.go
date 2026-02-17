// pkg/types/validation_test.go
package types

import (
	"encoding/json"
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

func TestValidationResult_JSON(t *testing.T) {
	result := NewValidationResult(StatusInvalid, 0.95, "credentials rejected")
	
	// Marshal
	data, err := json.Marshal(result)
	assert.NoError(t, err)
	
	// Check JSON structure
	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	
	assert.Equal(t, "invalid", decoded["status"])
	assert.Equal(t, 0.95, decoded["confidence"])
	assert.Equal(t, "credentials rejected", decoded["message"])
	assert.NotEmpty(t, decoded["validated_at"])
}

func TestValidationResult_JSON_Omitempty(t *testing.T) {
	// nil result should be omitted when pointer
	type wrapper struct {
		Result *ValidationResult `json:"validation_result,omitempty"`
	}
	
	w := wrapper{Result: nil}
	data, err := json.Marshal(w)
	assert.NoError(t, err)
	assert.Equal(t, "{}", string(data))
}
