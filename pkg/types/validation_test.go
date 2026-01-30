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
