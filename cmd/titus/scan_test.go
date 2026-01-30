// cmd/titus/scan_test.go
package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanFlags_Validate(t *testing.T) {
	// Verify default values
	assert.False(t, scanValidate, "validate should be disabled by default")
	assert.Equal(t, 4, scanValidateWorkers, "default workers should be 4")
}
