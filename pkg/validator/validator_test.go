// pkg/validator/validator_test.go
package validator

import (
	"context"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

// mockValidator implements Validator for testing
type mockValidator struct {
	name    string
	ruleIDs []string
	result  *types.ValidationResult
	err     error
}

func (m *mockValidator) Name() string { return m.name }

func (m *mockValidator) CanValidate(ruleID string) bool {
	for _, rid := range m.ruleIDs {
		if rid == ruleID {
			return true
		}
	}
	return false
}

func (m *mockValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	return m.result, m.err
}

func TestValidator_Interface(t *testing.T) {
	mock := &mockValidator{
		name:    "test-validator",
		ruleIDs: []string{"np.test.1"},
		result:  types.NewValidationResult(types.StatusValid, 1.0, "ok"),
	}

	// Verify interface implementation
	var v Validator = mock

	assert.Equal(t, "test-validator", v.Name())
	assert.True(t, v.CanValidate("np.test.1"))
	assert.False(t, v.CanValidate("np.other.1"))

	result, err := v.Validate(context.Background(), &types.Match{RuleID: "np.test.1"})
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}
