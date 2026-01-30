// pkg/validator/engine_test.go
package validator

import (
	"context"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestEngine_New(t *testing.T) {
	mock := &mockValidator{name: "test", ruleIDs: []string{"np.test.1"}}

	engine := NewEngine(4, mock)

	assert.NotNil(t, engine)
	assert.Len(t, engine.validators, 1)
}

func TestEngine_ValidateMatch_CacheHit(t *testing.T) {
	mock := &mockValidator{
		name:    "test",
		ruleIDs: []string{"np.test.1"},
		result:  types.NewValidationResult(types.StatusValid, 1.0, "from validator"),
	}

	engine := NewEngine(4, mock)

	match := &types.Match{
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("test-secret")},
	}

	// First call - validator invoked
	result1, err := engine.ValidateMatch(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result1.Status)

	// Second call - should hit cache
	result2, err := engine.ValidateMatch(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result2.Status)
}
