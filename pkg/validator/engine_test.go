// pkg/validator/engine_test.go
package validator

import (
	"context"
	"errors"
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

func TestEngine_ValidateAsync(t *testing.T) {
	mock := &mockValidator{
		name:    "test",
		ruleIDs: []string{"np.test.1"},
		result:  types.NewValidationResult(types.StatusValid, 1.0, "async result"),
	}

	engine := NewEngine(2, mock)

	match := &types.Match{
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("async-secret")},
	}

	// Start async validation
	resultCh := engine.ValidateAsync(context.Background(), match)

	// Wait for result
	result := <-resultCh
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, "async result", result.Message)
}

func TestEngine_ValidateAsync_CacheHitFastPath(t *testing.T) {
	mock := &mockValidator{
		name:    "test",
		ruleIDs: []string{"np.test.1"},
		result:  types.NewValidationResult(types.StatusValid, 1.0, ""),
	}

	engine := NewEngine(2, mock)

	match := &types.Match{
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("cached-secret")},
	}

	// Warm cache
	engine.ValidateMatch(context.Background(), match)

	// Async should return from cache immediately
	resultCh := engine.ValidateAsync(context.Background(), match)
	result := <-resultCh
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestEngine_NoValidator(t *testing.T) {
	mock := &mockValidator{
		name:    "aws-only",
		ruleIDs: []string{"np.aws.1"}, // Only handles AWS
	}

	engine := NewEngine(4, mock)

	// Request validation for non-AWS rule
	match := &types.Match{
		RuleID: "np.github.1",
		Groups: [][]byte{[]byte("ghp_xxxx")},
	}

	result, err := engine.ValidateMatch(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "no validator available")
}

func TestEngine_ValidationError(t *testing.T) {
	mock := &mockValidator{
		name:    "failing",
		ruleIDs: []string{"np.test.1"},
		err:     errors.New("network timeout"),
	}

	engine := NewEngine(4, mock)

	match := &types.Match{
		RuleID: "np.test.1",
		Groups: [][]byte{[]byte("test-secret")},
	}

	result, err := engine.ValidateMatch(context.Background(), match)
	assert.NoError(t, err) // Engine handles error gracefully
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "network timeout")
}
