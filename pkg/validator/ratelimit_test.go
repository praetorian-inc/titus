package validator

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingValidator struct {
	calls atomic.Int32
}

func (v *countingValidator) Name() string                   { return "counting" }
func (v *countingValidator) CanValidate(ruleID string) bool { return ruleID == "test.1" }
func (v *countingValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	v.calls.Add(1)
	return types.NewValidationResult(types.StatusValid, 1.0, "ok"), nil
}

func TestEngine_WithRateLimit(t *testing.T) {
	cv := &countingValidator{}
	e := NewEngine(4, cv)
	e.SetRateLimit(2.0) // 2 requests/sec

	match := &types.Match{
		RuleID:  "test.1",
		Groups:  [][]byte{[]byte("secret123")},
		Snippet: types.Snippet{Matching: []byte("secret123")},
	}

	start := time.Now()
	results := make([]<-chan *types.ValidationResult, 4)
	for i := 0; i < 4; i++ {
		m := &types.Match{
			RuleID:  "test.1",
			Groups:  [][]byte{[]byte("secret" + string(rune('a'+i)))},
			Snippet: types.Snippet{Matching: []byte("secret" + string(rune('a'+i)))},
		}
		results[i] = e.ValidateAsync(context.Background(), m)
	}
	for _, ch := range results {
		r := <-ch
		require.NotNil(t, r)
	}
	elapsed := time.Since(start)
	_ = match
	assert.GreaterOrEqual(t, elapsed, 1*time.Second, "rate limit should throttle 4 requests at 2/sec")
}

func TestEngine_WithBackoff(t *testing.T) {
	bc := NewBackoffController(3, 100*time.Millisecond, 1*time.Second)
	cv := &countingValidator{}
	e := NewEngine(4, cv)
	e.SetBackoff(bc)
	assert.NotNil(t, e.backoff)
}

func TestEngine_DefaultNoRateLimit(t *testing.T) {
	cv := &countingValidator{}
	e := NewEngine(4, cv)

	match := &types.Match{
		RuleID:  "test.1",
		Groups:  [][]byte{[]byte("secret123")},
		Snippet: types.Snippet{Matching: []byte("secret123")},
	}

	start := time.Now()
	result, err := e.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Less(t, time.Since(start), 100*time.Millisecond)
}
