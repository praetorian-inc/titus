package validator

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackoffController_NoErrorsNoDelay(t *testing.T) {
	bc := NewBackoffController(3, 500*time.Millisecond, 30*time.Second)
	start := time.Now()
	err := bc.Wait(context.Background())
	require.NoError(t, err)
	assert.Less(t, time.Since(start), 10*time.Millisecond)
}

func TestBackoffController_ErrorsBelowThresholdNoDelay(t *testing.T) {
	bc := NewBackoffController(3, 500*time.Millisecond, 30*time.Second)
	bc.RecordError()
	bc.RecordError()
	start := time.Now()
	err := bc.Wait(context.Background())
	require.NoError(t, err)
	assert.Less(t, time.Since(start), 10*time.Millisecond)
}

func TestBackoffController_ErrorsAtThresholdTriggerDelay(t *testing.T) {
	bc := NewBackoffController(3, 100*time.Millisecond, 30*time.Second)
	bc.RecordError()
	bc.RecordError()
	bc.RecordError()
	start := time.Now()
	err := bc.Wait(context.Background())
	require.NoError(t, err)
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, 50*time.Millisecond, "should wait at least half the base delay (jitter)")
	assert.Less(t, elapsed, 250*time.Millisecond, "should not exceed base delay significantly")
}

func TestBackoffController_SuccessResetsCounter(t *testing.T) {
	bc := NewBackoffController(3, 100*time.Millisecond, 30*time.Second)
	bc.RecordError()
	bc.RecordError()
	bc.RecordError()
	assert.Equal(t, int64(3), bc.ConsecutiveErrors())
	bc.RecordSuccess()
	assert.Equal(t, int64(0), bc.ConsecutiveErrors())

	start := time.Now()
	err := bc.Wait(context.Background())
	require.NoError(t, err)
	assert.Less(t, time.Since(start), 10*time.Millisecond)
}

func TestBackoffController_ExponentialGrowth(t *testing.T) {
	bc := NewBackoffController(1, 100*time.Millisecond, 30*time.Second)
	for i := 0; i < 5; i++ {
		bc.RecordError()
	}
	delay := bc.currentDelay()
	assert.GreaterOrEqual(t, delay, 100*time.Millisecond)
	assert.LessOrEqual(t, delay, 30*time.Second)
}

func TestBackoffController_CappedAtMax(t *testing.T) {
	bc := NewBackoffController(1, 100*time.Millisecond, 500*time.Millisecond)
	for i := 0; i < 20; i++ {
		bc.RecordError()
	}
	delay := bc.currentDelay()
	assert.LessOrEqual(t, delay, 500*time.Millisecond)
}

func TestBackoffController_ContextCancellation(t *testing.T) {
	bc := NewBackoffController(1, 5*time.Second, 30*time.Second)
	bc.RecordError()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := bc.Wait(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestBackoffController_ConcurrentAccess(t *testing.T) {
	bc := NewBackoffController(3, 100*time.Millisecond, 30*time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bc.RecordError()
			bc.RecordSuccess()
			_ = bc.ConsecutiveErrors()
		}()
	}
	wg.Wait()
}
