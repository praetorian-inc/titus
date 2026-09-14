package validator

import (
	"context"
	"math"
	"math/rand"
	"sync/atomic"
	"time"
)

// BackoffController tracks consecutive errors across concurrent workers and
// computes an adaptive backoff delay once a configurable error threshold is
// reached. Below the threshold, Wait returns immediately. At or above the
// threshold, the delay grows exponentially with the number of errors past
// the threshold, jittered, and capped at maxDelay.
type BackoffController struct {
	threshold   int64
	baseDelay   time.Duration
	maxDelay    time.Duration
	consecutive atomic.Int64
}

// NewBackoffController creates a BackoffController. threshold is the number
// of consecutive errors that must accumulate before any delay is applied.
// baseDelay is the initial delay applied at the threshold, and maxDelay caps
// the exponential growth.
func NewBackoffController(threshold int64, baseDelay, maxDelay time.Duration) *BackoffController {
	return &BackoffController{
		threshold: threshold,
		baseDelay: baseDelay,
		maxDelay:  maxDelay,
	}
}

// RecordError increments the consecutive error counter. Safe for concurrent use.
func (b *BackoffController) RecordError() {
	b.consecutive.Add(1)
}

// RecordSuccess resets the consecutive error counter to zero. Safe for concurrent use.
func (b *BackoffController) RecordSuccess() {
	b.consecutive.Store(0)
}

// ConsecutiveErrors returns the current consecutive error count.
func (b *BackoffController) ConsecutiveErrors() int64 {
	return b.consecutive.Load()
}

// currentDelay computes the un-jittered backoff delay based on the current
// consecutive error count.
func (b *BackoffController) currentDelay() time.Duration {
	n := b.consecutive.Load()
	if n < b.threshold {
		return 0
	}
	exp := float64(n - b.threshold)
	delay := float64(b.baseDelay) * math.Pow(2, exp)
	if delay > float64(b.maxDelay) {
		delay = float64(b.maxDelay)
	}
	return time.Duration(delay)
}

// Wait blocks for the current backoff delay (if any), jittered, or until ctx
// is done, whichever comes first. It returns nil if the delay elapsed (or no
// delay was needed), or ctx.Err() if the context was cancelled first.
func (b *BackoffController) Wait(ctx context.Context) error {
	d := b.currentDelay()
	if d == 0 {
		return nil
	}
	jitter := time.Duration(rand.Int63n(int64(d))) // #nosec G404 -- jitter for retry backoff; cryptographic randomness unnecessary.
	d = d/2 + jitter/2
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
