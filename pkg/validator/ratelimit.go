package validator

import (
	"golang.org/x/time/rate"
)

// SetRateLimit configures the engine to throttle validation requests to at
// most reqsPerSec requests per second. Passing a value <= 0 disables rate
// limiting (the default).
func (e *Engine) SetRateLimit(reqsPerSec float64) {
	if reqsPerSec <= 0 {
		e.limiter = nil
		return
	}
	e.limiter = rate.NewLimiter(rate.Limit(reqsPerSec), 1)
}

// SetBackoff configures the engine's adaptive backoff controller. Passing
// nil disables backoff.
func (e *Engine) SetBackoff(bc *BackoffController) {
	e.backoff = bc
}
