# Agentic Validation Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add LLM-augmented validation, LLM scoring conditions, and infrastructure resilience (adaptive backoff, retry, rate limiting) to titus's secrets scanning pipeline.

**Architecture:** Four independently shippable phases. Phase 1 adds retry/backoff/rate-limiting to the validator engine with no new dependencies. Phase 2 builds a provider-agnostic LLM client (`pkg/llm/`). Phase 3 wraps the validator engine with an LLM verifier that upgrades `undetermined` results. Phase 4 adds an `llmCondition` to the scoring engine loadable from YAML.

**Tech Stack:** Go 1.22+, `golang.org/x/time/rate` (already in go.mod), `net/http` for Anthropic API (no SDK), `github.com/stretchr/testify` for tests.

**Spec:** `docs/superpowers/specs/2026-09-14-agentic-validation-pipeline-design.md`

## Global Constraints

- No new external Go module dependencies except what's already in go.mod (`x/time`, `x/sync`, `testify`)
- Anthropic API integration uses raw `net/http` + JSON marshaling — no SDK
- All LLM features are off by default; existing behavior unchanged when flags are absent
- All tests use `httptest.Server` or mock interfaces — no real API calls in CI
- `go vet ./...` and `go test ./...` must pass after every task
- Template variables use the existing `{{name}}` / `{{ name }}` syntax from `substituteTemplateVars`

---

## File Structure

### Phase 1: Infrastructure Resilience (pkg/validator/)

| File | Action | Responsibility |
|------|--------|---------------|
| `pkg/validator/backoff.go` | Create | Adaptive backoff controller — atomic consecutive-error counter, exponential delay with jitter |
| `pkg/validator/backoff_test.go` | Create | Unit tests for BackoffController |
| `pkg/validator/retry.go` | Create | RetryHTTPClient wrapping `*http.Client` with retry logic for 429/5xx/connection errors |
| `pkg/validator/retry_test.go` | Create | Unit tests for RetryHTTPClient using httptest.Server |
| `pkg/validator/ratelimit.go` | Create | Rate-limiter integration for Engine.ValidateAsync |
| `pkg/validator/ratelimit_test.go` | Create | Unit tests for rate limiter wiring |
| `pkg/validator/engine.go` | Modify | Add `backoff`, `limiter` fields; apply rate limit in ValidateAsync |
| `pkg/validator/http.go` | Modify | Use RetryHTTPClient instead of http.DefaultClient |
| `cmd/titus/scan.go` | Modify | Add `--validate-rate-limit` flag, wire into engine |

### Phase 2: LLM Client Foundation (pkg/llm/)

| File | Action | Responsibility |
|------|--------|---------------|
| `pkg/llm/client.go` | Create | Client interface, Request/Response/Usage types, NewClient factory |
| `pkg/llm/client_test.go` | Create | Factory tests |
| `pkg/llm/anthropic.go` | Create | Anthropic Messages API implementation |
| `pkg/llm/anthropic_test.go` | Create | Tests against httptest.Server |
| `pkg/llm/cache.go` | Create | Thread-safe response cache keyed by SHA256(system+user) |
| `pkg/llm/cache_test.go` | Create | Cache hit/miss/concurrency tests |
| `pkg/llm/sanitize.go` | Create | Strip null bytes, ANSI, control chars; truncate; XML-wrap untrusted input |
| `pkg/llm/sanitize_test.go` | Create | Sanitization tests |

### Phase 3: LLM-Augmented Validation

| File | Action | Responsibility |
|------|--------|---------------|
| `pkg/types/validation.go` | Modify | Add ResponseMeta struct and field to ValidationResult |
| `pkg/validator/http.go` | Modify | Capture ResponseMeta in tryURL |
| `pkg/validator/jenkins.go` | Modify | Capture ResponseMeta from /whoAmI response |
| `pkg/validator/verifier.go` | Create | LLMVerifier wrapping Engine — second-pass LLM review of undetermined results |
| `pkg/validator/verifier_test.go` | Create | Verifier decision logic, budget, upgrade/no-downgrade tests |
| `cmd/titus/scan.go` | Modify | Add `--llm-verify`, `--llm-budget`, `--llm-model`, `--llm-timeout` flags |

### Phase 4: LLM Scoring Conditions

| File | Action | Responsibility |
|------|--------|---------------|
| `pkg/scoring/condition_llm.go` | Create | llmCondition implementing Condition + networkCondition |
| `pkg/scoring/condition_llm_test.go` | Create | Tests with mock LLM client |
| `pkg/scoring/yaml.go` | Modify | Add `LLM *yamlLLMDef` to yamlModifier |
| `pkg/scoring/loader.go` | Modify | Parse `llm:` condition blocks in convertYAMLModifier |
| `pkg/scoring/engine.go` | Modify | Handle llmCondition in Score() similar to httpCondition |
| `cmd/titus/scan.go` | Modify | Pass LLM client to scoring engine when --score-scope enabled |

---

### Task 1: Adaptive Backoff Controller

**Files:**
- Create: `pkg/validator/backoff.go`
- Create: `pkg/validator/backoff_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `BackoffController` struct with `RecordError()`, `RecordSuccess()`, `Wait(ctx) error`, `ConsecutiveErrors() int64`

- [ ] **Step 1: Write the failing test for BackoffController**

```go
// pkg/validator/backoff_test.go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/titus && go test ./pkg/validator/ -run TestBackoffController -v -count=1`
Expected: compilation error — `NewBackoffController` undefined

- [ ] **Step 3: Write minimal implementation**

```go
// pkg/validator/backoff.go
package validator

import (
	"context"
	"math"
	"math/rand"
	"sync/atomic"
	"time"
)

type BackoffController struct {
	threshold    int64
	baseDelay    time.Duration
	maxDelay     time.Duration
	consecutive  atomic.Int64
}

func NewBackoffController(threshold int64, baseDelay, maxDelay time.Duration) *BackoffController {
	return &BackoffController{
		threshold: threshold,
		baseDelay: baseDelay,
		maxDelay:  maxDelay,
	}
}

func (b *BackoffController) RecordError() {
	b.consecutive.Add(1)
}

func (b *BackoffController) RecordSuccess() {
	b.consecutive.Store(0)
}

func (b *BackoffController) ConsecutiveErrors() int64 {
	return b.consecutive.Load()
}

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

func (b *BackoffController) Wait(ctx context.Context) error {
	d := b.currentDelay()
	if d == 0 {
		return nil
	}
	jitter := time.Duration(rand.Int63n(int64(d)))
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/titus && go test ./pkg/validator/ -run TestBackoffController -v -count=1`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/validator/backoff.go pkg/validator/backoff_test.go
git commit -m "feat(validator): add adaptive backoff controller

Tracks consecutive connection errors across workers via atomic counter.
Injects exponential backoff delay with jitter above a configurable
threshold, capped at a maximum. Thread-safe for concurrent access."
```

---

### Task 2: Retry HTTP Client

**Files:**
- Create: `pkg/validator/retry.go`
- Create: `pkg/validator/retry_test.go`

**Interfaces:**
- Consumes: `BackoffController` from Task 1 (RecordError, RecordSuccess, Wait)
- Produces: `RetryHTTPClient` struct with `Do(req *http.Request) (*http.Response, error)` — drop-in replacement for `*http.Client.Do`

- [ ] **Step 1: Write the failing tests**

```go
// pkg/validator/retry_test.go
package validator

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetryHTTPClient_SuccessNoRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	rc := NewRetryHTTPClient(srv.Client(), nil)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, int32(1), calls.Load())
}

func TestRetryHTTPClient_429RetriesOnce(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	rc := NewRetryHTTPClient(srv.Client(), nil)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, int32(2), calls.Load())
}

func TestRetryHTTPClient_429RetryAfterCapped(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "9999")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	rc := NewRetryHTTPClient(srv.Client(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, int32(2), calls.Load())
}

func TestRetryHTTPClient_5xxRetriesOnce(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	rc := NewRetryHTTPClient(srv.Client(), nil)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, int32(2), calls.Load())
}

func TestRetryHTTPClient_4xxNoRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(401)
	}))
	defer srv.Close()

	rc := NewRetryHTTPClient(srv.Client(), nil)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 401, resp.StatusCode)
	assert.Equal(t, int32(1), calls.Load())
}

func TestRetryHTTPClient_5xxPersistsReturnsLast(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(503)
	}))
	defer srv.Close()

	rc := NewRetryHTTPClient(srv.Client(), nil)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 503, resp.StatusCode)
	assert.Equal(t, int32(2), calls.Load())
}

func TestRetryHTTPClient_BackoffRecordsErrorAndSuccess(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	bc := NewBackoffController(3, 100*time.Millisecond, 1*time.Second)
	rc := NewRetryHTTPClient(srv.Client(), bc)

	bc.RecordError()
	bc.RecordError()
	assert.Equal(t, int64(2), bc.ConsecutiveErrors())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := rc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, int64(0), bc.ConsecutiveErrors(), "success should reset backoff")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/titus && go test ./pkg/validator/ -run TestRetryHTTPClient -v -count=1`
Expected: compilation error — `NewRetryHTTPClient` undefined

- [ ] **Step 3: Write minimal implementation**

```go
// pkg/validator/retry.go
package validator

import (
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	retryMaxAttempts     = 2
	retryBackoffDelay    = 1 * time.Second
	retryAfterCap        = 30 * time.Second
)

type RetryHTTPClient struct {
	inner   *http.Client
	backoff *BackoffController
}

func NewRetryHTTPClient(inner *http.Client, backoff *BackoffController) *RetryHTTPClient {
	if inner == nil {
		inner = http.DefaultClient
	}
	return &RetryHTTPClient{inner: inner, backoff: backoff}
}

func (c *RetryHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if c.backoff != nil {
		if err := c.backoff.Wait(req.Context()); err != nil {
			return nil, err
		}
	}

	var lastResp *http.Response
	var lastErr error

	for attempt := 0; attempt < retryMaxAttempts; attempt++ {
		if attempt > 0 && lastResp != nil {
			_, _ = io.Copy(io.Discard, lastResp.Body)
			_ = lastResp.Body.Close()
		}

		resp, err := c.inner.Do(req)
		if err != nil {
			if c.backoff != nil {
				c.backoff.RecordError()
			}
			lastErr = err
			lastResp = nil
			if attempt < retryMaxAttempts-1 {
				if c.backoff != nil {
					if waitErr := c.backoff.Wait(req.Context()); waitErr != nil {
						return nil, waitErr
					}
				} else {
					if sleepErr := sleepCtx(req.Context(), retryBackoffDelay); sleepErr != nil {
						return nil, sleepErr
					}
				}
			}
			continue
		}

		lastResp = resp
		lastErr = nil

		switch {
		case resp.StatusCode == 429:
			if c.backoff != nil {
				c.backoff.RecordError()
			}
			if attempt < retryMaxAttempts-1 {
				delay := parseRetryAfter(resp.Header.Get("Retry-After"))
				if sleepErr := sleepCtx(req.Context(), delay); sleepErr != nil {
					return resp, nil
				}
				continue
			}
		case resp.StatusCode >= 500:
			if c.backoff != nil {
				c.backoff.RecordError()
			}
			if attempt < retryMaxAttempts-1 {
				if sleepErr := sleepCtx(req.Context(), retryBackoffDelay); sleepErr != nil {
					return resp, nil
				}
				continue
			}
		default:
			if c.backoff != nil {
				c.backoff.RecordSuccess()
			}
			return resp, nil
		}
	}

	if lastResp != nil {
		if c.backoff != nil {
			c.backoff.RecordSuccess()
		}
		return lastResp, nil
	}
	return nil, lastErr
}

func parseRetryAfter(val string) time.Duration {
	if val == "" {
		return retryBackoffDelay
	}
	secs, err := strconv.Atoi(val)
	if err != nil || secs < 0 {
		return retryBackoffDelay
	}
	d := time.Duration(secs) * time.Second
	if d > retryAfterCap {
		d = retryAfterCap
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
```

Note: `sleepCtx` requires adding `"context"` to the import block.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/titus && go test ./pkg/validator/ -run TestRetryHTTPClient -v -count=1`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/validator/retry.go pkg/validator/retry_test.go
git commit -m "feat(validator): add RetryHTTPClient with 429/5xx retry

Wraps http.Client with single-retry logic: respects Retry-After for 429
(capped 30s), retries 5xx once after 1s, retries connection errors with
backoff controller delay. 2xx/3xx/4xx pass through immediately."
```

---

### Task 3: Rate Limiter + Engine Wiring

**Files:**
- Create: `pkg/validator/ratelimit.go`
- Create: `pkg/validator/ratelimit_test.go`
- Modify: `pkg/validator/engine.go:52-69` (Engine struct and NewEngine)
- Modify: `pkg/validator/engine.go:131-176` (ValidateAsync)
- Modify: `pkg/validator/http.go:24-31` (NewHTTPValidator)
- Modify: `cmd/titus/scan.go:58-87` (add flag variable)
- Modify: `cmd/titus/scan.go:2064-2070` (initValidationEngine)

**Interfaces:**
- Consumes: `BackoffController` from Task 1, `RetryHTTPClient` from Task 2
- Produces: `SetRateLimit(reqsPerSec float64)` and `SetBackoff(bc *BackoffController)` methods on `*Engine`

- [ ] **Step 1: Write the failing test for engine options**

```go
// pkg/validator/ratelimit_test.go
package validator

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/praetorian-inc/titus/pkg/types"
)

type countingValidator struct {
	calls atomic.Int32
}

func (v *countingValidator) Name() string                { return "counting" }
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
		RuleID: "test.1",
		Groups: [][]byte{[]byte("secret123")},
		Snippet: types.Snippet{Matching: []byte("secret123")},
	}

	start := time.Now()
	results := make([]<-chan *types.ValidationResult, 4)
	for i := 0; i < 4; i++ {
		m := &types.Match{
			RuleID: "test.1",
			Groups: [][]byte{[]byte("secret" + string(rune('a'+i)))},
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
		RuleID: "test.1",
		Groups: [][]byte{[]byte("secret123")},
		Snippet: types.Snippet{Matching: []byte("secret123")},
	}

	start := time.Now()
	result, err := e.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Less(t, time.Since(start), 100*time.Millisecond)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/titus && go test ./pkg/validator/ -run "TestEngine_With|TestEngine_Default" -v -count=1`
Expected: compilation error — `SetRateLimit` undefined

- [ ] **Step 3: Implement rate limiter and engine wiring**

Create `pkg/validator/ratelimit.go`:

```go
package validator

import (
	"golang.org/x/time/rate"
)

func (e *Engine) SetRateLimit(reqsPerSec float64) {
	if reqsPerSec <= 0 {
		e.limiter = nil
		return
	}
	e.limiter = rate.NewLimiter(rate.Limit(reqsPerSec), 1)
}

func (e *Engine) SetBackoff(bc *BackoffController) {
	e.backoff = bc
}
```

Modify `pkg/validator/engine.go` — add fields to `Engine` struct (line 52):

```go
type Engine struct {
	validators []Validator
	cache      *ValidationCache
	workers    int
	sem        chan struct{}
	limiter    *rate.Limiter        // optional rate limiter
	backoff    *BackoffController   // optional adaptive backoff
}
```

Add `"golang.org/x/time/rate"` to imports.

Modify `ValidateAsync` (engine.go line 155, after semaphore acquisition) to add rate limit wait:

```go
		// Acquire semaphore (bounded concurrency)
		select {
		case e.sem <- struct{}{}:
			defer func() { <-e.sem }()
		case <-ctx.Done():
			result <- types.NewValidationResult(types.StatusUndetermined, 0, "context cancelled")
			return
		}

		// Apply rate limit if configured.
		if e.limiter != nil {
			if err := e.limiter.Wait(ctx); err != nil {
				result <- types.NewValidationResult(types.StatusUndetermined, 0, "rate limit cancelled")
				return
			}
		}
```

Modify `cmd/titus/scan.go` — add flag variable near line 74:

```go
	scanValidateRateLimit float64
```

Add flag registration near line 110:

```go
	scanCmd.Flags().Float64Var(&scanValidateRateLimit, "validate-rate-limit", 0, "max validation requests per second (0 = unlimited)")
```

Modify `initValidationEngine` (scan.go line 2064) to wire options:

```go
func initValidationEngine() *validator.Engine {
	if !scanValidate {
		return nil
	}
	e := validator.NewDefaultEngine(scanValidateWorkers)
	if scanValidateRateLimit > 0 {
		e.SetRateLimit(scanValidateRateLimit)
	}
	bc := validator.NewBackoffController(3, 500*time.Millisecond, 30*time.Second)
	e.SetBackoff(bc)
	return e
}
```

Modify `pkg/validator/http.go` — change `NewHTTPValidator` to accept and use `RetryHTTPClient` (line 24):

```go
func NewHTTPValidator(def ValidatorDef, client *http.Client) *HTTPValidator {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPValidator{
		def:    def,
		client: client,
	}
}
```

The HTTPValidator already stores `*http.Client`. To enable retry, the embedded YAML validator loader should pass a `RetryHTTPClient`-backed `http.Client` (via `Transport` wrapping). However, since `RetryHTTPClient` operates at the `Do()` level, and `HTTPValidator` uses `v.client.Do(req)`, the simplest integration is to change the `client` field type. This is deferred to a follow-up refinement — for now the backoff controller and rate limiter are wired at the `Engine` level.

**Out of scope for this plan:** The spec mentions a `NewValidatorHTTPClient()` helper for Go validators that create their own `http.Client` (Jenkins, Mattermost, TrueNAS, etc.). Each Go validator can adopt `RetryHTTPClient` incrementally in separate PRs once Phase 1 ships — it's a one-line change per validator (`v.client = NewRetryHTTPClient(v.client, bc)`). Not blocking this plan.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/titus && go test ./pkg/validator/ -run "TestEngine_With|TestEngine_Default" -v -count=1`
Expected: all PASS

- [ ] **Step 5: Run full validator test suite**

Run: `cd /workspace/titus && go test ./pkg/validator/... -count=1`
Expected: all PASS, no regressions

- [ ] **Step 6: Commit**

```bash
git add pkg/validator/ratelimit.go pkg/validator/ratelimit_test.go pkg/validator/engine.go cmd/titus/scan.go
git commit -m "feat(validator): add rate limiting and wire backoff into engine

Engine gains optional rate limiter (--validate-rate-limit flag) and
adaptive backoff controller. Rate limit applied in ValidateAsync before
dispatching to validators. Backoff always enabled with sensible defaults
(threshold=3, base=500ms, max=30s)."
```

---

### Task 4: LLM Client Interface and Factory

**Files:**
- Create: `pkg/llm/client.go`
- Create: `pkg/llm/client_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `Client` interface with `Complete(ctx, *Request) (*Response, error)`, `Request`, `Response`, `Usage`, `Message` types, `NewClient(provider, apiKey, model string, opts ...Option) (Client, error)` factory

- [ ] **Step 1: Write the failing tests**

```go
// pkg/llm/client_test.go
package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient_Anthropic(t *testing.T) {
	c, err := NewClient("anthropic", "test-key", "claude-haiku-4-5-20251001")
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestNewClient_UnknownProvider(t *testing.T) {
	_, err := NewClient("openai", "test-key", "gpt-4")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported provider")
}

func TestNewClient_EmptyAPIKey(t *testing.T) {
	_, err := NewClient("anthropic", "", "claude-haiku-4-5-20251001")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API key")
}

func TestMessage_Roles(t *testing.T) {
	m := Message{Role: "user", Content: "hello"}
	assert.Equal(t, "user", m.Role)

	m2 := Message{Role: "assistant", Content: "hi"}
	assert.Equal(t, "assistant", m2.Role)
}

func TestRequest_Defaults(t *testing.T) {
	r := &Request{
		System:    "You are helpful.",
		Messages:  []Message{{Role: "user", Content: "test"}},
		MaxTokens: 256,
	}
	assert.Equal(t, 256, r.MaxTokens)
	assert.Len(t, r.Messages, 1)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/titus && go test ./pkg/llm/ -run "TestNewClient|TestMessage|TestRequest" -v -count=1`
Expected: compilation error — package `pkg/llm` does not exist

- [ ] **Step 3: Write minimal implementation**

```go
// pkg/llm/client.go
package llm

import (
	"context"
	"fmt"
	"time"
)

type Client interface {
	Complete(ctx context.Context, req *Request) (*Response, error)
}

type Request struct {
	System    string
	Messages  []Message
	MaxTokens int
}

type Message struct {
	Role    string
	Content string
}

type Response struct {
	Content string
	Model   string
	Usage   Usage
}

type Usage struct {
	InputTokens  int
	OutputTokens int
}

type Option func(*clientConfig)

type clientConfig struct {
	Timeout    time.Duration
	MaxRetries int
	BaseURL    string
}

func WithTimeout(d time.Duration) Option {
	return func(c *clientConfig) { c.Timeout = d }
}

func WithMaxRetries(n int) Option {
	return func(c *clientConfig) { c.MaxRetries = n }
}

func WithBaseURL(url string) Option {
	return func(c *clientConfig) { c.BaseURL = url }
}

func NewClient(provider, apiKey, model string, opts ...Option) (Client, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}

	cfg := clientConfig{
		Timeout:    15 * time.Second,
		MaxRetries: 1,
	}
	for _, o := range opts {
		o(&cfg)
	}

	switch provider {
	case "anthropic":
		return newAnthropicClient(apiKey, model, cfg)
	default:
		return nil, fmt.Errorf("unsupported provider: %q", provider)
	}
}
```

Note: `newAnthropicClient` is defined in Task 5. For this task to compile, add a stub:

```go
// Temporary stub at bottom of client.go — replaced in Task 5
func newAnthropicClient(apiKey, model string, cfg clientConfig) (Client, error) {
	return &stubClient{}, nil
}

type stubClient struct{}

func (s *stubClient) Complete(ctx context.Context, req *Request) (*Response, error) {
	return nil, fmt.Errorf("not implemented")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/titus && go test ./pkg/llm/ -run "TestNewClient|TestMessage|TestRequest" -v -count=1`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/llm/client.go pkg/llm/client_test.go
git commit -m "feat(llm): add Client interface and factory

Provider-agnostic LLM client with Request/Response types. Factory
dispatches by provider string; only 'anthropic' supported initially.
Configurable timeout, retries, base URL via functional options."
```

---

### Task 5: Anthropic Implementation

**Files:**
- Create: `pkg/llm/anthropic.go`
- Create: `pkg/llm/anthropic_test.go`
- Modify: `pkg/llm/client.go` (remove stub, update factory)

**Interfaces:**
- Consumes: `Client` interface from Task 4
- Produces: `anthropicClient` implementing `Client` — direct HTTP calls to Anthropic Messages API

- [ ] **Step 1: Write the failing tests**

```go
// pkg/llm/anthropic_test.go
package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnthropicClient_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/messages", r.URL.Path)
		assert.Equal(t, "test-key", r.Header.Get("x-api-key"))
		assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))

		body, _ := io.ReadAll(r.Body)
		var reqBody map[string]any
		json.Unmarshal(body, &reqBody)
		assert.Equal(t, "claude-haiku-4-5-20251001", reqBody["model"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": `{"status":"valid","confidence":0.9,"reason":"token works"}`},
			},
			"model": "claude-haiku-4-5-20251001",
			"usage": map[string]any{"input_tokens": 100, "output_tokens": 50},
		})
	}))
	defer srv.Close()

	c, err := NewClient("anthropic", "test-key", "claude-haiku-4-5-20251001", WithBaseURL(srv.URL))
	require.NoError(t, err)

	resp, err := c.Complete(context.Background(), &Request{
		System:    "You classify secrets.",
		Messages:  []Message{{Role: "user", Content: "Is this valid?"}},
		MaxTokens: 256,
	})
	require.NoError(t, err)
	assert.Contains(t, resp.Content, "valid")
	assert.Equal(t, 100, resp.Usage.InputTokens)
	assert.Equal(t, 50, resp.Usage.OutputTokens)
}

func TestAnthropicClient_429Retry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			w.Write([]byte(`{"error":{"type":"rate_limit","message":"slow down"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{{"type": "text", "text": "ok"}},
			"model":   "claude-haiku-4-5-20251001",
			"usage":   map[string]any{"input_tokens": 10, "output_tokens": 5},
		})
	}))
	defer srv.Close()

	c, err := NewClient("anthropic", "test-key", "claude-haiku-4-5-20251001", WithBaseURL(srv.URL))
	require.NoError(t, err)
	resp, err := c.Complete(context.Background(), &Request{
		Messages:  []Message{{Role: "user", Content: "test"}},
		MaxTokens: 100,
	})
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Content)
	assert.Equal(t, 2, calls)
}

func TestAnthropicClient_529Retry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(529)
			w.Write([]byte(`{"error":{"type":"overloaded","message":"overloaded"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{{"type": "text", "text": "ok"}},
			"model":   "claude-haiku-4-5-20251001",
			"usage":   map[string]any{"input_tokens": 10, "output_tokens": 5},
		})
	}))
	defer srv.Close()

	c, err := NewClient("anthropic", "test-key", "claude-haiku-4-5-20251001", WithBaseURL(srv.URL))
	require.NoError(t, err)
	resp, err := c.Complete(context.Background(), &Request{
		Messages:  []Message{{Role: "user", Content: "test"}},
		MaxTokens: 100,
	})
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Content)
	assert.Equal(t, 2, calls)
}

func TestAnthropicClient_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":{"type":"authentication_error","message":"invalid key"}}`))
	}))
	defer srv.Close()

	c, err := NewClient("anthropic", "bad-key", "claude-haiku-4-5-20251001", WithBaseURL(srv.URL))
	require.NoError(t, err)
	_, err = c.Complete(context.Background(), &Request{
		Messages:  []Message{{Role: "user", Content: "test"}},
		MaxTokens: 100,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestAnthropicClient_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	c, err := NewClient("anthropic", "test-key", "claude-haiku-4-5-20251001",
		WithBaseURL(srv.URL), WithTimeout(100*time.Millisecond))
	require.NoError(t, err)
	_, err = c.Complete(context.Background(), &Request{
		Messages:  []Message{{Role: "user", Content: "test"}},
		MaxTokens: 100,
	})
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/titus && go test ./pkg/llm/ -run TestAnthropicClient -v -count=1`
Expected: failures — `stubClient` returns "not implemented"

- [ ] **Step 3: Write minimal implementation**

```go
// pkg/llm/anthropic.go
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const defaultAnthropicURL = "https://api.anthropic.com"

type anthropicClient struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
	retries int
}

func newAnthropicClient(apiKey, model string, cfg clientConfig) (Client, error) {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultAnthropicURL
	}
	return &anthropicClient{
		apiKey:  apiKey,
		model:   model,
		baseURL: baseURL,
		client:  &http.Client{Timeout: cfg.Timeout},
		retries: cfg.MaxRetries,
	}, nil
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Model string `json:"model"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func (c *anthropicClient) Complete(ctx context.Context, req *Request) (*Response, error) {
	msgs := make([]anthropicMessage, len(req.Messages))
	for i, m := range req.Messages {
		msgs[i] = anthropicMessage{Role: m.Role, Content: m.Content}
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 256
	}

	body := anthropicRequest{
		Model:     c.model,
		MaxTokens: maxTokens,
		System:    req.System,
		Messages:  msgs,
	}

	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		resp, err := c.doRequest(ctx, body)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

func (c *anthropicClient) doRequest(ctx context.Context, body anthropicRequest) (*Response, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/messages", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == 429 || resp.StatusCode == 529 {
		delay := time.Second
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil && secs >= 0 {
				delay = time.Duration(secs) * time.Second
				if delay > 30*time.Second {
					delay = 30 * time.Second
				}
			}
		}
		t := time.NewTimer(delay)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("HTTP %d: retryable", resp.StatusCode)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var ar anthropicResponse
	if err := json.Unmarshal(respBody, &ar); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	var content string
	for _, c := range ar.Content {
		if c.Type == "text" {
			content = c.Text
			break
		}
	}

	return &Response{
		Content: content,
		Model:   ar.Model,
		Usage: Usage{
			InputTokens:  ar.Usage.InputTokens,
			OutputTokens: ar.Usage.OutputTokens,
		},
	}, nil
}
```

Remove the `stubClient` and `newAnthropicClient` stub from `client.go`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/titus && go test ./pkg/llm/ -v -count=1`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/llm/anthropic.go pkg/llm/anthropic_test.go pkg/llm/client.go
git commit -m "feat(llm): add Anthropic Messages API implementation

Direct HTTP calls to api.anthropic.com/v1/messages with retry on 429/529,
configurable timeout, and base URL override for testing. No SDK dependency."
```

---

### Task 6: LLM Response Cache

**Files:**
- Create: `pkg/llm/cache.go`
- Create: `pkg/llm/cache_test.go`

**Interfaces:**
- Consumes: `Response` from Task 4
- Produces: `ResponseCache` struct with `Get(key string) *Response`, `Set(key string, resp *Response)`, `CacheKey(system, userMsg string) string`, `Hits() int64`

- [ ] **Step 1: Write the failing tests**

```go
// pkg/llm/cache_test.go
package llm

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResponseCache_HitAndMiss(t *testing.T) {
	c := NewResponseCache()
	key := CacheKey("system", "hello")

	got := c.Get(key)
	assert.Nil(t, got, "miss expected")

	resp := &Response{Content: "world", Usage: Usage{InputTokens: 10}}
	c.Set(key, resp)

	got = c.Get(key)
	require.NotNil(t, got)
	assert.Equal(t, "world", got.Content)
	assert.Equal(t, int64(1), c.Hits())
}

func TestResponseCache_DifferentKeys(t *testing.T) {
	c := NewResponseCache()
	k1 := CacheKey("sys", "msg1")
	k2 := CacheKey("sys", "msg2")

	c.Set(k1, &Response{Content: "one"})
	c.Set(k2, &Response{Content: "two"})

	assert.Equal(t, "one", c.Get(k1).Content)
	assert.Equal(t, "two", c.Get(k2).Content)
}

func TestCacheKey_Deterministic(t *testing.T) {
	k1 := CacheKey("system", "user message")
	k2 := CacheKey("system", "user message")
	assert.Equal(t, k1, k2)
}

func TestCacheKey_DifferentInputsDifferentKeys(t *testing.T) {
	k1 := CacheKey("system", "msg1")
	k2 := CacheKey("system", "msg2")
	assert.NotEqual(t, k1, k2)
}

func TestResponseCache_ConcurrentAccess(t *testing.T) {
	c := NewResponseCache()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := CacheKey("sys", string(rune('a'+n%26)))
			c.Set(key, &Response{Content: "val"})
			c.Get(key)
		}(i)
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/titus && go test ./pkg/llm/ -run TestResponseCache -v -count=1`
Expected: compilation error — `NewResponseCache` undefined

- [ ] **Step 3: Write minimal implementation**

```go
// pkg/llm/cache.go
package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
)

type ResponseCache struct {
	mu      sync.RWMutex
	entries map[string]*Response
	hits    atomic.Int64
}

func NewResponseCache() *ResponseCache {
	return &ResponseCache{
		entries: make(map[string]*Response),
	}
}

func CacheKey(system, userMsg string) string {
	h := sha256.New()
	h.Write([]byte(system))
	h.Write([]byte{0})
	h.Write([]byte(userMsg))
	return hex.EncodeToString(h.Sum(nil))
}

func (c *ResponseCache) Get(key string) *Response {
	c.mu.RLock()
	defer c.mu.RUnlock()
	resp, ok := c.entries[key]
	if ok {
		c.hits.Add(1)
	}
	return resp
}

func (c *ResponseCache) Set(key string, resp *Response) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = resp
}

func (c *ResponseCache) Hits() int64 {
	return c.hits.Load()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/titus && go test ./pkg/llm/ -run "TestResponseCache|TestCacheKey" -v -count=1`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/llm/cache.go pkg/llm/cache_test.go
git commit -m "feat(llm): add thread-safe response cache

SHA256-keyed by system+user prompt. Same pattern as validator's
ValidationCache. Prevents duplicate LLM calls for the same secret."
```

---

### Task 7: Prompt Sanitization

**Files:**
- Create: `pkg/llm/sanitize.go`
- Create: `pkg/llm/sanitize_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `Sanitize(input string) string`, `TruncateBody(body []byte, maxLen int) string`, `WrapUntrusted(tag, content string) string`

- [ ] **Step 1: Write the failing tests**

```go
// pkg/llm/sanitize_test.go
package llm

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitize_StripNullBytes(t *testing.T) {
	assert.Equal(t, "hello world", Sanitize("hello\x00 world"))
}

func TestSanitize_StripANSI(t *testing.T) {
	assert.Equal(t, "hello", Sanitize("\x1b[31mhello\x1b[0m"))
}

func TestSanitize_StripControlChars(t *testing.T) {
	assert.Equal(t, "ab", Sanitize("a\x01\x02\x03\x04\x05\x06\x07b"))
}

func TestSanitize_PreservesNewlinesAndTabs(t *testing.T) {
	assert.Equal(t, "a\nb\tc", Sanitize("a\nb\tc"))
}

func TestTruncateBody_Short(t *testing.T) {
	body := []byte("short")
	assert.Equal(t, "short", TruncateBody(body, 2048))
}

func TestTruncateBody_Long(t *testing.T) {
	body := []byte(strings.Repeat("x", 3000))
	result := TruncateBody(body, 2048)
	assert.Len(t, result, 2048+len("... [truncated]"))
	assert.True(t, strings.HasSuffix(result, "... [truncated]"))
}

func TestTruncateBody_ExactLimit(t *testing.T) {
	body := []byte(strings.Repeat("x", 2048))
	assert.Equal(t, string(body), TruncateBody(body, 2048))
}

func TestWrapUntrusted(t *testing.T) {
	result := WrapUntrusted("response_body", "some content")
	assert.Contains(t, result, "<response_body>")
	assert.Contains(t, result, "some content")
	assert.Contains(t, result, "</response_body>")
}

func TestWrapUntrusted_SanitizesContent(t *testing.T) {
	result := WrapUntrusted("body", "hello\x00world")
	assert.NotContains(t, result, "\x00")
	assert.Contains(t, result, "helloworld")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/titus && go test ./pkg/llm/ -run "TestSanitize|TestTruncate|TestWrapUntrusted" -v -count=1`
Expected: compilation error — `Sanitize` undefined

- [ ] **Step 3: Write minimal implementation**

```go
// pkg/llm/sanitize.go
package llm

import (
	"fmt"
	"regexp"
	"strings"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func Sanitize(input string) string {
	input = ansiPattern.ReplaceAllString(input, "")
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func TruncateBody(body []byte, maxLen int) string {
	if len(body) <= maxLen {
		return string(body)
	}
	return string(body[:maxLen]) + "... [truncated]"
}

func WrapUntrusted(tag, content string) string {
	content = Sanitize(content)
	return fmt.Sprintf("<%s>\n%s\n</%s>", tag, content, tag)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/titus && go test ./pkg/llm/ -run "TestSanitize|TestTruncate|TestWrapUntrusted" -v -count=1`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/llm/sanitize.go pkg/llm/sanitize_test.go
git commit -m "feat(llm): add prompt sanitization utilities

Strip null bytes, ANSI escapes, and control characters. Truncate response
bodies to configurable limit. Wrap untrusted input in XML tags for prompt
injection mitigation."
```

---

### Task 8: ResponseMeta Type Extension

**Files:**
- Modify: `pkg/types/validation.go:16-22` (add ResponseMeta)

**Interfaces:**
- Consumes: nothing
- Produces: `ResponseMeta` struct, new `ResponseMeta *ResponseMeta` field on `ValidationResult`

- [ ] **Step 1: Write the failing test**

```go
// Add to an existing test file or create pkg/types/validation_test.go
// pkg/types/validation_test.go
package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidationResult_ResponseMetaNil(t *testing.T) {
	r := NewValidationResult(StatusUndetermined, 0.5, "test")
	assert.Nil(t, r.ResponseMeta)
}

func TestValidationResult_ResponseMetaSet(t *testing.T) {
	r := NewValidationResult(StatusValid, 1.0, "ok")
	r.ResponseMeta = &ResponseMeta{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       []byte(`{"ok":true}`),
		URL:        "https://api.example.com/check",
	}
	assert.Equal(t, 200, r.ResponseMeta.StatusCode)
	assert.Equal(t, "application/json", r.ResponseMeta.Headers["Content-Type"])
	assert.Equal(t, "https://api.example.com/check", r.ResponseMeta.URL)
}

func TestResponseMeta_EmptyBody(t *testing.T) {
	m := &ResponseMeta{StatusCode: 204}
	assert.Empty(t, m.Body)
	assert.Nil(t, m.Headers)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/titus && go test ./pkg/types/ -run TestValidationResult_ResponseMeta -v -count=1`
Expected: compilation error — `ResponseMeta` undefined

- [ ] **Step 3: Write minimal implementation**

Add to `pkg/types/validation.go` after the `ValidationResult` struct:

```go
type ResponseMeta struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       []byte            `json:"body,omitempty"`
	URL        string            `json:"url,omitempty"`
}
```

Add field to `ValidationResult`:

```go
type ValidationResult struct {
	Status       ValidationStatus  `json:"status"`
	Confidence   float64           `json:"confidence"`
	Message      string            `json:"message"`
	ValidatedAt  time.Time         `json:"validated_at"`
	Details      map[string]string `json:"details,omitempty"`
	ResponseMeta *ResponseMeta     `json:"response_meta,omitempty"`
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/titus && go test ./pkg/types/... -v -count=1`
Expected: all PASS

- [ ] **Step 5: Run full test suite to check for regressions**

Run: `cd /workspace/titus && go test ./... -count=1 2>&1 | tail -20`
Expected: all PASS — the new field is a pointer, so existing code that doesn't set it defaults to nil

- [ ] **Step 6: Commit**

```bash
git add pkg/types/validation.go pkg/types/validation_test.go
git commit -m "feat(types): add ResponseMeta to ValidationResult

Optional field carrying HTTP status, selected headers, truncated body,
and URL from validation requests. Nil by default for backwards
compatibility. Used by Phase 3 LLM verifier to reason about responses."
```

---

### Task 9: Capture ResponseMeta in Validators

**Files:**
- Modify: `pkg/validator/http.go:74-118` (tryURL — capture response meta)
- Modify: `pkg/validator/jenkins.go:73-88` (Validate — capture response meta)

**Interfaces:**
- Consumes: `ResponseMeta` from Task 8
- Produces: Validators populate `result.ResponseMeta` on all HTTP responses

- [ ] **Step 1: Write the failing tests**

```go
// Add to pkg/validator/http_test.go (or create it)
// This tests that HTTPValidator populates ResponseMeta
package validator

// (add to existing test file if one exists)

func TestHTTPValidator_PopulatesResponseMeta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "test-value")
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"active"}`))
	}))
	defer srv.Close()

	def := ValidatorDef{
		Name:    "test-validator",
		RuleIDs: []string{"test.1"},
		HTTP: HTTPDef{
			Method:       "GET",
			URL:          srv.URL,
			Auth:         AuthDef{Type: "none"},
			SuccessCodes: []int{200},
		},
	}
	v := NewHTTPValidator(def, srv.Client())
	match := &types.Match{
		RuleID:      "test.1",
		NamedGroups: map[string][]byte{"secret": []byte("test")},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	require.NotNil(t, result.ResponseMeta)
	assert.Equal(t, 200, result.ResponseMeta.StatusCode)
	assert.Equal(t, srv.URL, result.ResponseMeta.URL)
	assert.Contains(t, string(result.ResponseMeta.Body), "active")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/titus && go test ./pkg/validator/ -run TestHTTPValidator_PopulatesResponseMeta -v -count=1`
Expected: FAIL — `result.ResponseMeta` is nil

- [ ] **Step 3: Modify HTTPValidator.tryURL to capture ResponseMeta**

In `pkg/validator/http.go`, after the `resp` body is read (line ~115), before returning `result`:

```go
	result := v.evaluateResponse(resp.StatusCode, respBody)
	v.pullThrough(result, resp.Header, respBody)

	// Capture response metadata for LLM verifier.
	selectedHeaders := make(map[string]string)
	for _, name := range []string{"Content-Type", "X-Request-Id", "Server"} {
		if val := resp.Header.Get(name); val != "" {
			selectedHeaders[name] = val
		}
	}
	bodyForMeta := respBody
	if len(bodyForMeta) == 0 {
		bodyForMeta, _ = io.ReadAll(io.LimitReader(resp.Body, 2048))
	}
	if len(bodyForMeta) > 2048 {
		bodyForMeta = bodyForMeta[:2048]
	}
	result.ResponseMeta = &types.ResponseMeta{
		StatusCode: resp.StatusCode,
		Headers:    selectedHeaders,
		Body:       bodyForMeta,
		URL:        url,
	}

	return result, nil
```

Similarly modify `pkg/validator/jenkins.go` — in the `Validate` method, after receiving `resp` (line 73), capture meta for the non-200 cases; for the 200 case, capture it in `verifyWhoAmI`:

In the switch block (line 79), before each return, attach ResponseMeta. The simplest approach: read body once, build ResponseMeta, then evaluate.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/titus && go test ./pkg/validator/ -run TestHTTPValidator_PopulatesResponseMeta -v -count=1`
Expected: PASS

- [ ] **Step 5: Run full validator test suite**

Run: `cd /workspace/titus && go test ./pkg/validator/... -count=1`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/validator/http.go pkg/validator/jenkins.go
git commit -m "feat(validator): capture ResponseMeta from HTTP responses

HTTPValidator and JenkinsValidator now populate ResponseMeta on every
ValidationResult: status code, selected headers, truncated body (2KB),
and request URL. Other Go validators that use HTTP can follow the same
pattern incrementally."
```

---

### Task 10: LLM Verifier

**Files:**
- Create: `pkg/validator/verifier.go`
- Create: `pkg/validator/verifier_test.go`

**Interfaces:**
- Consumes: `Engine` from existing code (ValidateMatch), `llm.Client` from Task 4, `ResponseMeta` from Task 8, `llm.Sanitize`/`WrapUntrusted`/`TruncateBody` from Task 7, `llm.CacheKey`/`ResponseCache` from Task 6
- Produces: `LLMVerifier` struct with `ValidateMatch(ctx, match) (*ValidationResult, error)` — same signature as Engine, wraps it with LLM second pass

- [ ] **Step 1: Write the failing tests**

```go
// pkg/validator/verifier_test.go
package validator

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/praetorian-inc/titus/pkg/llm"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLLMClient struct {
	response string
	err      error
	calls    atomic.Int32
}

func (m *mockLLMClient) Complete(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	m.calls.Add(1)
	if m.err != nil {
		return nil, m.err
	}
	return &llm.Response{
		Content: m.response,
		Usage:   llm.Usage{InputTokens: 100, OutputTokens: 50},
	}, nil
}

type staticValidator struct {
	result *types.ValidationResult
}

func (v *staticValidator) Name() string                { return "static" }
func (v *staticValidator) CanValidate(ruleID string) bool { return ruleID == "test.1" }
func (v *staticValidator) Validate(ctx context.Context, m *types.Match) (*types.ValidationResult, error) {
	return v.result, nil
}

func TestLLMVerifier_HighConfidenceSkipsLLM(t *testing.T) {
	sv := &staticValidator{result: &types.ValidationResult{
		Status: types.StatusValid, Confidence: 1.0, Message: "confirmed",
	}}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{response: `{"status":"invalid"}`}

	v := NewLLMVerifier(engine, mock, 256, 100)
	match := &types.Match{
		RuleID: "test.1",
		Groups: [][]byte{[]byte("secret")},
		Snippet: types.Snippet{Matching: []byte("secret")},
	}

	result, err := v.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, int32(0), mock.calls.Load(), "LLM should not be called for high-confidence valid")
}

func TestLLMVerifier_UndeterminedWithResponseMetaCallsLLM(t *testing.T) {
	undetermined := &types.ValidationResult{
		Status: types.StatusUndetermined, Confidence: 0.5, Message: "unclear",
		ResponseMeta: &types.ResponseMeta{
			StatusCode: 200,
			Body:       []byte(`{"user":"admin"}`),
			URL:        "https://api.example.com",
		},
	}
	sv := &staticValidator{result: undetermined}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{response: `{"status":"valid","confidence":0.9,"reason":"response shows admin access"}`}

	v := NewLLMVerifier(engine, mock, 256, 100)
	match := &types.Match{
		RuleID: "test.1",
		Groups: [][]byte{[]byte("secret")},
		Snippet: types.Snippet{
			Before:   []byte("API_KEY="),
			Matching: []byte("secret"),
			After:    []byte("\n"),
		},
	}

	result, err := v.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, int32(1), mock.calls.Load())
}

func TestLLMVerifier_UndeterminedNilResponseMetaSkipsLLM(t *testing.T) {
	undetermined := &types.ValidationResult{
		Status: types.StatusUndetermined, Confidence: 0.5, Message: "no response",
	}
	sv := &staticValidator{result: undetermined}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{response: `{"status":"valid"}`}

	v := NewLLMVerifier(engine, mock, 256, 100)
	match := &types.Match{
		RuleID: "test.1",
		Groups: [][]byte{[]byte("secret")},
		Snippet: types.Snippet{Matching: []byte("secret")},
	}

	result, err := v.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Equal(t, int32(0), mock.calls.Load())
}

func TestLLMVerifier_NeverDowngrades(t *testing.T) {
	lowConfidence := &types.ValidationResult{
		Status: types.StatusValid, Confidence: 0.6, Message: "maybe valid",
		ResponseMeta: &types.ResponseMeta{StatusCode: 200, Body: []byte("ok")},
	}
	sv := &staticValidator{result: lowConfidence}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{response: `{"status":"invalid","confidence":0.9,"reason":"looks invalid"}`}

	v := NewLLMVerifier(engine, mock, 256, 100)
	match := &types.Match{
		RuleID: "test.1",
		Groups: [][]byte{[]byte("secret")},
		Snippet: types.Snippet{Matching: []byte("secret")},
	}

	result, err := v.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status, "LLM must never downgrade valid to invalid")
}

func TestLLMVerifier_LLMErrorKeepsOriginal(t *testing.T) {
	undetermined := &types.ValidationResult{
		Status: types.StatusUndetermined, Confidence: 0.5, Message: "unclear",
		ResponseMeta: &types.ResponseMeta{StatusCode: 200, Body: []byte("x")},
	}
	sv := &staticValidator{result: undetermined}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{err: fmt.Errorf("API timeout")}

	v := NewLLMVerifier(engine, mock, 256, 100)
	match := &types.Match{
		RuleID: "test.1",
		Groups: [][]byte{[]byte("secret")},
		Snippet: types.Snippet{Matching: []byte("secret")},
	}

	result, err := v.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Equal(t, "unclear", result.Message)
}

func TestLLMVerifier_BudgetEnforcement(t *testing.T) {
	undetermined := &types.ValidationResult{
		Status: types.StatusUndetermined, Confidence: 0.5, Message: "unclear",
		ResponseMeta: &types.ResponseMeta{StatusCode: 200, Body: []byte("x")},
	}
	sv := &staticValidator{result: undetermined}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{response: `{"status":"valid","confidence":0.9,"reason":"ok"}`}

	v := NewLLMVerifier(engine, mock, 256, 2) // budget of 2

	for i := 0; i < 5; i++ {
		match := &types.Match{
			RuleID: "test.1",
			Groups: [][]byte{[]byte(fmt.Sprintf("secret%d", i))},
			Snippet: types.Snippet{Matching: []byte(fmt.Sprintf("secret%d", i))},
		}
		_, _ = v.ValidateMatch(context.Background(), match)
	}

	assert.LessOrEqual(t, mock.calls.Load(), int32(2), "should not exceed budget")
}

func TestLLMVerifier_ParseError(t *testing.T) {
	undetermined := &types.ValidationResult{
		Status: types.StatusUndetermined, Confidence: 0.5, Message: "unclear",
		ResponseMeta: &types.ResponseMeta{StatusCode: 200, Body: []byte("x")},
	}
	sv := &staticValidator{result: undetermined}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{response: "this is not json at all"}

	v := NewLLMVerifier(engine, mock, 256, 100)
	match := &types.Match{
		RuleID: "test.1",
		Groups: [][]byte{[]byte("secret")},
		Snippet: types.Snippet{Matching: []byte("secret")},
	}

	result, err := v.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status, "parse failure keeps original")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/titus && go test ./pkg/validator/ -run TestLLMVerifier -v -count=1`
Expected: compilation error — `NewLLMVerifier` undefined

- [ ] **Step 3: Write minimal implementation**

```go
// pkg/validator/verifier.go
package validator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/praetorian-inc/titus/pkg/llm"
	"github.com/praetorian-inc/titus/pkg/types"
)

type LLMVerifier struct {
	engine    *Engine
	llm       llm.Client
	cache     *llm.ResponseCache
	maxTokens int
	budget    int64
	spent     atomic.Int64
	sem       chan struct{}
}

func NewLLMVerifier(engine *Engine, client llm.Client, maxTokens int, budget int64) *LLMVerifier {
	return &LLMVerifier{
		engine:    engine,
		llm:       client,
		cache:     llm.NewResponseCache(),
		maxTokens: maxTokens,
		budget:    budget,
		sem:       make(chan struct{}, 4),
	}
}

func (v *LLMVerifier) ValidateMatch(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	result, err := v.engine.ValidateMatch(ctx, match)
	if err != nil {
		return result, err
	}

	if !v.shouldCallLLM(result) {
		return result, nil
	}

	if v.spent.Load() >= v.budget {
		return result, nil
	}

	select {
	case v.sem <- struct{}{}:
		defer func() { <-v.sem }()
	case <-ctx.Done():
		return result, nil
	}

	upgraded := v.tryLLMUpgrade(ctx, match, result)
	return upgraded, nil
}

func (v *LLMVerifier) shouldCallLLM(result *types.ValidationResult) bool {
	if result.Status == types.StatusValid && result.Confidence >= 0.9 {
		return false
	}
	if result.Status == types.StatusInvalid && result.Confidence >= 0.9 {
		return false
	}
	if result.ResponseMeta == nil {
		return false
	}
	return true
}

const verifierSystemPrompt = `You are a credential validation analyst. Given a secret detection result and the HTTP response from validating it, classify the credential as valid, invalid, or undetermined.

Respond with ONLY a JSON object:
{"status": "valid|invalid|undetermined", "confidence": 0.0-1.0, "reason": "one sentence explanation"}

Rules:
- "valid" means the credential grants access to the service
- "invalid" means the credential is rejected or expired
- "undetermined" means you cannot confidently classify it
- Be conservative: when in doubt, say "undetermined"`

func (v *LLMVerifier) tryLLMUpgrade(ctx context.Context, match *types.Match, original *types.ValidationResult) *types.ValidationResult {
	userMsg := v.buildUserMessage(match, original)

	key := llm.CacheKey(verifierSystemPrompt, userMsg)
	if cached := v.cache.Get(key); cached != nil {
		return v.applyLLMResponse(cached.Content, original)
	}

	v.spent.Add(1)

	resp, err := v.llm.Complete(ctx, &llm.Request{
		System:    verifierSystemPrompt,
		Messages:  []llm.Message{{Role: "user", Content: userMsg}},
		MaxTokens: v.maxTokens,
	})
	if err != nil {
		return original
	}

	v.cache.Set(key, resp)
	return v.applyLLMResponse(resp.Content, original)
}

func (v *LLMVerifier) buildUserMessage(match *types.Match, result *types.ValidationResult) string {
	meta := result.ResponseMeta
	bodyStr := llm.TruncateBody(meta.Body, 2048)

	return fmt.Sprintf(`Rule: %s
Validator verdict: %s (confidence: %.1f)
Validator message: %s

HTTP Response:
Status: %d
URL: %s
%s`,
		match.RuleID,
		result.Status, result.Confidence, result.Message,
		meta.StatusCode, meta.URL,
		llm.WrapUntrusted("response_body", bodyStr),
	)
}

type llmVerdict struct {
	Status     string  `json:"status"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

func (v *LLMVerifier) applyLLMResponse(content string, original *types.ValidationResult) *types.ValidationResult {
	var verdict llmVerdict
	if err := json.Unmarshal([]byte(content), &verdict); err != nil {
		return original
	}

	newStatus := types.ValidationStatus(verdict.Status)
	switch newStatus {
	case types.StatusValid, types.StatusInvalid:
	case types.StatusUndetermined:
		return original
	default:
		return original
	}

	if original.Status == types.StatusValid && newStatus == types.StatusInvalid {
		return original
	}
	if original.Status == types.StatusInvalid && newStatus == types.StatusValid {
		return original
	}

	return &types.ValidationResult{
		Status:       newStatus,
		Confidence:   verdict.Confidence,
		Message:      fmt.Sprintf("[LLM] %s", verdict.Reason),
		ValidatedAt:  original.ValidatedAt,
		Details:      original.Details,
		ResponseMeta: original.ResponseMeta,
	}
}

func (v *LLMVerifier) Stats() LLMStats {
	return LLMStats{
		Requests:  v.spent.Load(),
		CacheHits: v.cache.Hits(),
	}
}

type LLMStats struct {
	Requests     int64
	CacheHits    int64
	Upgrades     int64
	Failures     int64
	InputTokens  int64
	OutputTokens int64
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/titus && go test ./pkg/validator/ -run TestLLMVerifier -v -count=1`
Expected: all PASS

- [ ] **Step 5: Run full test suite**

Run: `cd /workspace/titus && go test ./pkg/validator/... -count=1`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/validator/verifier.go pkg/validator/verifier_test.go
git commit -m "feat(validator): add LLM verifier for second-pass validation

Wraps the validator Engine with an LLM second pass. Calls LLM only for
undetermined results that have ResponseMeta. Never downgrades existing
verdicts. Budget-limited, cached, bounded concurrency (4 concurrent LLM
calls). Parse failures silently keep the original result."
```

---

### Task 11: Wire LLM Verify into CLI

**Files:**
- Modify: `cmd/titus/scan.go:58-87` (add LLM flag variables)
- Modify: `cmd/titus/scan.go:97-130` (register flags)
- Modify: `cmd/titus/scan.go:2064-2070` (initValidationEngine — return verifier-wrapped engine)
- Modify: `cmd/titus/scan.go:2072-2102` (validateMatches — accept interface)

**Interfaces:**
- Consumes: `LLMVerifier` from Task 10, `llm.NewClient` from Tasks 4-5
- Produces: `--llm-verify`, `--llm-budget`, `--llm-model`, `--llm-timeout` CLI flags wired into scan pipeline

- [ ] **Step 1: Add flag variables**

Add near line 74 in `cmd/titus/scan.go`:

```go
	// LLM flags
	scanLLMVerify  bool
	scanLLMBudget  int
	scanLLMModel   string
	scanLLMTimeout time.Duration
```

- [ ] **Step 2: Register flags**

Add near line 128 in `cmd/titus/scan.go`:

```go
	scanCmd.Flags().BoolVar(&scanLLMVerify, "llm-verify", false, "enable LLM second-pass validation for undetermined results")
	scanCmd.Flags().IntVar(&scanLLMBudget, "llm-budget", 100, "max LLM calls per scan")
	scanCmd.Flags().StringVar(&scanLLMModel, "llm-model", "claude-haiku-4-5-20251001", "LLM model for verification")
	scanCmd.Flags().DurationVar(&scanLLMTimeout, "llm-timeout", 15*time.Second, "timeout per LLM call")
```

- [ ] **Step 3: Define validationInterface**

The scan code currently passes `*validator.Engine` directly. To allow either a bare Engine or an LLMVerifier, define an interface in `cmd/titus/scan.go`:

```go
type validationEngine interface {
	ValidateMatch(ctx context.Context, match *types.Match) (*types.ValidationResult, error)
	ValidateAsync(ctx context.Context, match *types.Match) <-chan *types.ValidationResult
	CanValidate(ruleID string) bool
}
```

Then `validateMatches` and the call sites use this interface. The `*validator.Engine` already satisfies it. The `LLMVerifier` needs `ValidateAsync` and `CanValidate` forwarded from the inner engine — add those as passthrough methods in `verifier.go`.

- [ ] **Step 4: Modify initValidationEngine to return LLM verifier when enabled**

```go
func initValidationEngine() validationEngine {
	if !scanValidate {
		return nil
	}
	e := validator.NewDefaultEngine(scanValidateWorkers)
	if scanValidateRateLimit > 0 {
		e.SetRateLimit(scanValidateRateLimit)
	}
	bc := validator.NewBackoffController(3, 500*time.Millisecond, 30*time.Second)
	e.SetBackoff(bc)

	if !scanLLMVerify {
		return e
	}

	apiKey := os.Getenv("TITUS_LLM_API_KEY")
	if apiKey == "" {
		fmt.Fprintf(os.Stderr, "[warn] --llm-verify set but TITUS_LLM_API_KEY not set; LLM verification disabled\n")
		return e
	}

	client, err := llm.NewClient("anthropic", apiKey, scanLLMModel,
		llm.WithTimeout(scanLLMTimeout))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] failed to create LLM client: %v; LLM verification disabled\n", err)
		return e
	}

	return validator.NewLLMVerifier(e, client, 256, int64(scanLLMBudget))
}
```

- [ ] **Step 5: Run full test suite**

Run: `cd /workspace/titus && go build ./cmd/titus/ && go test ./... -count=1 2>&1 | tail -20`
Expected: builds and all tests PASS

- [ ] **Step 6: Print LLMStats in scan summary**

In scan.go, after the scan completes (near the existing `HTTPModifierStats` printing), add:

```go
	if v, ok := validationEngine.(*validator.LLMVerifier); ok {
		if s := v.Stats(); s.Requests > 0 {
			fmt.Fprintf(os.Stderr, "[llm] %d requests (%d cache hits, %d upgrades, %d failures)\n",
				s.Requests, s.CacheHits, s.Upgrades, s.Failures)
		}
	}
```

- [ ] **Step 7: Run full test suite**

Run: `cd /workspace/titus && go build ./cmd/titus/ && go test ./... -count=1 2>&1 | tail -20`
Expected: builds, all PASS

- [ ] **Step 8: Commit**

```bash
git add cmd/titus/scan.go pkg/validator/verifier.go
git commit -m "feat(cli): wire --llm-verify flag into scan pipeline

When --llm-verify and TITUS_LLM_API_KEY are set, the validation engine
is wrapped with LLMVerifier for second-pass review of undetermined
results. LLMStats printed in scan summary.
Default model: claude-haiku-4-5-20251001, budget: 100 calls."
```

---

### Task 12: LLM Scoring Condition

**Files:**
- Create: `pkg/scoring/condition_llm.go`
- Create: `pkg/scoring/condition_llm_test.go`

**Interfaces:**
- Consumes: `Condition` interface from `pkg/scoring/condition.go`, `networkCondition` marker interface from `pkg/scoring/scorer.go`, `llm.Client` from Task 4, `llm.Sanitize`/`WrapUntrusted` from Task 7
- Produces: `llmCondition` implementing `Condition` + `networkCondition`, constructable via `newLLMCondition(client llm.Client, prompt, firesWhen string) *llmCondition`

- [ ] **Step 1: Write the failing tests**

```go
// pkg/scoring/condition_llm_test.go
package scoring

import (
	"context"
	"testing"

	"github.com/praetorian-inc/titus/pkg/llm"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLLMClient struct {
	response string
	err      error
}

func (m *mockLLMClient) Complete(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &llm.Response{Content: m.response}, nil
}

func TestLLMCondition_FiresWhenMatches(t *testing.T) {
	mock := &mockLLMClient{response: "admin"}
	c := newLLMCondition(mock, "What access level? {{secret}}", "admin")

	match := &types.Match{
		NamedGroups: map[string][]byte{"secret": []byte("AKIA1234")},
		Snippet:     types.Snippet{Matching: []byte("AKIA1234")},
	}

	fired, err := c.Evaluate(context.Background(), match)
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestLLMCondition_FiresWhenNoMatch(t *testing.T) {
	mock := &mockLLMClient{response: "read_only"}
	c := newLLMCondition(mock, "What access level? {{secret}}", "admin")

	match := &types.Match{
		NamedGroups: map[string][]byte{"secret": []byte("AKIA1234")},
		Snippet:     types.Snippet{Matching: []byte("AKIA1234")},
	}

	fired, err := c.Evaluate(context.Background(), match)
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestLLMCondition_CaseInsensitive(t *testing.T) {
	mock := &mockLLMClient{response: "ADMIN access granted"}
	c := newLLMCondition(mock, "test", "admin")

	match := &types.Match{Snippet: types.Snippet{Matching: []byte("x")}}
	fired, err := c.Evaluate(context.Background(), match)
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestLLMCondition_ErrorReturnsFalse(t *testing.T) {
	mock := &mockLLMClient{err: assert.AnError}
	c := newLLMCondition(mock, "test", "admin")

	match := &types.Match{Snippet: types.Snippet{Matching: []byte("x")}}
	fired, err := c.Evaluate(context.Background(), match)
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestLLMCondition_TemplateSubstitution(t *testing.T) {
	var capturedPrompt string
	mock := &mockLLMClient{response: "admin"}
	c := newLLMCondition(mock, "Key {{secret}} from rule {{rule_name}}", "admin")
	c.capturePrompt = &capturedPrompt

	match := &types.Match{
		RuleID:      "np.aws.1",
		NamedGroups: map[string][]byte{"secret": []byte("AKIA1234")},
		Snippet:     types.Snippet{Matching: []byte("AKIA1234")},
	}
	_, _ = c.Evaluate(context.Background(), match)
	assert.Contains(t, capturedPrompt, "AKIA1234")
}

func TestLLMCondition_IsNetworkCondition(t *testing.T) {
	mock := &mockLLMClient{response: "x"}
	c := newLLMCondition(mock, "test", "x")
	var nc networkCondition = c
	nc.markDynamic()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/titus && go test ./pkg/scoring/ -run TestLLMCondition -v -count=1`
Expected: compilation error — `newLLMCondition` undefined

- [ ] **Step 3: Write minimal implementation**

```go
// pkg/scoring/condition_llm.go
package scoring

import (
	"context"
	"strings"

	"github.com/praetorian-inc/titus/pkg/llm"
	"github.com/praetorian-inc/titus/pkg/types"
)

type llmCondition struct {
	client       llm.Client
	promptTpl    string
	firesWhen    string
	capturePrompt *string // test hook, nil in production
}

func newLLMCondition(client llm.Client, promptTpl, firesWhen string) *llmCondition {
	return &llmCondition{
		client:    client,
		promptTpl: promptTpl,
		firesWhen: firesWhen,
	}
}

func (c *llmCondition) markDynamic() {}

func (c *llmCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	prompt := substituteMatchVars(c.promptTpl, m)
	if c.capturePrompt != nil {
		*c.capturePrompt = prompt
	}

	resp, err := c.client.Complete(ctx, &llm.Request{
		System:    "You are analyzing a detected secret. Answer concisely.",
		Messages:  []llm.Message{{Role: "user", Content: prompt}},
		MaxTokens: 256,
	})
	if err != nil {
		return false, nil
	}

	return strings.Contains(strings.ToLower(resp.Content), strings.ToLower(c.firesWhen)), nil
}

func substituteMatchVars(tpl string, m *types.Match) string {
	tpl = strings.ReplaceAll(tpl, "{{rule_name}}", m.RuleID)
	tpl = strings.ReplaceAll(tpl, "{{ rule_name }}", m.RuleID)
	for name, value := range m.NamedGroups {
		val := string(value)
		tpl = strings.ReplaceAll(tpl, "{{"+name+"}}", val)
		tpl = strings.ReplaceAll(tpl, "{{ "+name+" }}", val)
	}
	if m.Snippet.Matching != nil {
		val := string(m.Snippet.Matching)
		tpl = strings.ReplaceAll(tpl, "{{matching}}", val)
		tpl = strings.ReplaceAll(tpl, "{{ matching }}", val)
	}
	return tpl
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/titus && go test ./pkg/scoring/ -run TestLLMCondition -v -count=1`
Expected: all PASS

- [ ] **Step 5: Run full scoring test suite**

Run: `cd /workspace/titus && go test ./pkg/scoring/... -count=1`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/scoring/condition_llm.go pkg/scoring/condition_llm_test.go
git commit -m "feat(scoring): add llmCondition type

Implements Condition + networkCondition interfaces. Template variables
substituted from match named groups. fires_when matches case-insensitively
against LLM response. Errors silently return false (condition does not fire).
Gated by --score-scope same as httpCondition."
```

---

### Task 13: YAML Schema Extension + Loader

**Files:**
- Modify: `pkg/scoring/yaml.go:27-43` (add LLM field to yamlModifier)
- Modify: `pkg/scoring/loader.go:152-225` (parse llm condition in convertYAMLModifier)
- Create: test YAML fixture for llm condition

**Interfaces:**
- Consumes: `llmCondition` from Task 12, `yamlModifier` struct
- Produces: YAML `llm:` condition block parsed into `llmCondition` during scorer loading

- [ ] **Step 1: Write the failing test**

```go
// Add to pkg/scoring/loader_test.go or create it
package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertYAMLModifier_LLMCondition(t *testing.T) {
	delta := 30
	ym := yamlModifier{
		Name:     "llm-scope-check",
		Priority: 50,
		LLM: &yamlLLMDef{
			Prompt:    "What access does {{secret}} have? Respond: admin, read_write, read_only, unknown",
			FiresWhen: "admin",
		},
		Delta: &delta,
	}

	m, err := convertYAMLModifier(ym, nil)
	require.NoError(t, err)
	assert.Equal(t, "llm-scope-check", m.Name)
	assert.Equal(t, 50, m.Priority)
	assert.True(t, m.IsDynamic(), "llmCondition should be a network condition")
}

func TestConvertYAMLModifier_LLMAndHTTPRejects(t *testing.T) {
	delta := 10
	ym := yamlModifier{
		Name: "bad",
		LLM: &yamlLLMDef{
			Prompt:    "test",
			FiresWhen: "yes",
		},
		HTTP:      &yamlHTTPDef{Method: "GET", URL: "http://x"},
		FiresWhen: &yamlFiresWhen{StatusCode: intPtr(200)},
		Delta:     &delta,
	}
	_, err := convertYAMLModifier(ym, nil)
	assert.Error(t, err, "should reject two condition types")
}

func TestConvertYAMLModifier_LLMMissingPrompt(t *testing.T) {
	delta := 10
	ym := yamlModifier{
		Name: "bad",
		LLM: &yamlLLMDef{
			FiresWhen: "yes",
		},
		Delta: &delta,
	}
	_, err := convertYAMLModifier(ym, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "prompt")
}

func TestConvertYAMLModifier_LLMMissingFiresWhen(t *testing.T) {
	delta := 10
	ym := yamlModifier{
		Name: "bad",
		LLM: &yamlLLMDef{
			Prompt: "test",
		},
		Delta: &delta,
	}
	_, err := convertYAMLModifier(ym, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fires_when")
}

func intPtr(n int) *int { return &n }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/titus && go test ./pkg/scoring/ -run TestConvertYAMLModifier_LLM -v -count=1`
Expected: compilation error — `yamlLLMDef` undefined

- [ ] **Step 3: Implement YAML schema and loader changes**

Add to `pkg/scoring/yaml.go` after line 43:

```go
type yamlLLMDef struct {
	Prompt    string `yaml:"prompt"`
	FiresWhen string `yaml:"fires_when"`
}
```

Add field to `yamlModifier` (line 27):

```go
	// LLM condition (Phase 4)
	LLM *yamlLLMDef `yaml:"llm,omitempty"`
```

Modify `convertYAMLModifier` in `loader.go` to accept an optional `llm.Client` parameter and parse the `llm:` block. Add this condition block after the HTTP+FiresWhen block (before the `condCount != 1` check):

```go
	if ym.LLM != nil {
		condCount++
		if ym.LLM.Prompt == "" {
			return Modifier{}, fmt.Errorf("llm.prompt is required")
		}
		if ym.LLM.FiresWhen == "" {
			return Modifier{}, fmt.Errorf("llm.fires_when is required")
		}
		cond = newLLMCondition(llmClient, ym.LLM.Prompt, ym.LLM.FiresWhen)
	}
```

The `convertYAMLModifier` function signature changes to accept `llmClient llm.Client`. Update all call sites in `loader.go` to pass nil (or the client when available). The caller in `convertYAMLScorer` passes the client through.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/titus && go test ./pkg/scoring/ -run TestConvertYAMLModifier_LLM -v -count=1`
Expected: all PASS

- [ ] **Step 5: Run full scoring + whole project test suite**

Run: `cd /workspace/titus && go test ./pkg/scoring/... -count=1`
Run: `cd /workspace/titus && go test ./... -count=1 2>&1 | tail -20`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/scoring/yaml.go pkg/scoring/loader.go pkg/scoring/condition_llm.go
git commit -m "feat(scoring): parse llm condition from YAML scorers

New 'llm:' block in scorer YAML with prompt template and fires_when
string. Parsed by convertYAMLModifier as a condition leaf alongside
match_group, surrounding_context_contains, match_length, and http.
LLM client injected via loader; nil client skips LLM conditions."
```

---

### Task 14: Wire LLM Conditions into Scoring Engine

**Files:**
- Modify: `pkg/scoring/engine.go:120-128` (handle llmCondition in Score like httpCondition)
- Modify: `cmd/titus/scan.go` (pass LLM client to scoring engine)

**Interfaces:**
- Consumes: `llmCondition` from Task 12, `llm.Client` from Task 4, `buildScoringEngine()` from scan.go
- Produces: Scoring engine evaluates LLM conditions when `--score-scope` is enabled and LLM API key is available

- [ ] **Step 1: Modify scoring engine Score() for llmCondition**

In `pkg/scoring/engine.go`, the Score method already has special handling for `httpCondition` (line 120-123). Add a similar block for `llmCondition`:

```go
		if hc, ok := m.Condition.(*httpCondition); ok {
			fired, err = hc.evaluateWithCache(modCtx, primary, e.cache)
		} else if _, ok := m.Condition.(*llmCondition); ok {
			fired, err = m.Condition.Evaluate(modCtx, primary)
		} else {
			fired, err = m.Condition.Evaluate(modCtx, primary)
		}
```

Actually the `llmCondition` just uses `Evaluate()` directly (no special cache), so the else branch already handles it. The main change is that `buildScoringEngine` in `scan.go` needs to pass the LLM client to the scorer loader.

- [ ] **Step 2: Modify buildScoringEngine to accept LLM client**

```go
func buildScoringEngine() (scoringEngineInterface, error) {
	var llmClient llm.Client
	if scanScopeEnabled {
		apiKey := os.Getenv("TITUS_LLM_API_KEY")
		if apiKey != "" {
			var err error
			llmClient, err = llm.NewClient("anthropic", apiKey, scanLLMModel,
				llm.WithTimeout(scanLLMTimeout))
			if err != nil {
				fmt.Fprintf(os.Stderr, "[warn] failed to create LLM client for scoring: %v\n", err)
			}
		}
	}

	allScorers, err := scoring.AllBuiltinScorers(llmClient)
	if err != nil {
		return nil, fmt.Errorf("loading scorers: %w", err)
	}
	cfg := scoring.EngineConfig{
		ScopeEnabled: scanScopeEnabled,
		Timeout:      scanScoreTimeout,
		Budget:       scanScoreBudget,
	}
	return scoring.NewEngine(allScorers, cfg), nil
}
```

This requires `AllBuiltinScorers` to accept an `llm.Client` parameter. Modify its signature in the scoring package to pass the client through the loader chain.

- [ ] **Step 3: Update AllBuiltinScorers signature**

In the scoring package, wherever `AllBuiltinScorers()` is defined, update it to accept `llmClient llm.Client` and thread it through to `convertYAMLModifier`.

- [ ] **Step 4: Run full test suite**

Run: `cd /workspace/titus && go build ./cmd/titus/ && go test ./... -count=1 2>&1 | tail -20`
Expected: builds, all PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/scoring/engine.go pkg/scoring/loader.go cmd/titus/scan.go
git commit -m "feat(scoring): wire LLM client into scoring engine

When --score-scope is enabled and TITUS_LLM_API_KEY is set, the scoring
engine passes an LLM client to the scorer loader. LLM conditions in
YAML scorers are evaluated alongside HTTP conditions. Without an API key,
LLM conditions are constructed with nil client and silently skip."
```

---

### Task 15: End-to-End Integration Test

**Files:**
- Create: `pkg/validator/integration_test.go`

**Interfaces:**
- Consumes: All Phase 1-4 components
- Produces: Integration test proving the full pipeline works: scan → validate → (LLM verify) → score → (LLM condition)

- [ ] **Step 1: Write integration test**

```go
// pkg/validator/integration_test.go
package validator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/llm"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_LLMVerifierUpgradesUndetermined(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"unknown","message":"unrecognized key format"}`))
	}))
	defer apiSrv.Close()

	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{{
				"type": "text",
				"text": `{"status":"valid","confidence":0.85,"reason":"response body shows the key was accepted"}`,
			}},
			"model": "claude-haiku-4-5-20251001",
			"usage": map[string]any{"input_tokens": 100, "output_tokens": 50},
		})
	}))
	defer llmSrv.Close()

	undeterminedValidator := &staticValidator{
		result: &types.ValidationResult{
			Status:     types.StatusUndetermined,
			Confidence: 0.5,
			Message:    "ambiguous response",
			ResponseMeta: &types.ResponseMeta{
				StatusCode: 200,
				Body:       []byte(`{"status":"unknown"}`),
				URL:        apiSrv.URL,
			},
		},
	}
	engine := NewEngine(1, undeterminedValidator)

	llmClient, err := llm.NewClient("anthropic", "test-key", "claude-haiku-4-5-20251001",
		llm.WithBaseURL(llmSrv.URL))
	require.NoError(t, err)

	verifier := NewLLMVerifier(engine, llmClient, 256, 100)

	match := &types.Match{
		RuleID: "test.1",
		Groups: [][]byte{[]byte("my-secret-key")},
		Snippet: types.Snippet{
			Before:   []byte("API_KEY="),
			Matching: []byte("my-secret-key"),
			After:    []byte("\n"),
		},
	}

	result, err := verifier.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status, "LLM should upgrade undetermined to valid")
	assert.Contains(t, result.Message, "LLM")
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `cd /workspace/titus && go test ./pkg/validator/ -run TestIntegration_LLMVerifier -v -count=1`
Expected: PASS

- [ ] **Step 3: Run full project test suite**

Run: `cd /workspace/titus && go test ./... -count=1 2>&1 | tail -30`
Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add pkg/validator/integration_test.go
git commit -m "test: add end-to-end integration test for LLM verifier

Tests the full pipeline: validator returns undetermined with ResponseMeta,
LLM verifier calls mock Anthropic API, upgrades to valid. Uses
httptest.Server for both the target API and the LLM API."
```

---

## Summary

| Phase | Tasks | New Files | Modified Files |
|-------|-------|-----------|----------------|
| 1: Infrastructure | 1-3 | 6 | 3 |
| 2: LLM Client | 4-7 | 8 | 0 |
| 3: LLM Validation | 8-11 | 4 | 4 |
| 4: LLM Scoring | 12-14 | 4 | 4 |
| Integration | 15 | 1 | 0 |
| **Total** | **15** | **23** | **11** |

Each phase is independently shippable. Phase 1 adds resilience with no new dependencies. Phase 2 is a standalone LLM client. Phases 3 and 4 both depend on Phase 2 but are independent of each other.
