# Agentic Validation Pipeline — Design Spec

Bring brutus's agentic flow patterns into titus: LLM-augmented validation,
LLM scoring conditions, and infrastructure resilience (adaptive backoff,
retry, rate limiting) for the validator engine.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Architecture | Layered insertion — shared LLM client, two independent consumers | Composition over modification; ships incrementally; existing validators unchanged |
| LLM position in pipeline | Post-validation second pass (A) + scoring condition (C) | Complementary without overlapping; validation and scoring stay separate concerns |
| Provider model | Provider-agnostic interface, Anthropic first | Thin interface with one implementation; leaves room without over-engineering |
| LLM input context | Response + match context | Avoids duplicating requests; gives LLM enough to reason without re-issuing HTTP calls |

## Phasing

```
Phase 1: Infrastructure resilience      (no new deps, standalone)
Phase 2: LLM client foundation          (standalone)
Phase 3: LLM-augmented validation       (depends on Phase 2)
Phase 4: LLM scoring conditions         (depends on Phase 2, independent of Phase 3)
```

Each phase is independently shippable and useful on its own.

---

## Phase 1: Infrastructure Resilience

No new external dependencies. Ports patterns from brutus's `pkg/brutus/backoff.go`
and worker pool to titus's validator engine.

### Package layout

```
pkg/validator/
  backoff.go      — adaptive backoff controller
  retry.go        — retry wrapper for HTTP-based validators
  ratelimit.go    — shared rate limiter for outbound validation requests
```

### Adaptive backoff controller (`backoff.go`)

Tracks consecutive connection errors across all validator workers via a shared
atomic counter.

- After 3+ consecutive errors: inject exponential backoff delay
  (base 500ms, max 30s, with random jitter)
- On any successful response (including invalid credentials — that's a live
  endpoint): reset counter to zero
- Thread-safe — multiple goroutines in the validator worker pool read the delay

### Retry wrapper (`retry.go`)

Wraps HTTP-based validators with retry logic for transient failures:

| Response | Behavior |
|----------|----------|
| 429 | Respect `Retry-After` header (capped 30s), retry once |
| 5xx | Retry once after 1s backoff |
| Connection error (DNS, timeout, reset) | Retry once with backoff controller delay |
| 2xx, 3xx, 4xx (except 429) | Pass through immediately, no retry |

YAML validators get retry automatically — they all go through `HTTPValidator`.
Go validators opt in by using a shared `RetryHTTPClient` instead of raw
`http.Client`.

### Rate limiter (`ratelimit.go`)

Shared `golang.org/x/time/rate.Limiter` across all validators. The dependency
is already in go.mod (used by the Asana enumerator).

- Default: unlimited (preserves existing behavior)
- Configurable via `--validate-rate-limit` CLI flag
- Applied in `Engine.ValidateAsync()` before dispatching to a validator

### Changes to existing code

- `Engine` struct gains optional `backoff *BackoffController` and
  `limiter *rate.Limiter` fields
- `HTTPValidator` (YAML validators) switches from `http.DefaultClient` to a
  `RetryHTTPClient`
- Go validators that create their own `http.Client` get a
  `NewValidatorHTTPClient()` helper that wires in retry + backoff

---

## Phase 2: LLM Client Foundation

### Package layout

```
pkg/llm/
  client.go     — Client interface + factory
  anthropic.go  — Anthropic implementation
  cache.go      — response cache (prompt hash -> result)
  sanitize.go   — prompt sanitization
```

### Client interface (`client.go`)

```go
type Client interface {
    Complete(ctx context.Context, req *Request) (*Response, error)
}

type Request struct {
    System    string
    Messages  []Message
    MaxTokens int
}

type Message struct {
    Role    string // "user" or "assistant"
    Content string
}

type Response struct {
    Content  string
    Model    string
    Usage    Usage
}

type Usage struct {
    InputTokens  int
    OutputTokens int
}
```

Deliberately minimal — text completion only. No tool use, no vision, no
streaming. Both consumers (verifier and scoring condition) need "prompt in,
text out." Extensible later if needed.

Factory: `NewClient(provider, apiKey, model string, opts ...Option)` returns a
`Client`. Only `"anthropic"` is implemented initially. Options for timeout, max
retries, base URL override.

### Anthropic implementation (`anthropic.go`)

Direct HTTP calls to `api.anthropic.com/v1/messages`. No SDK dependency — just
`net/http` + JSON marshaling. Keeps the dependency footprint minimal, same
pattern brutus uses.

- Respects `context.Context` for cancellation
- Retries on 429 (with `Retry-After`) and 529 (overloaded), retry once

### Response cache (`cache.go`)

In-memory, keyed by `SHA256(system + user_message)`. Same pattern as the
validator's `ValidationCache` and scoring's `httpResponseCache`.

- Thread-safe with `sync.RWMutex`
- Prevents duplicate LLM calls for the same secret appearing in multiple matches

### Prompt sanitization (`sanitize.go`)

Ported from brutus's `SanitizeBanner()`:

- Strip null bytes, ANSI escapes, control characters
- Truncate response bodies to 2KB
- Wrap untrusted input in XML tags with clear boundaries to mitigate prompt
  injection

### Configuration

| Config | Type | Default |
|--------|------|---------|
| `TITUS_LLM_API_KEY` | env var | (required when LLM features enabled) |
| `--llm-model` | CLI flag | `claude-haiku-4-5-20251001` |
| `--llm-timeout` | CLI flag | 15s |

Follows titus's existing env var + CLI flag pattern. No config file.

---

## Phase 3: LLM-Augmented Validation

### Extending ValidationResult

Add optional `ResponseMeta` to `types.ValidationResult`:

```go
type ResponseMeta struct {
    StatusCode int
    Headers    map[string]string // selected headers, not all
    Body       []byte            // truncated to 2KB
    URL        string            // the endpoint that was hit
}
```

**Which validators populate ResponseMeta:**

| Category | Populates | Reason |
|----------|-----------|--------|
| All YAML/HTTP validators | Yes | `HTTPValidator` already has `*http.Response` |
| Go HTTP validators (Jenkins, SentryDSN, Mattermost, TrueNAS, etc.) | Yes | Add a few lines to capture before body close |
| Non-HTTP Go validators (AWS STS, Postgres, MySQL, RabbitMQ) | No | SDK/driver responses aren't meaningful HTTP |

Backwards-compatible — validators that don't set `ResponseMeta` are unchanged.
The LLM verifier skips results with nil `ResponseMeta`.

### LLM Verifier (`pkg/validator/verifier.go`)

```go
type LLMVerifier struct {
    engine    *Engine
    llm       llm.Client
    maxTokens int
    budget    int64 // max LLM calls per scan
    sem       chan struct{} // bounded LLM concurrency
}

func (v *LLMVerifier) ValidateMatch(ctx, match) (*ValidationResult, error)
```

The verifier wraps the engine. `ValidateMatch` flow:

1. Call `v.engine.ValidateMatch(ctx, match)` — normal validation
2. If result is `valid` or `invalid` with confidence >= 0.9 — return as-is
3. If result is `undetermined` and `ResponseMeta` is nil — return as-is
4. Otherwise — build prompt, call LLM, parse structured response

### Prompt design

System prompt instructs the LLM to classify a credential validation response as
`valid`, `invalid`, or `undetermined`, with a one-sentence reason.

User message includes:
- Rule ID and rule name (what kind of secret)
- Snippet context (Before/Matching/After, sanitized)
- Validator's original verdict and message
- ResponseMeta (status code, selected headers, truncated body)

LLM returns: `{"status": "valid|invalid|undetermined", "confidence": 0.0-1.0, "reason": "..."}`

If parsing fails or the LLM returns undetermined, keep the original validator
result. The LLM never downgrades — it can only upgrade undetermined to
valid/invalid.

### Concurrency

The verifier shares the engine's existing semaphore for validator calls. LLM
calls get their own bounded concurrency (default 4 concurrent LLM requests) to
avoid overwhelming the API and to cap cost.

### Integration point

`titus.go` already calls `engine.ValidateMatch()`. When `--llm-verify` is
enabled, create an `LLMVerifier` wrapping the engine and use that instead.
Single call-site change.

### CLI surface

| Flag | Default | Purpose |
|------|---------|---------|
| `--llm-verify` | false | Enable LLM validation pass |
| `--llm-budget` | 100 | Max LLM calls per scan |

---

## Phase 4: LLM Scoring Conditions

### New condition type (`pkg/scoring/condition_llm.go`)

```go
type llmCondition struct {
    prompt    string  // template with {{variables}}
    firesWhen string  // match string against LLM response
    client    llm.Client
}

func (c *llmCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error)
```

Implements the existing `Condition` interface alongside `matchGroupCondition`,
`surroundingContextContainsCondition`, and `httpCondition`. No scoring engine
changes needed.

### YAML schema extension

```yaml
scorers:
  - name: example-scorer
    rule_ids: [np.example.1]
    modifiers:
      - name: llm-scope-check
        priority: 50
        action:
          kind: delta
          value: 30
        condition:
          llm:
            prompt: |
              This is a {{rule_name}} secret: {{secret}}
              What level of access does this credential grant?
              Respond with: "admin", "read_write", "read_only", or "unknown"
            fires_when: "admin"
```

The `prompt` field supports the same `{{variable}}` template system that YAML
validators and HTTP scoring conditions already use. `fires_when` matches against
the LLM's response text (case-insensitive contains).

### Gating

LLM conditions implement the `networkCondition` marker interface, same as
`httpCondition`. `--score-scope` is currently a boolean flag that gates all
network conditions (HTTP). LLM conditions are gated the same way — when
`--score-scope` is enabled, both HTTP and LLM conditions run. No separate
`--score-scope-llm` flag; LLM conditions only exist in scorers where they
add value, so the existing boolean is sufficient.

### Budget and timeout

LLM conditions inherit the scoring engine's existing per-modifier timeout
(`--score-timeout`, default 10s) and per-finding budget (`--score-budget`,
default 60s). No new timeout plumbing.

### Caching

Two cache layers:
1. LLM client's own response cache (same prompt -> cached result)
2. Scoring engine's `httpResponseCache` pattern extended to cover LLM responses,
   keyed by rendered prompt + secret hash

### Example use cases

- AWS key: "does this key have admin/PowerUser policies?"
- GitHub token: "based on the scopes, can this token push to repos or just read?"
- Generic API key: "based on the API response body, what can this key do?"

These require reasoning over unstructured text that the existing `fires_when`
HTTP leaf conditions cannot do.

---

## Error Handling and Observability

### Failure modes

The LLM is always additive, never destructive. If the LLM is unavailable, slow,
or returns garbage, titus behaves exactly as it does today.

| Failure | Behavior |
|---------|----------|
| API unreachable / auth failure | Log warning once at startup, disable LLM features for the scan |
| Per-call timeout | Keep original validator result / scoring condition returns false |
| Unparseable LLM response | Keep original result, log at debug level |
| LLM returns undetermined | Keep original result |
| Rate limited (429/529) | Retry once per LLM client; if still limited, treat as timeout |

The verifier never downgrades a result. It can only upgrade undetermined to
valid/invalid.

### Observability

```go
type LLMStats struct {
    Requests     int64  // total LLM calls attempted
    CacheHits    int64  // served from response cache
    Upgrades     int64  // undetermined -> valid or invalid
    Failures     int64  // timeouts + parse errors + API errors
    InputTokens  int64  // total across all calls
    OutputTokens int64  // total across all calls
}
```

Printed in scan summary when `--llm-verify` is enabled. Extends the existing
pattern where scoring prints `HTTPModifierStats`.

### Cost guardrails

- `--llm-budget` flag: max total LLM calls per scan (default 100). After
  hitting budget, verifier and LLM conditions silently pass through.
- Haiku default model: ~$0.001/call. 100-call budget caps LLM cost at
  ~$0.10/scan.
- Response cache prevents duplicate calls for the same credential across files.

---

## Testing Strategy

### Phase 1

- Unit tests for `BackoffController`: consecutive errors trigger backoff,
  success resets, jitter is bounded, thread-safety under concurrent access
- Unit tests for retry wrapper: 429 retries with Retry-After, 5xx retries once,
  4xx passes through, connection errors retry with backoff
- Unit tests for rate limiter integration in `Engine`
- Integration test: flaky HTTP test server returning 429/5xx intermittently,
  verify validators succeed through retry

### Phase 2

- Unit tests with mock HTTP server impersonating Anthropic API: success, 429
  retry, 529 retry, timeout, malformed response
- Cache tests: hit, miss, thread-safety, same-prompt dedup
- Sanitization tests: null bytes stripped, ANSI codes stripped, truncation at
  2KB, control characters removed
- No real API calls in CI — all tests use `httptest.Server`

### Phase 3

- Unit tests with `MockLLMClient` implementing `Client` interface
- Decision logic: high-confidence valid/invalid skips LLM, undetermined with
  ResponseMeta triggers LLM, nil ResponseMeta skips LLM
- Upgrade behavior: undetermined -> valid, undetermined -> invalid,
  undetermined -> undetermined (keeps original)
- Failure modes: timeout keeps original, parse error keeps original, never
  downgrades
- Budget enforcement: after N calls, silently passes through
- go-vcr cassette tests for full verifier flow against recorded LLM responses

### Phase 4

- Unit tests with `MockLLMClient`: fires_when matches, fires_when doesn't
  match, template variable substitution
- Gating behind `--score-scope`: LLM conditions skipped when scope excludes llm
- Timeout/budget: condition returns false on timeout, inherits scoring engine
  per-modifier timeout
- YAML parsing: llm condition block parsed correctly, invalid schema rejected
- Cassette tests for representative scorers with recorded LLM responses

### Across all phases

- Existing test suites pass with no changes (LLM features off by default)
- No real LLM API calls anywhere in the test suite
