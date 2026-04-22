# Finding Scoring Design

**Date:** 2026-04-22
**Status:** Approved design, pending implementation
**Author:** Drafted collaboratively with Claude

## Problem

When Titus findings are verified (`--validate` returns `valid`) and surfaced in Chariot, they are currently treated uniformly as HIGH severity. This is wrong: a leaked LinkedIn session cookie has fundamentally different blast radius than a leaked AWS root access key with IAM admin.

We need a way to:
1. Assign a base severity to every secret type based on the inherent value of that secret class.
2. Refine that severity based on observed **scope** — what the specific credential can actually do (e.g., an AWS key with read-only S3 is less interesting than one with `sts:AssumeRole` on every production role).
3. Emit the result in a form that downstream consumers (Chariot, CI pipelines, SARIF tooling) can use to make automated decisions.

## Goals

- Every finding emits a deterministic **score** between 0 and 100.
- Every detection rule has a required `base_score` in its YAML.
- A declarative "scorer" mechanism (new YAML file type) lets us express scope-detection logic without writing Go code for the common cases.
- Complex scope detection (e.g., AWS IAM enumeration requiring SigV4) drops into custom Go scorers, mirroring how `pkg/validator` handles complex validators.
- Scope scoring is opt-in behind a new CLI flag; default scan behavior is unchanged modulo the new `score` field in output.
- Output includes a full **audit trail** of which modifiers fired, so humans and downstream systems can explain and tune the score.

## Non-goals

- Titus does not define Chariot's severity bands. It emits the raw score and a **suggested** severity tier; downstream consumers are authoritative.
- Titus does not attempt to model secret *exposure* (repo visibility, historical presence) — scoring addresses intrinsic value and scope, not likelihood of compromise.
- No compound boolean logic (AND/OR/NOT) in modifier conditions in v1. Leaf conditions only. Compound support is a planned future extension (see Open Questions).
- No auto-retry on transient failures beyond a fixed policy — no exponential backoff or circuit-breaker machinery in v1.

## Primary consumers

- **CI automation (consumer B)** — pipelines consume the JSON output and gate on numeric thresholds (`jq '.score.final >= 80'`).
- **Downstream security platforms (consumer C)** — primarily Chariot, which ingests findings and owns severity interpretation for its customers.

Both consumers require:
- A stable numeric scale (0-100 integer).
- A stable JSON/SARIF schema.
- An auditable breakdown of how the score was derived.

## Core scoring model

### Score math

```
score = base_score
for each fired modifier in evaluation order (priority DESC, YAML ASC):
    if modifier.kind == "set_score":
        score = modifier.value       # assignment, wipes prior adjustments
    else: # "delta"
        score += modifier.value      # accumulate
score = clamp(score, 0, 100)
```

**Evaluation order** is priority descending (higher priority first), with YAML declaration order breaking ties. `set_score` modifiers *replace* the current value; later deltas apply on top of the replacement; a later `set_score` replaces again. This gives authors precise control: place cheap static deltas at high priority (they run first but get overridden by expensive scope-detecting `set_score` modifiers if those fire), and place definitive-capability `set_score` modifiers where they should override.

### Base score and modifiers

- **Base score** is required metadata on every rule YAML. It reflects the inherent value of the secret class, roughly corresponding to "worst-case financial/operational damage if leaked".
- **Modifiers** live in separate scorer YAML files (or custom Go scorers). Each modifier has:
  - A `name` for audit
  - An optional `priority` (default: YAML order)
  - Either a static condition (zero-network, evaluated from match data alone) or a dynamic `http:` + `fires_when:` block
  - Either `delta: ±N` or `set_score: N`

### Suggested severity tiers

The engine emits a `suggested_severity` hint based on these bands. Consumers may ignore or remap.

| Tier      | Range   | Example rules                                        |
|-----------|---------|------------------------------------------------------|
| critical  | 80-100  | AWS credentials, Stripe live keys, PEM private keys  |
| high      | 60-79   | GitHub tokens (repo scope), Slack tokens, Okta API   |
| medium    | 40-59   | SendGrid, Mailgun, Twilio, most SaaS API keys        |
| low       | 20-39   | Analytics keys (Datadog, New Relic), LinkedIn        |
| info      | 0-19    | Identifiers (AWS Account ID, client IDs)             |

## Architecture

### Package layout

```
pkg/scoring/
├── engine.go              # ScoringEngine, registration, dispatch, math
├── scorer.go              # Scorer interface, ModifierResult, ScoreResult
├── yaml_scorer.go         # declarative scorer loading + eval
├── yaml_scorer.go         # static + HTTP condition evaluation
├── embed.go               # //go:embed scorers/*.yaml
├── scorers/               # embedded YAML scorer files
│   ├── github.yaml
│   ├── slack.yaml
│   └── ...
├── aws.go                 # custom Go scorer (SigV4 + IAM enumeration)
├── github.go              # custom Go scorer (go-github, covers YAML edge cases)
└── ...
```

### Scorer interface

```go
type Scorer interface {
    Name() string
    CanScore(ruleID string) bool
    Modifiers(ruleID string) []Modifier
}

type Modifier interface {
    Name() string
    Priority() int
    IsDynamic() bool
    Evaluate(ctx context.Context, match *types.Match, cache *responseCache) (fired bool, err error)
    Kind() string   // "delta" or "set_score"
    Value() int
}
```

### Engine

```go
type Engine struct {
    scorers      []Scorer       // Go scorers registered first, then YAML
    scopeEnabled bool           // --score-scope flag
    httpCache    *responseCache // per-scan HTTP response cache
    workers      int            // reuses --validate-workers
    timeout      time.Duration  // per-modifier HTTP timeout
    budget       time.Duration  // per-finding overall scoring budget
}
```

Dispatch is first-match-wins: the engine iterates registered scorers and invokes the first whose `CanScore(finding.RuleID)` returns true. Go scorers are registered before YAML scorers so they take precedence, matching the validator subsystem's pattern.

### Pipeline integration

Scoring fires at **finding-creation time** inside `runScan`'s per-blob flush, immediately after the `FindingExists` check confirms a new unique finding. This ensures:

- One scoring call per unique finding, not per match
- Score persists in the datastore; `titus report` renders it without re-scoring
- Deduplication naturally eliminates redundant HTTP hits for the same secret

## Data model

```go
// pkg/types/score.go
type Score struct {
    Final             int              // clamped 0-100
    Base              int              // 0-100, from rule.BaseScore
    SuggestedSeverity string           // "info" | "low" | "medium" | "high" | "critical"
    Applied           []ScoreModifier  // fired modifiers, in evaluation order
}

type ScoreModifier struct {
    Name     string
    Scorer   string
    Kind     string   // "delta" or "set_score"
    Value    int
    Priority int
}

// pkg/types/rule.go — extension
type Rule struct {
    // ... existing fields ...
    BaseScore int // required, 0-100
}

// pkg/types/finding.go — extension
type Finding struct {
    // ... existing fields ...
    Score *Score // nil for legacy datastores predating this feature
}
```

## YAML scorer schema

### Full realistic example

```yaml
# pkg/scoring/scorers/github.yaml
scorers:
  - name: github-pat-scope
    rule_ids:
      - np.github.1   # classic PAT
      - np.github.2   # OAuth token
      - np.github.7   # fine-grained PAT
    modifiers:

      # Static condition — zero network, always runs
      - name: fine-grained-pat
        priority: 100
        match_group: { name: token, matches: '^github_pat_' }
        delta: -10

      # Dynamic — HTTP call, requires --score-scope
      - name: admin-org-scope
        priority: 90
        http:
          method: GET
          url: https://api.github.com/user
          auth: { type: bearer, secret_group: token }
        fires_when:
          header_contains: { name: x-oauth-scopes, value: 'admin:org' }
        set_score: 90

      - name: enterprise-plan
        priority: 80
        http:
          method: GET
          url: https://api.github.com/user
          auth: { type: bearer, secret_group: token }
        fires_when:
          json_path_equals: { path: '.plan.name', value: enterprise }
        delta: +15

      - name: multi-org-member
        priority: 50
        http:
          method: GET
          url: https://api.github.com/user/orgs
          auth: { type: bearer, secret_group: token }
        fires_when:
          json_array_length_gte: { path: '.', value: 3 }
        delta: +10
```

### Condition DSL — v1 leaf types

**Static (no network):**
- `match_group: { name: <capture>, matches: <regex> }`
- `surrounding_context_contains: { within: <int>, value: <string> }`
- `match_length: { op: gt|lt|eq, value: <int> }`

**Dynamic (inside a `fires_when:` block, requires `http:` peer):**
- `status_code: <int>` or `status_code_in: [<int>, ...]`
- `response_body_contains: <string>`
- `header_contains: { name: <string>, value: <string> }`
- `json_path_equals: { path: <JSONPath>, value: <any> }`
- `json_path_matches: { path: <JSONPath>, regex: <string> }`
- `json_array_length_gte: { path: <JSONPath>, value: <int> }`

### HTTP sub-schema

The `http:` block reuses `pkg/validator`'s existing HTTP schema verbatim: `method`, `url`, `auth` (bearer / basic / header / query / api_key), `body`, `headers`. This means no new validation code; the same `substituteTemplateVars` and `applyAuth` helpers work unchanged.

### HTTP response caching

Keyed by `(method, url, auth_secret_hash)`, scoped to a single scan. Three modifiers hitting `/user` for the same token = one HTTP call. Cache is invalidated at scan end and re-populated for `titus report` runs (though by then findings already have their `Score` stored, so this is moot — report never calls scorers).

## CLI flags

- `--score-scope` (default `false`) — enables dynamic modifiers. Static modifiers always run if a scorer is registered.
- `--validate-workers N` (existing) — reused for scoring concurrency. No new `--score-workers` flag.
- `--score-timeout DURATION` (default 10s) — per-modifier HTTP timeout.
- `--score-budget DURATION` (default 60s) — per-finding overall scoring budget.

**Flag interaction:** `--score-scope` without `--validate` is a soft misconfiguration. Dynamic modifiers are skipped (they have no validated credentials to work against); static modifiers continue to run; a one-line stderr warning is emitted. The flags remain independent at the CLI layer for composability.

## Output formats

### JSON

```json
{
  "finding_id": "a099ef00...",
  "rule_id": "np.aws.1",
  "score": {
    "final": 85,
    "base": 60,
    "suggested_severity": "critical",
    "applied": [
      {
        "name": "iam-admin",
        "scorer": "aws-key-scope",
        "kind": "set_score",
        "value": 95,
        "priority": 50
      },
      {
        "name": "session-token",
        "scorer": "aws-key-scope",
        "kind": "delta",
        "value": -10,
        "priority": 100
      }
    ]
  },
  ...
}
```

### SARIF

- `level`: `none` (0-19), `note` (20-39), `warning` (40-59), `error` (60-100)
- `properties.security-severity`: `final / 10` as float (compatible with GitHub Code Scanning)
- `properties.titus_score`: full Score object for consumers that want the breakdown

### Human report

Score breakdown is **always shown** when any modifier fires (no `--verbose` gate):

```
Finding 1/11 (id a099ef006b08f45fcc9e5428263cbde15bea2de6)
  Score: 85/100 (critical)
    + iam-admin        sets score to 95
    - session-token    -10 (temporary credential)
  Rule: AWS API Credentials
  ...
```

Findings with no modifiers fired show only the base score on a single line.

## Chariot integration

Titus emits the raw 0-100 score plus `suggested_severity` tier and the `applied` audit trail. Chariot owns severity interpretation.

Reasoning:
- The 0-100 numeric scale is stable across Titus versions.
- Chariot can tune its severity mapping per customer (a financial-services tenant may treat `medium` as `high`).
- The `applied` array provides full context for Chariot's UI to explain scores to users.

The "demonstrated secret" trigger in Chariot becomes: `validation.status == valid AND score.final >= 80` → promote to critical. Validated-but-low-score findings (e.g., a working-but-read-only LinkedIn cookie) stay at medium or lower.

## Error handling

### HTTP error taxonomy

| Category                         | Retry? | Fallback                  |
|----------------------------------|--------|---------------------------|
| Context/deadline timeout         | No     | Skip modifier, log warn   |
| Rate limit (429)                 | Once (respect Retry-After, cap 30s) | Skip after retry        |
| Server 5xx                       | Once (1s backoff) | Skip after retry        |
| Network (connect refused, DNS)   | No     | Skip modifier, log warn   |
| TLS handshake failure            | No     | Skip modifier, log warn   |
| Body parse error (e.g., bad JSON)| No     | Skip modifier, log warn   |

### Per-finding budget

If cumulative scoring time for a single finding exceeds `--score-budget` (default 60s), remaining modifiers are skipped and the finding is marked with a partial-scoring warning in the audit trail.

### Aggregate reporting

The scan statistics line gains scoring diagnostics when `--score-scope` is set:
```
Scored 841 findings; 3 timeouts, 1 rate-limited, 0 network errors during scope checks
```

## Base score migration

### Strategy

A single PR introduces the scoring subsystem and backfills `base_score` for every existing rule simultaneously. No warning grace period; the loader requires `base_score` from the first release. Existing datastores (pre-scoring) render findings with `score == null` in JSON; the report command handles this gracefully.

### Research-driven scoring

Rather than a heuristic category-to-score mapping, base scores are **researched per rule**:
- Rules are batched by vendor/ecosystem (e.g., all `np.aws.*`, all `np.github.*`, all analytics keys)
- Each batch is dispatched to a research subagent (using `/research`)
- The research agent investigates real-world blast radius, known breach impact, and financial exposure for each secret class
- Results are returned as `(rule_id, proposed_base_score, tier, reasoning)` tuples
- Maintainer review merges the proposed scores

Expected parallelism: ~20 subagent batches covering ~500 rules. Human review takes a day or two; research itself is parallel.

### Loader enforcement

```go
// pkg/rule/loader.go
if rule.BaseScore == 0 {
    return nil, fmt.Errorf("rule %s: base_score is required", rule.ID)
}
if rule.BaseScore < 0 || rule.BaseScore > 100 {
    return nil, fmt.Errorf("rule %s: base_score must be 0-100, got %d", rule.ID, rule.BaseScore)
}
```

### Community contribution guardrails

A `make score-lint` target runs `pkg/rule/score_lint.go` which:
- Flags rules missing `base_score` (hard error)
- Flags rules whose `base_score` is wildly out of sync with the rule's category tier (soft warning — e.g., a rule named `aws.private.key` scored 20)

## Testing strategy

### Layer 1 — Engine math (`pkg/scoring/engine_test.go`)
- `TestScoreMath_BaseOnly`
- `TestScoreMath_SetScoreReplacesValue`
- `TestScoreMath_DeltaStacks`
- `TestScoreMath_SetScoreWipesPriorDeltas`
- `TestScoreMath_ClampsToBounds`
- `TestScoreMath_PriorityOrdering`
- `TestScoreMath_UnspecifiedPriorityYamlOrder`
- `TestEngine_NoScorerRegistered_ReturnsBaseOnly`
- `TestEngine_ScorePerFinding_NotPerMatch`
- `TestEngine_HTTPError_SkipsModifier_ContinuesScoring`

### Layer 2 — YAML scorer and condition DSL (`pkg/scoring/yaml_scorer_test.go`)
- One test per condition leaf (static and dynamic)
- Round-trip parse + evaluate
- Schema validation (malformed YAML, both `delta` and `set_score` on one modifier)
- Response cache hit/miss

### Layer 3 — Per-rule invariants (`pkg/rule/base_score_test.go`)
- `TestAllRules_HaveBaseScore`
- `TestCriticalTier_RulesExist`
- `TestTierBoundaries` (sanity guards on naming vs. score ranges)
- Golden file tests for end-to-end scoring

### Layer 4 — Go scorer tests (`pkg/scoring/aws_test.go` etc.)
- Per-scorer parity with validator test patterns
- HTTP mocking via `httptest`

### Layer 5 — HTTP error handling
- `TestHTTPError_ContextTimeout_MarksErrored`
- `TestHTTPError_RateLimit_RetriesThenSkips`
- `TestHTTPError_5xx_RetryOnceThenSkip`
- `TestHTTPError_Network_NoRetry`
- `TestHTTPError_MalformedJSON_SkipsCleanly`
- `TestScoring_ManyConsecutiveNetworkErrors_LogsButContinues`
- `TestScoring_PerFindingBudget_StopsAtLimit`

### Schema stability
- `TestScoreJSON_SchemaStability` — golden file of a scored finding's JSON output; intentional breaks require updating the golden file and versioning the schema.

## Milestones

### Milestone 1 — Base scoring only
- `pkg/types.Score` struct; `Rule.BaseScore` field; loader enforcement
- Research-driven base scores for every rule (one mega-PR)
- JSON/SARIF/human output changes, `suggested_severity` mapping
- Datastore schema migration (add `score` column on `findings`)
- No modifiers, no scoring engine yet
- Chariot can immediately benefit from per-rule severity differentiation

### Milestone 2 — Static modifiers
- `pkg/scoring` package scaffolding
- YAML scorer loader + condition DSL (static-only leaves)
- Scorer YAML files for AWS key prefix, GitHub fine-grained PAT detection
- No `--score-scope` flag yet; static modifiers always run if a scorer is registered

### Milestone 3 — Dynamic modifiers + `--score-scope`
- HTTP sub-schema in YAML scorers
- Engine HTTP cache, per-modifier timeout, per-finding budget
- Error handling taxonomy
- Full YAML scorers for GitHub, Slack, Okta
- Aggregate error reporting

### Milestone 4 — Go scorers
- `pkg/scoring/aws.go` — AWS SDK, STS GetCallerIdentity + IAM enumeration
- `pkg/scoring/github.go` — go-github client, complex org/team reasoning
- Go scorer registration precedence over YAML

## Open questions / future work

- **Compound conditions (`all:` / `any:` / `not:`)** — deferred to v2. Today every leaf condition stands alone. Real AWS admin detection may need OR across ListAttachedUserPolicies, ListUserPolicies, ListGroupsForUser.
- **Short-circuit termination (`stop_on_fire: true`)** — deferred. Would allow expensive modifiers to skip subsequent checks once a definitive signal fires.
- **Shared rate-limit buckets across scorers** — v1 has per-scorer buckets; cross-scorer sharing (e.g., one global GitHub bucket) is a follow-up.
- **`scope` caching across scans** — v1 caches HTTP responses within a single scan only. For CI where the same secret is scanned repeatedly, cross-scan caching keyed on secret hash could meaningfully reduce API load, but has security implications (stale cached data after credential rotation).
- **Replay / re-scoring of existing datastores** — a `titus rescore` command that re-runs scorers against a stored datastore without re-enumerating. Useful after scorer YAML changes.
- **User-defined scorer overrides** — a `--scorers PATH` flag mirroring the existing `--rules PATH` flag, so organizations can ship their own scoring logic without patching Titus.
