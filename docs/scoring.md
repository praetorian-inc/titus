# Titus Scoring System

Titus assigns a numeric score to every finding to help you prioritize remediation. Each detection rule carries a `base_score` (0–100). When a finding is produced, one or more **modifiers** are applied on top of that base score to produce a **final score** that maps to a human-readable severity tier. Modifiers can be static (always fire) or dynamic (require live network calls to verify a credential). This document explains how scoring works, which scorers ship with Titus, and how to write your own.

---

## Overview

The scoring pipeline runs after a match is found:

1. The rule's `base_score` becomes the starting score.
2. All registered scorers are checked; any scorer targeting the matched rule ID contributes its modifiers.
3. Modifiers are sorted by **descending priority** (highest number fires first). Modifiers with equal priority apply in YAML definition order.
4. Each modifier either adds/subtracts a value (`delta`) or replaces the running score entirely (`set_score`).
5. The final score is clamped to [0, 100] and mapped to a severity tier.
6. An `accessibility` modifier (from the `scan-context` scorer) may apply an additional penalty based on whether the repository is public or private.

---

## Severity Tiers

| Tier       | Score Range |
|------------|-------------|
| `info`     | 0 – 20      |
| `low`      | 21 – 40     |
| `medium`   | 41 – 60     |
| `high`     | 61 – 80     |
| `critical` | 81 – 100    |

Source: `pkg/types/score.go`

---

## Modifier Kinds

Two modifier kinds are available:

| Kind        | Effect                                                     |
|-------------|------------------------------------------------------------|
| `delta`     | Adds (or subtracts) a fixed value from the running score.  |
| `set_score` | Replaces the running score with an absolute value.         |

---

## CLI Flags

These flags control scoring behavior when running `titus scan`:

| Flag | Default | Description |
|------|---------|-------------|
| `--score-scope` | disabled | Enables **dynamic** modifiers that make live HTTP or SDK API calls to verify whether a discovered credential is active. Disabled by default because it sends real network requests. |
| `--score-timeout duration` | `10s` | Per-modifier timeout for HTTP/SDK calls when `--score-scope` is enabled. |
| `--score-budget duration` | `60s` | Total time budget for scoring a single finding across all its modifiers. |
| `--accessibility string` | `auto` | Controls the code-accessibility modifier applied by the `scan-context` scorer. Options: `public` (no penalty), `private` (−25 to all scores), `auto` (detect from git remote or GitHub API; defaults to `private` if undetermined). |

Source: `cmd/titus/scan.go`

---

## Built-in YAML Scorers

Titus ships three YAML scorer files in `pkg/scoring/scorers/`. These run for every scan (static modifiers always; dynamic modifiers only with `--score-scope`).

### `aws.yaml` — AWS Credential Scoring

**Targets:** `np.aws.1`, `np.aws.6`

| Modifier | Priority | Condition | Effect |
|----------|----------|-----------|--------|
| `akia-long-term` | 100 | Key prefix matches `^AKIA` | `delta +10` — long-lived IAM credentials carry higher risk |
| `asia-temporary-session` | 100 | Key prefix matches `^ASIA` | `delta -10` — short-lived STS session tokens are less impactful |
| `aida-user-identifier` | 100 | Key prefix matches `^AIDA` | `set_score 10` — this is a user identifier, not a usable credential |

### `github.yaml` — GitHub Token Scoring

**Targets:** `np.github.1`, `np.github.2` (classic PATs), `np.github.7` (fine-grained PATs)

| Modifier | Priority | Kind | Condition | Effect |
|----------|----------|------|-----------|--------|
| Static: fine-grained PAT prefix | — | static | Token is a fine-grained PAT | `delta -10` — fine-grained PATs are structurally scoped at creation |
| Dynamic: OAuth scope extraction | — | dynamic (`--score-scope`) | HTTP `GET /user` succeeds | Inspects `X-OAuth-Scopes` header; enterprise membership adds `delta +15`; broad scopes (`repo`, `admin`) raise score; limited scopes (`public_repo` only) lower score |

### `slack.yaml` — Slack Token Scoring

**Targets:** `np.slack.2`, `np.slack.4`, `np.slack.6` (bot/user tokens)

| Modifier | Priority | Kind | Condition | Effect |
|----------|----------|------|-----------|--------|
| Dynamic: Enterprise Grid check | — | dynamic (`--score-scope`) | `auth.test` API call succeeds and response contains `enterprise_id` | `delta +15` — Enterprise Grid tokens have broader organizational impact |

---

## Built-in Go Scorers

Two Go scorers use the AWS and GitHub SDKs (not raw HTTP) for more sophisticated verification. Both run only when `--score-scope` is enabled. Source files: `pkg/scoring/aws.go`, `pkg/scoring/github.go`, registered in `pkg/scoring/go_scorers.go`.

Go scorers take precedence over YAML scorers: if both a Go scorer and a YAML scorer target the same rule ID, the Go scorer wins.

### `AWSGoScorer` — AWS Key + Secret Pair

**Targets:** `np.aws.6` (key ID + secret access key pair)

**Static modifiers (always fire):**

Same AKIA/ASIA/AIDA prefix logic as `aws.yaml` above.

For `^ASIA` keys, the scorer automatically extracts any accompanying session token from `Snippet.After` (surrounding context).

**Dynamic modifiers (`--score-scope` required):**

| Modifier | SDK Call | Effect |
|----------|----------|--------|
| Credential liveness check | `sts:GetCallerIdentity` | `delta +5` if the credential is valid and active |
| Administrator access | `iam:ListAttachedUserPolicies` or `iam:ListAttachedRolePolicies` | `set_score 99` if `AdministratorAccess` or `PowerUserAccess` is attached |
| Broad write access | Same as above | `set_score 85` if other broad write policies are attached |
| Read-only access | Same as above | `delta -20` if only `ReadOnlyAccess` or `ViewOnlyAccess` policies are attached |
| Role enumeration | `iam:ListRoles` | `delta +10` if the key can enumerate IAM roles (indicates broad IAM read privileges) |

### `GitHubGoScorer` — GitHub Fine-Grained PATs

**Targets:** `np.github.7` (fine-grained personal access tokens)

**Static modifiers (always fire):**

| Modifier | Condition | Effect |
|----------|-----------|--------|
| `fine-grained-pat-prefix` | Token has fine-grained PAT prefix | `delta -10` — PATs are structurally scoped at creation |

**Dynamic modifiers (`--score-scope` required):**

| Modifier | SDK Call | Effect |
|----------|----------|--------|
| Repository admin access | `GET /user/repos` (paginated, up to 500 repos) | `set_score 92` if admin access on any repo |
| Repository write access | Same | `set_score 85` if write access on any repo (only if admin was not also found) |
| Organization membership | `GET /user/orgs` | `delta +8` if token has org membership |

---

## Writing Custom YAML Scorers

You can write YAML scorers to extend or override scoring for any rule ID, including your own custom rules.

### Full Format Reference

```yaml
scorers:
  - name: my-scorer-name
    rule_ids:
      - np.aws.6          # list of rule IDs this scorer applies to
      - my.custom.rule.1
    modifiers:
      # Static modifier: fires based on a named capture group value
      - name: my-static-modifier
        priority: 100
        match_group:
          name: key_id          # named capture group from the rule regex pattern
          matches: '^PREFIX'    # regex tested against the captured group value
        delta: 15               # OR use: set_score: 75

      # Static modifier: fires based on surrounding context of the match
      - name: config-file-context
        priority: 80
        surrounding_context_contains:
          pattern: 'api_key\s*='
        delta: 5

      # Static modifier: fires based on secret length (useful as an entropy proxy)
      - name: long-token
        priority: 70
        match_length:
          min: 40
        delta: 10

      # Dynamic modifier: makes a live HTTP call (only fires with --score-scope)
      - name: check-active
        priority: 90
        http:
          method: GET
          url: "https://api.example.com/me"
          auth:
            bearer: "{{ .Groups.token }}"    # inject named capture group as Bearer token
        fires_when:
          status_code_is: 200
        delta: 20
```

### HTTP Modifier Details

Dynamic (`http`) modifiers support the following options:

**Authentication:**
- `auth.bearer`: injects a named capture group value as a `Bearer` token in the `Authorization` header.

**Firing conditions (`fires_when`):**

| Condition | Description |
|-----------|-------------|
| `status_code_is` | Fires when the HTTP response status matches the given code |
| `header_contains` | Fires when a specific response header contains a substring |
| `json_path_equals` | Fires when a JSONPath expression equals a specific value |
| `json_path_matches` | Fires when a JSONPath expression matches a regex |
| `json_array_length_gte` | Fires when a JSONPath array has at least N elements |

**Template variables:**

Use `{{ .Groups.<name> }}` in URL strings or header values to inject named capture groups from the rule regex. Example: if your rule captures a token in a group named `token`, use `{{ .Groups.token }}` anywhere in the HTTP modifier.

**Response caching:**

Within a single scan, identical HTTP requests (same URL, method, and headers) are cached. If multiple modifiers for the same finding make the same call, only one network request is sent.

---

## Writing Custom Go Scorers

For cases where YAML conditions are insufficient — multi-step SDK flows, complex response parsing, state carried between modifier checks — implement the `scoring.Condition` interface in Go.

### The `Condition` Interface

```go
package scoring

import (
    "context"
    "github.com/praetorian-inc/titus/pkg/types"
)

type myCondition struct{}

// markDynamic gates this condition behind --score-scope.
// Omit this method entirely for static conditions that always run.
func (c *myCondition) markDynamic() {}

func (c *myCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
    // Extract named capture groups from the match
    token, ok := m.NamedGroups["token"]
    if !ok {
        return false, nil
    }

    // Perform your API or SDK call here.
    // Return true to fire the modifier, false to skip it.
    return checkTokenActive(ctx, string(token))
}
```

### Registering a Custom Go Scorer

```go
func MyServiceScorer() *scoring.Scorer {
    return &scoring.Scorer{
        Name:    "my-service-scope",
        RuleIDs: []string{"np.myservice.1"},
        Modifiers: []scoring.Modifier{
            {
                Name:      "token-active",
                Priority:  90,
                Kind:      scoring.ModifierKindDelta,
                Value:     25,
                Condition: &myCondition{},
            },
        },
    }
}
```

Prepend your scorer to the scorer list inside `buildScoringEngine()` in `cmd/titus/scan.go`. Go scorers are first-match: if a Go scorer and a YAML scorer both target the same rule ID, the Go scorer wins.

---

## Library API

If you use Titus as a Go library, scoring integrates through scanner options.

### Scanner Options

```go
import "github.com/praetorian-inc/titus"

// Enable scoring (static modifiers only, no network calls)
scanner, err := titus.NewScanner(
    titus.WithScoring(),
)

// Enable dynamic scoring (makes live API/SDK calls)
scanner, err := titus.NewScanner(
    titus.WithScoring(titus.ScopeEnabled(true)),
)

// Set accessibility context explicitly (disables auto-detection)
scanner, err := titus.NewScanner(
    titus.WithScoring(),
    titus.WithAccessibility("public"),   // "public" or "private"
)
```

### Accessing Score Results

Each `Match` returned by the scanner includes an optional `Score` field:

```go
matches, _ := scanner.ScanString(content)
for _, m := range matches {
    if m.Score != nil {
        fmt.Printf("%s: score=%d severity=%s\n",
            m.RuleID, m.Score.Final, m.Score.SuggestedSeverity)

        // Inspect which modifiers fired and by how much
        for _, mod := range m.Score.Applied {
            fmt.Printf("  [%s] %s: %+d\n", mod.Scorer, mod.Name, mod.Value)
        }
    }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `m.Score.Final` | `int` | Final clamped score after all modifiers |
| `m.Score.SuggestedSeverity` | `string` | Severity tier: `info`, `low`, `medium`, `high`, or `critical` |
| `m.Score.Applied` | `[]AppliedModifier` | List of modifiers that fired, with scorer name, modifier name, and delta/set value |
