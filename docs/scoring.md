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

**Targets:** `np.github.7` (fine-grained PATs)

| Modifier | Priority | Kind | Condition | Effect |
|----------|----------|------|-----------|--------|
| Static: fine-grained PAT prefix | 100 | static | Token is a fine-grained PAT | `delta -10` — fine-grained PATs are structurally scoped at creation |

Classic PATs (`np.github.1`) and OAuth tokens (`np.github.2`) are scored by the
`GitHubClassicPATGoScorer` Go scorer (see below), which parses the
`X-OAuth-Scopes` header with exact-token matching.

### `slack.yaml` — Slack Token Scoring

**Targets:** `np.slack.2`, `np.slack.4`, `np.slack.6` (bot/user tokens)

| Modifier | Priority | Kind | Condition | Effect |
|----------|----------|------|-----------|--------|
| Dynamic: Enterprise Grid check | — | dynamic (`--score-scope`) | `auth.test` API call succeeds and response contains `enterprise_id` | `delta +15` — Enterprise Grid tokens have broader organizational impact |

---

## Built-in Go Scorers

Go scorers use service SDKs (not raw HTTP) for more sophisticated verification and run only when `--score-scope` is enabled. The full set is registered in `pkg/scoring/go_scorers.go`; the AWS and GitHub scorers documented below live in `pkg/scoring/aws.go`, `pkg/scoring/github.go`, and `pkg/scoring/github_classic.go`.

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

### `GitHubClassicPATGoScorer` — GitHub Classic PATs & OAuth Tokens

**Targets:** `np.github.1` (classic PAT), `np.github.2` (OAuth token)

Classic PATs and OAuth tokens carry a comma-separated scope list in the
`X-OAuth-Scopes` response header. Scopes are parsed with exact-token matching
(not substring), so `public_repo` is never conflated with `repo`, nor
`read:user` with `user`. All modifiers are dynamic (`--score-scope` required).

| Modifier | Priority | Kind | Condition | Effect |
|----------|----------|------|-----------|--------|
| `token-revoked` | 80 | `set_score 5` | `GET /user` returns 401 | Expired or revoked token (dead credential) |
| `read-user-only` | 78 | `set_score 10` | Scopes ⊆ `{read:user}` (non-empty) | Profile read only, no repo access |
| `public-repo-only` | 76 | `set_score 25` | Scopes ⊆ `{public_repo}` (non-empty) | Read/write public repos only, no private data |
| `delete-repo-scope` | 60 | `set_score 85` | `delete_repo` ∈ scopes | Destructive repository access |
| `admin-org-scope` | 55 | `set_score 90` | `admin:org` ∈ scopes | Full organization control |
| `site-admin` | 50 | `set_score 95` | `GET /user` `.site_admin == true` | GitHub instance admin (self-hosted Enterprise Server) |
| `org-owner-3plus` | 20 | `delta +12` | ≥3 active org memberships with role `admin` (`GET /user/memberships/orgs`) | Broad blast radius across owned orgs |
| `enterprise-plan` | 18 | `delta +15` | `GET /user` `.plan.name == enterprise` | Enterprise account — elevated organizational risk |

`set_score` priorities are ordered so the most severe co-firing modifier applies
last (the engine's last-fired `set_score` wins). The scope-only DOWN modifiers
are mutually exclusive with the scope UP modifiers by construction; `site-admin`
is orthogonal to scopes, and its lower priority lets it correctly override
`admin:org`/`delete_repo` when all are present. `org-owner-3plus` is a `delta`
and fires last, stacking on top of whichever `set_score` won — e.g. a
`site-admin` token (95) that owns 3+ orgs reaches the 100 ceiling after the
final clamp.

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
          value: 'api_key='
          within: 64
        delta: 5

      # Static modifier: fires based on secret length (useful as an entropy proxy)
      - name: long-token
        priority: 70
        match_length:
          op: gt          # gt | lt | eq
          value: 40
        delta: 10

      # Dynamic modifier: makes a live HTTP call (only fires with --score-scope)
      - name: check-active
        priority: 90
        http:
          method: GET
          url: "https://api.example.com/me"
          auth:
            type: bearer
            secret_group: "token"   # named capture group holding the secret
        fires_when:
          status_code: 200
        delta: 20
```

### HTTP Modifier Details

Dynamic (`http`) modifiers support the following options:

**Authentication (`auth`):**

`auth.type` selects the scheme and `auth.secret_group` names the rule capture
group holding the secret:

| Type | Effect |
|------|--------|
| `bearer` | `Authorization: Bearer <secret>` |
| `basic` | `Authorization: Basic base64(<username>:<secret>)` (set `username`) |
| `header` | Sends the secret in `header_name` |
| `query` | Sends the secret in the `query_param` query parameter |
| `api_key` | `Authorization: <key_prefix><secret>` (`key_prefix` defaults to `key=`) |
| `none` | No auth header — for APIs that take the credential in the URL or body via a `{{template}}` variable |

An unsupported `auth.type` is rejected at load time rather than failing per-request.
Keep `secret_group` set even with `none`: the response cache keys on it, so omitting
it makes every finding sharing a URL template collide on one cache entry.

**Firing conditions (`fires_when`):**

| Condition | Description |
|-----------|-------------|
| `status_code` | Fires when the HTTP response status equals the given code |
| `status_code_in` | Fires when the response status is any of the given codes |
| `response_body_contains` | Fires when the response body contains a substring |
| `header_contains` | Fires when a specific response header contains a substring |
| `json_path_equals` | Fires when a dot-notation path equals a specific value |
| `json_path_matches` | Fires when a dot-notation path matches a regex |
| `json_array_length_gte` | Fires when a dot-notation path is an array with at least N elements |

Paths are simple dot-notation (`.`, `.field`, `.a.b`); array indexing is not supported.

**Negating a condition (`negative`):**

Set `negative: true` alongside a leaf to invert it. It modifies the leaf rather than
being a leaf itself, so a `fires_when` block still requires exactly one condition:

```yaml
fires_when:
  negative: true
  json_array_length_gte:
    path: ".scopes"
    value: 25          # fires when there are FEWER than 25 scopes
```

This supplies the absence and upper-bound tests the condition list otherwise lacks.

Errors are propagated, never inverted: a path that does not exist is an error rather
than a `false`, so a negated `json_path_*` will not fire on a response missing the
field. For absence checks prefer `response_body_contains`, which cannot error.

**Template variables:**

Use `{{name}}` (or `{{ name }}` with spaces) in the URL, header values, or request body to inject a named capture group from the rule regex. If your rule captures a token in a group named `token`, write `{{token}}`.

Note the secret itself is normally injected via `auth.secret_group` rather than a template variable; template variables are for the other captures a request needs, such as an account or region identifier.

**Response caching:**

Within a single scan, responses are cached on the **rendered** request: method, URL, headers, body, auth scheme and secret, after template substitution. If several modifiers for the same finding issue the same request, only one network call is made -- so a scorer can split its logic across many modifiers without multiplying traffic.

Because the key is a hash of all of those together, credentials never appear in cache keys even though a rendered URL or body may contain them. Requests that differ in any component -- including a non-secret template variable such as a region or account identifier -- get separate entries, so a template variable is a safe way to distinguish two requests.

Header order is significant: two modifiers declaring the same headers in a different order miss the shared entry and issue separate requests. That costs an extra call, never a wrong response.

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
