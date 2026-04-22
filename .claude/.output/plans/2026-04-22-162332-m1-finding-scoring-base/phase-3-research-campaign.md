<!--
{
  "phase": 3,
  "title": "Research campaign: base_score for every rule via parallel subagents",
  "feature": "m1-finding-scoring-base",
  "linear": "LAB-2431",
  "depends_on": [2],
  "tasks": 6
}
-->

# Phase 3 — Research Campaign

> Depends on Phase 2 (migration tool must exist to apply the research output).
>
> This is the **most subagent-heavy phase** and has the highest risk of review overhead if the orchestration isn't tight. The entire design of this phase is to keep subagent output machine-consumable so the orchestrator can automate validation, sorting, and merging.

## Objective

Produce a single `scores.csv` with exactly one row per Titus detection rule. Each row contains:

```
rule_id,base_score,tier,reasoning
```

Dispatch research work across ~20 subagents batched by vendor/ecosystem, operating in parallel. The orchestrator validates each batch's output, merges into the master CSV, and hands off to the migration tool (Phase 2) for application.

## Entry criteria
- Phase 2 complete: `cmd/titus-migrate-scores` tool exists and is tested
- Every rule YAML is inspectable
- `pkg/rule/rules/` has ~299 YAML files, total rule count to be verified in Task 3.1

## Exit criteria
- [ ] `scores.csv` exists at `/tmp/titus-ci-fix/scores.csv`
- [ ] Every rule in `pkg/rule/rules/*.yml` has exactly one row in `scores.csv`
- [ ] Every row has a valid `base_score` in [0, 100] and a valid `tier` value
- [ ] `go run ./cmd/titus-migrate-scores -scores scores.csv -rules pkg/rule/rules/ -apply` completes without errors or missing-rule warnings

---

## Task 3.1: Enumerate all rules and build the batch plan

**Files:**
- Create: `scripts/enumerate_rules.sh` (temporary helper, committed for reproducibility)
- Create: `.claude/.output/plans/2026-04-22-162332-m1-finding-scoring-base/research/all_rules.csv` (intermediate file, not in git)

**Step 1: Count rules and group by prefix**

Run:
```bash
cd /tmp/titus-ci-fix
{
  echo "rule_id,rule_name,yaml_file"
  for f in pkg/rule/rules/*.yml; do
    # Extract (id, name) pairs from each rule YAML.
    awk -v file="$f" '
      /^[[:space:]]*- name:/ { name=$0; sub(/^[[:space:]]*- name:[[:space:]]*/, "", name); gsub(/"/, "", name) }
      /^[[:space:]]*id:/ { id=$0; sub(/^[[:space:]]*id:[[:space:]]*/, "", id); print id "," name "," file }
    ' "$f"
  done
} > /tmp/all_rules.csv
wc -l /tmp/all_rules.csv
```

Expected: ~500 rules (one per rule definition, one header line).

**Step 2: Group by vendor prefix for batching**

Run:
```bash
# Extract vendor prefix from each rule_id (second dotted segment: np.<vendor>.N or kingfisher.<vendor>.N)
awk -F'[.,]' 'NR>1 { print $2 }' /tmp/all_rules.csv | sort | uniq -c | sort -rn | head -40
```

This shows the top vendors by rule count. Build a batch plan where each batch targets a coherent vendor or group of related vendors, sized to be feasible for a single research subagent (roughly ≤40 rules per batch).

**Step 3: Save the batch plan**

Create `/tmp/titus-ci-fix/.claude/.output/plans/2026-04-22-162332-m1-finding-scoring-base/research/batch_plan.md`:

```markdown
# Batch Plan

| Batch ID | Vendors                              | Approx rule count |
|----------|--------------------------------------|-------------------|
| B01      | aws, azure, gcp                      | ~40               |
| B02      | github, gitlab, bitbucket            | ~20               |
| B03      | stripe, paypal, square, razorpay     | ~15               |
| B04      | slack, mattermost, teams, discord    | ~20               |
| B05      | openai, anthropic, cohere, groq, ...  (AI vendors) | ~30 |
| B06      | datadog, new relic, grafana, sentry  | ~25               |
| B07      | sendgrid, mailgun, mailchimp, postmark | ~15             |
| B08      | twilio, sendbird, messagebird        | ~10               |
| B09      | npm, pypi, docker, gradle, rubygems  | ~15               |
| B10      | kubernetes, hashicorp, helm          | ~10               |
| B11      | algolia, apify, airtable, atlassian  | ~15               |
| B12      | generic (np.generic.*), pem          | ~10               |
| B13      | credentials, jdbc, postgres, mysql, odbc | ~15           |
| B14      | linkedin, twitter, facebook, instagram | ~15             |
| B15      | shopify, bigcommerce                 | ~10               |
| B16      | google, youtube, maps, ...           | ~15               |
| B17      | ai-related mid-tier (baseten, together, etc.) | ~20      |
| B18      | telemetry/observability misc         | ~15               |
| B19      | random SaaS tier-2                   | ~30               |
| B20      | everything else                      | ~30               |
```

The exact batch membership is derived from the rules enumeration in Step 2 — adjust based on actual count per vendor. The 20-batch structure keeps each subagent's scope manageable.

**Step 4: Commit helper script and plan**

```bash
cd /tmp/titus-ci-fix && git add -f .claude/.output/plans/2026-04-22-162332-m1-finding-scoring-base/research/ && git commit -m "docs(research): batch plan for base_score research campaign"
```

**Exit Criteria:**
- [ ] All rules enumerated with rule_id, name, yaml_file columns
- [ ] Batch plan covers every rule (verify: sum of approx rule counts >= total rule count)

---

## Task 3.2: Standard research subagent prompt

Every research subagent uses this exact prompt template. The orchestrator substitutes `{{BATCH_ID}}`, `{{RULES_JSON}}`, and `{{OUTPUT_PATH}}` per dispatch.

**Files:**
- Create: `.claude/.output/plans/2026-04-22-162332-m1-finding-scoring-base/research/subagent_prompt_template.md`

Contents:

````markdown
# Research subagent prompt (batch {{BATCH_ID}})

You are assigning `base_score` values to Titus secret-detection rules.

## Context

Titus is a secrets-scanner. Each rule detects a specific class of secret (e.g., an AWS API key, a GitHub token, a LinkedIn session cookie). We need to assign each rule a **base_score** in the range [0, 100] representing the intrinsic severity of that secret class if leaked.

Severity is driven primarily by:
1. **Financial impact** — can the key spend money or move assets? (AWS, Stripe → high)
2. **Blast radius** — what systems does one credential unlock? (SSO tokens → high; one-user APIs → low)
3. **Authorization power** — is this admin/root or limited? (root keys → high; read-only metrics → low)
4. **Remediation cost** — how hard is rotation + containment?
5. **Secondary exposure** — does compromise enable further lateral movement?

## Tier system

| Tier      | Range   | Meaning                                                                 |
|-----------|---------|-------------------------------------------------------------------------|
| critical  | 80-100  | Cloud infrastructure (AWS/Azure/GCP), payments (Stripe), PEM keys       |
| high      | 60-79   | Source control with write access, SSO, admin-tier API keys              |
| medium    | 40-59   | Typical SaaS API keys (email sending, generic API integrations)         |
| low       | 20-39   | Analytics, telemetry, single-user session tokens, reference data        |
| info      | 0-19    | Identifiers that aren't themselves secrets (AWS Account IDs, client IDs) |

## Your task

For each rule in the input batch, produce a single CSV row:

```
rule_id,base_score,tier,reasoning
```

Where:
- `rule_id` — exact match to the input (e.g., `np.aws.1`)
- `base_score` — integer 0-100
- `tier` — one of: info | low | medium | high | critical
- `reasoning` — 1-3 sentences explaining your score, mentioning blast radius and financial impact

## Rules in this batch

```json
{{RULES_JSON}}
```

Each entry in the JSON array has:
- `id` — the rule ID
- `name` — human-readable name
- `yaml_file` — path to the rule's source YAML (you may read it for context like description and references)

## Research method (per rule)

1. **Skim the rule's YAML** — the `name`, `description`, `references`, and `categories` fields often clarify what the secret class is.
2. **Consult references** — the `references` field usually points to the vendor's documentation. Look for documented capabilities of the secret.
3. **Compare against known examples in the tier table above** — for a new vendor, find the closest analog.
4. **Assign conservatively** — if in doubt between two tiers, pick the higher one for cloud/payment/infrastructure, the lower one for analytics/metrics.

## Constraints

- Do NOT assign scores based on how common the secret is in the wild — severity ≠ prevalence.
- Do NOT use fractional scores — integers only.
- Do NOT give every rule the same score — differentiation is the entire point.
- If a rule is an identifier (e.g., "AWS Account ID", "Client ID") that is not itself a secret, score it ≤ 19 (info tier).
- If a rule's purpose is unclear from the YAML, default to medium (50) and mark the reasoning with "LOW CONFIDENCE: ".

## Output format

Write a CSV file to `{{OUTPUT_PATH}}` with **exactly** this shape — header plus one row per rule:

```
rule_id,base_score,tier,reasoning
np.aws.1,60,high,"AWS access key ID alone is an identifier. In isolation without the secret access key, it's useful for attribution and reconnaissance but not direct impact."
np.aws.2,85,critical,"AWS secret access key grants programmatic access to whatever IAM identity owns the key. Combined with key ID (from separate rule), can be full cloud takeover."
np.linkedin.1,25,low,"LinkedIn session cookie compromises one user's profile and connections. Limited lateral movement, no financial impact."
```

Every row must be present. Missing rules are a hard error.

## Verification before returning

After writing the CSV:
1. Count rows — must equal the number of input rules.
2. Spot-check 3 rows — re-read your reasoning and verify the tier matches your score range.
3. If more than 50% of your scores are in the same tier, reconsider — you're probably not differentiating enough.

## Final output

Print to stdout:
- Path to the CSV file you wrote
- A one-line summary: `Batch {{BATCH_ID}}: N rules scored (critical=X, high=Y, medium=Z, low=W, info=V)`

Do not write any other files.
````

**Commit:**

```bash
cd /tmp/titus-ci-fix && git add -f .claude/.output/plans/2026-04-22-162332-m1-finding-scoring-base/research/subagent_prompt_template.md && git commit -m "docs(research): standard subagent prompt template"
```

**Exit Criteria:**
- [ ] Prompt template covers: task definition, tier system, research method, constraints, output format, verification steps

---

## Task 3.3: Dispatch research subagents in parallel

**Orchestrator actions (not a single script — the orchestrating Claude session does this):**

For each batch in the batch plan:

1. **Extract rules JSON for the batch**:
   ```bash
   # Filter /tmp/all_rules.csv by vendor prefix for this batch
   # Build JSON array in the format expected by the prompt
   ```

2. **Instantiate the prompt template** with:
   - `{{BATCH_ID}}` = batch identifier (e.g., `B01`)
   - `{{RULES_JSON}}` = the JSON array for this batch
   - `{{OUTPUT_PATH}}` = `/tmp/titus-ci-fix/.claude/.output/plans/2026-04-22-162332-m1-finding-scoring-base/research/batch_{{BATCH_ID}}.csv`

3. **Dispatch via `Agent` tool** with subagent_type=`core:research` (or `general-purpose` if research agent isn't available):

   ```
   Agent(
     description: "Score research batch B01 (AWS/Azure/GCP)",
     subagent_type: "general-purpose",
     prompt: "<instantiated template from Task 3.2>",
     run_in_background: true
   )
   ```

4. **Collect results** — each subagent writes its CSV to the output path. Orchestrator reads each CSV as it completes.

**Parallelism:** Dispatch all 20 batches concurrently. Each should take 5-15 minutes depending on how many rules are in the batch. Total wall-clock time: ~20 min for the entire campaign.

**Exit Criteria:**
- [ ] 20 CSV files exist in `research/batch_B*.csv`
- [ ] Each CSV has a header + N rows matching its batch's rule count

---

## Task 3.4: Validate and merge batches into master scores.csv

**Files:**
- Create: `.claude/.output/plans/2026-04-22-162332-m1-finding-scoring-base/research/merge_batches.sh`

**Step 1: Write validation + merge script**

```bash
#!/usr/bin/env bash
set -euo pipefail

RESEARCH_DIR=".claude/.output/plans/2026-04-22-162332-m1-finding-scoring-base/research"
MASTER="scores.csv"

# Write header
echo "rule_id,base_score,tier,reasoning" > "$MASTER"

# Concatenate all batch CSVs, skipping their headers
total=0
for csv in "$RESEARCH_DIR"/batch_B*.csv; do
    [ -f "$csv" ] || { echo "Missing: $csv"; exit 1; }
    rows=$(tail -n +2 "$csv" | wc -l | tr -d ' ')
    total=$((total + rows))
    tail -n +2 "$csv" >> "$MASTER"
done

echo "Merged $total rows into $MASTER"

# Verify: no duplicate rule_ids
dups=$(awk -F, 'NR>1 {print $1}' "$MASTER" | sort | uniq -d)
if [ -n "$dups" ]; then
    echo "ERROR: duplicate rule_ids found:" >&2
    echo "$dups" >&2
    exit 1
fi

# Verify: every row has a score in [0, 100]
awk -F, 'NR>1 { if ($2 < 0 || $2 > 100) { print "OUT OF RANGE: " $0; exit 1 } }' "$MASTER"

# Verify: every row has a valid tier
awk -F, 'NR>1 { if ($3 !~ /^(info|low|medium|high|critical)$/) { print "INVALID TIER: " $0; exit 1 } }' "$MASTER"

echo "Validation passed."

# Cross-check against all_rules.csv
tmpfile=$(mktemp)
awk -F, 'NR>1 {print $1}' /tmp/all_rules.csv | sort > "${tmpfile}.rules"
awk -F, 'NR>1 {print $1}' "$MASTER" | sort > "${tmpfile}.scores"

missing=$(comm -23 "${tmpfile}.rules" "${tmpfile}.scores")
if [ -n "$missing" ]; then
    echo "ERROR: rules missing from scores.csv:" >&2
    echo "$missing" >&2
    exit 1
fi

extra=$(comm -13 "${tmpfile}.rules" "${tmpfile}.scores")
if [ -n "$extra" ]; then
    echo "WARNING: scores.csv contains rules not in rule enumeration:" >&2
    echo "$extra" >&2
fi

rm -f "${tmpfile}.rules" "${tmpfile}.scores"
echo "Cross-check passed."
```

Make executable: `chmod +x merge_batches.sh`

**Step 2: Run the script**

```bash
cd /tmp/titus-ci-fix
bash .claude/.output/plans/2026-04-22-162332-m1-finding-scoring-base/research/merge_batches.sh
```

Expected: `Merged N rows into scores.csv`, `Validation passed.`, `Cross-check passed.`

**Step 3: Commit**

```bash
cd /tmp/titus-ci-fix && git add -f .claude/.output/plans/2026-04-22-162332-m1-finding-scoring-base/research/merge_batches.sh scores.csv && git commit -m "feat(research): merged master scores.csv from 20 research batches"
```

**Exit Criteria:**
- [ ] `scores.csv` at repo root has one row per rule
- [ ] No duplicates, no out-of-range scores, no invalid tiers
- [ ] All rules enumerated in `all_rules.csv` appear in `scores.csv`

---

## Task 3.5: Apply scores.csv via migration tool

**Step 1: Dry run first**

```bash
cd /tmp/titus-ci-fix
make build-migrate-scores
./dist/titus-migrate-scores -scores scores.csv -rules pkg/rule/rules/
```

Expected: reports expected changes, no write. Exit 0 if no unscored rules.

**Step 2: Apply**

```bash
cd /tmp/titus-ci-fix
./dist/titus-migrate-scores -scores scores.csv -rules pkg/rule/rules/ -apply
```

Expected: `Changes applied.`

**Step 3: Verify every rule YAML now has base_score**

```bash
# Count rules defined:
ruleCount=$(awk '/^[[:space:]]*id:/' pkg/rule/rules/*.yml | wc -l)
# Count rules with base_score:
scoreCount=$(awk '/^[[:space:]]*base_score:/' pkg/rule/rules/*.yml | wc -l)
echo "Rules: $ruleCount; with base_score: $scoreCount"
# These must match
[ "$ruleCount" -eq "$scoreCount" ] || { echo "MISMATCH"; exit 1; }
```

**Step 4: Build and smoke-test loader**

```bash
cd /tmp/titus-ci-fix && GOWORK=off go build ./... && GOWORK=off go test ./pkg/rule/ -v | tail -20
```

Expected: build succeeds, all loader tests pass (they should continue passing since Phase 0 made `base_score` optional in the loader).

**Step 5: Commit the rule YAML updates**

```bash
cd /tmp/titus-ci-fix && git add -f pkg/rule/rules/ && git commit -m "feat(rules): assign researched base_score to every detection rule"
```

This commit will be large — expect ~500 lines added, one per rule.

**Exit Criteria:**
- [ ] Count of `base_score:` lines in YAMLs matches total rule count
- [ ] All loader tests pass
- [ ] `go build ./...` succeeds

---

## Task 3.6: Sanity-review by tier distribution

After the mega-commit, run a tier-distribution sanity check:

```bash
cd /tmp/titus-ci-fix
awk -F, 'NR>1 {print $3}' scores.csv | sort | uniq -c | sort -rn
```

Expected distribution (approximate):
- critical: 30-60
- high: 80-120
- medium: 150-250
- low: 80-120
- info: 30-70

**Red flags to investigate:**
- Any tier with 0 entries → prompt didn't achieve differentiation
- `medium` > 60% of rules → subagents defaulted when uncertain, needs human review of `LOW CONFIDENCE` rows
- `critical` > 25% of rules → subagents over-scored, needs downgrade review

**Commit review notes:**

Create `.claude/.output/plans/2026-04-22-162332-m1-finding-scoring-base/research/tier_distribution.md` with the actual numbers and flag any rules where a human maintainer should validate:

```markdown
# Tier Distribution (actual)

| Tier     | Count | % of total |
|----------|-------|-----------|
| critical | XX    | XX%       |
| high     | XX    | XX%       |
| medium   | XX    | XX%       |
| low      | XX    | XX%       |
| info     | XX    | XX%       |

## LOW CONFIDENCE rules (human review needed)

<list rule_ids where reasoning starts with "LOW CONFIDENCE: ">

## Flagged for tier verification

<list rule_ids that appear possibly mis-tiered, e.g., a rule named "aws.*" scored < 60>
```

```bash
cd /tmp/titus-ci-fix && git add -f .claude/.output/plans/2026-04-22-162332-m1-finding-scoring-base/research/tier_distribution.md && git commit -m "docs(research): tier distribution and human-review flags"
```

**Exit Criteria:**
- [ ] Tier distribution report exists
- [ ] LOW CONFIDENCE rules are listed for human review in Phase 4

## Handoff

Phase 3 complete:
- Every rule has a researched `base_score`
- Migration is applied
- Tier distribution is documented
- Rules needing human review are flagged

Phase 4 now has real data to run loader enforcement and score-lint against.
