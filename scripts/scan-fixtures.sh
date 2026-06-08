#!/usr/bin/env bash
# scripts/scan-fixtures.sh
# Fails if Titus detects any secret in committed test fixtures.
# Run: bash scripts/scan-fixtures.sh
# Invoked automatically by: make scan-fixtures
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
TESTDATA="$ROOT/pkg/validator/testdata"

# If testdata directory doesn't exist yet, there's nothing to scan.
if [ ! -d "$TESTDATA" ]; then
  echo "OK: testdata/ directory does not exist yet -- nothing to scan"
  exit 0
fi

# Run titus scan and capture output. Fail loudly if the tool itself cannot run
# (build error, missing binary, bad flags, etc.) rather than silently returning
# zero findings and giving false confidence.
#
# Use --ruleset all so every rule fires regardless of score threshold.
# --output :memory: avoids writing a titus.ds file.
# --quiet suppresses the ASCII banner.
SCAN_OUT="$(GOWORK=off go run "$ROOT/cmd/titus" scan \
  --format json \
  --output :memory: \
  --ruleset all \
  --quiet \
  "$TESTDATA" 2>&1)" || {
  echo "FATAL: titus scan failed to run (build error or bad invocation):" >&2
  echo "$SCAN_OUT" >&2
  exit 1
}

COUNT="$(echo "$SCAN_OUT" | grep -c '"RuleID"' || true)"

if [ "$COUNT" -ne 0 ]; then
  echo "FATAL: $COUNT secret(s) found in testdata/ -- redact before commit"
  echo ""
  echo "Run the following to see findings:"
  echo "  GOWORK=off go run ./cmd/titus scan --format human --output :memory: --ruleset all $TESTDATA"
  exit 1
fi

echo "OK: no live secrets found in testdata/ ($COUNT findings)"
