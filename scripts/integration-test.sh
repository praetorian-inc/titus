#!/bin/bash
# Integration tests for Titus secrets scanner
# Runs scans against test fixtures and validates output

set -e  # Exit on error

# Configuration
TITUS="${TITUS:-./titus}"
TESTDATA_DIR="${TESTDATA_DIR:-testdata/secrets}"
RESULTS_FILE="/tmp/titus-integration-results.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Helper functions
pass() {
    echo -e "${GREEN}PASS${NC}: $1"
}

fail() {
    echo -e "${RED}FAIL${NC}: $1"
    exit 1
}

# Check prerequisites
echo "=== Checking prerequisites ==="
if [ ! -x "$TITUS" ]; then
    fail "Titus binary not found at $TITUS. Run 'make build' first."
fi

if ! command -v jq &> /dev/null; then
    fail "jq is required but not installed."
fi

echo "Titus: $TITUS"
echo "Test data: $TESTDATA_DIR"
echo ""

# Test 1: Filesystem scan produces JSON output
echo "=== Test 1: Filesystem Scan ==="
$TITUS scan "$TESTDATA_DIR" --format=json > "$RESULTS_FILE" 2>&1

if [ ! -s "$RESULTS_FILE" ]; then
    fail "No output produced from scan"
fi
pass "Scan produced output"

# Test 2: JSON output is valid
echo "=== Test 2: Valid JSON Output ==="
if ! jq empty "$RESULTS_FILE" 2>/dev/null; then
    fail "Output is not valid JSON"
fi
pass "Output is valid JSON"

# Test 3: AWS secrets detected
echo "=== Test 3: AWS Secrets Detection ==="
aws_count=$(jq '[.[] | select(.RuleID | startswith("np.aws"))] | length' "$RESULTS_FILE" 2>/dev/null || echo "0")
if [ "$aws_count" -lt 1 ]; then
    fail "Expected at least 1 AWS finding, got $aws_count"
fi
pass "Found $aws_count AWS findings"

# Test 4: GitHub secrets detected
echo "=== Test 4: GitHub Secrets Detection ==="
github_count=$(jq '[.[] | select(.RuleID | startswith("np.github"))] | length' "$RESULTS_FILE" 2>/dev/null || echo "0")
if [ "$github_count" -lt 1 ]; then
    fail "Expected at least 1 GitHub finding, got $github_count"
fi
pass "Found $github_count GitHub findings"

# Test 5: Total findings count
echo "=== Test 5: Total Findings ==="
total=$(jq 'length' "$RESULTS_FILE" 2>/dev/null || echo "0")
if [ "$total" -lt 3 ]; then
    fail "Expected at least 3 total findings, got $total"
fi
pass "Found $total total findings"

# Test 6: Human-readable format works
echo "=== Test 6: Human-Readable Format ==="
if ! $TITUS scan "$TESTDATA_DIR" --format=human > /dev/null 2>&1; then
    fail "Human-readable format failed"
fi
pass "Human-readable format works"

# Cleanup
rm -f "$RESULTS_FILE"

echo ""
echo "=== All integration tests passed! ==="
