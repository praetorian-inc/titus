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
$TITUS scan "$TESTDATA_DIR" --format=json > "$RESULTS_FILE" 2>/dev/null

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

# Test 7: Rules include filter
echo "=== Test 7: Rules Include Filter ==="
INCLUDE_FILE="/tmp/titus-include-results.json"
INCLUDE_DB="/tmp/titus-include.db"
rm -f "$INCLUDE_DB"
$TITUS scan "$TESTDATA_DIR" --rules-include "np.aws.*" --output="$INCLUDE_DB" --format=json > "$INCLUDE_FILE" 2>/dev/null

# Verify only AWS findings are returned
aws_include_count=$(jq '[.[] | select(.RuleID | startswith("np.aws"))] | length' "$INCLUDE_FILE" 2>/dev/null || echo "0")
total_include=$(jq 'length' "$INCLUDE_FILE" 2>/dev/null || echo "0")

if [ "$aws_include_count" -lt 1 ]; then
    fail "Expected at least 1 AWS finding with --rules-include, got $aws_include_count"
fi

if [ "$aws_include_count" -ne "$total_include" ]; then
    fail "Expected only AWS findings with --rules-include, but got $aws_include_count AWS out of $total_include total"
fi

# Verify no GitHub findings
github_include_count=$(jq '[.[] | select(.RuleID | startswith("np.github"))] | length' "$INCLUDE_FILE" 2>/dev/null || echo "0")
if [ "$github_include_count" -ne 0 ]; then
    fail "Expected no GitHub findings with --rules-include 'np.aws.*', but got $github_include_count"
fi

pass "Rules include filter works - found only $aws_include_count AWS findings"
rm -f "$INCLUDE_FILE" "$INCLUDE_DB"

# Test 8: Rules exclude filter
echo "=== Test 8: Rules Exclude Filter ==="
EXCLUDE_FILE="/tmp/titus-exclude-results.json"
EXCLUDE_DB="/tmp/titus-exclude.db"
rm -f "$EXCLUDE_DB"
$TITUS scan "$TESTDATA_DIR" --rules-exclude "np.aws.*" --output="$EXCLUDE_DB" --format=json > "$EXCLUDE_FILE" 2>/dev/null

# Verify AWS findings are excluded
aws_exclude_count=$(jq '[.[] | select(.RuleID | startswith("np.aws"))] | length' "$EXCLUDE_FILE" 2>/dev/null || echo "0")
if [ "$aws_exclude_count" -ne 0 ]; then
    fail "Expected no AWS findings with --rules-exclude, but got $aws_exclude_count"
fi

# Verify GitHub findings are still present
github_exclude_count=$(jq '[.[] | select(.RuleID | startswith("np.github"))] | length' "$EXCLUDE_FILE" 2>/dev/null || echo "0")
if [ "$github_exclude_count" -lt 1 ]; then
    fail "Expected at least 1 GitHub finding with --rules-exclude 'np.aws.*', got $github_exclude_count"
fi

pass "Rules exclude filter works - excluded AWS, found $github_exclude_count GitHub findings"
rm -f "$EXCLUDE_FILE" "$EXCLUDE_DB"

# Test 9: Rules list include filter
echo "=== Test 9: Rules List Include Filter ==="
RULES_LIST_FILE="/tmp/titus-rules-list.json"
$TITUS rules list --include "np.aws.*" --format=json > "$RULES_LIST_FILE" 2>/dev/null

# Verify output only contains AWS rules
total_rules=$(jq 'length' "$RULES_LIST_FILE" 2>/dev/null || echo "0")
if [ "$total_rules" -lt 1 ]; then
    fail "Expected at least 1 rule with --include 'np.aws.*', got $total_rules"
fi

# Check that all rules match the pattern
non_aws_rules=$(jq '[.[] | select(.ID | startswith("np.aws") | not)] | length' "$RULES_LIST_FILE" 2>/dev/null || echo "0")
if [ "$non_aws_rules" -ne 0 ]; then
    fail "Expected only AWS rules with --include 'np.aws.*', but got $non_aws_rules non-AWS rules"
fi

pass "Rules list include filter works - found $total_rules AWS rules"
rm -f "$RULES_LIST_FILE"

# Test 10: Combined include and exclude filters
echo "=== Test 10: Combined Include/Exclude Filters ==="
COMBINED_FILE="/tmp/titus-combined-results.json"
COMBINED_DB="/tmp/titus-combined.db"
rm -f "$COMBINED_DB"
$TITUS scan "$TESTDATA_DIR" --rules-include "np\\..*" --rules-exclude ".*token.*" --output="$COMBINED_DB" --format=json > "$COMBINED_FILE" 2>/dev/null

# Verify results match the combined criteria
total_combined=$(jq 'length' "$COMBINED_FILE" 2>/dev/null || echo "0")
if [ "$total_combined" -lt 1 ]; then
    fail "Expected at least 1 finding with combined filters, got $total_combined"
fi

# Check that no findings contain "token" in the RuleID
token_findings=$(jq '[.[] | select(.RuleID | contains("token"))] | length' "$COMBINED_FILE" 2>/dev/null || echo "0")
if [ "$token_findings" -ne 0 ]; then
    fail "Expected no token findings with --rules-exclude '.*token.*', but got $token_findings"
fi

# Verify all findings start with "np."
all_np=$(jq '[.[] | select(.RuleID | startswith("np."))] | length' "$COMBINED_FILE" 2>/dev/null || echo "0")
if [ "$all_np" -ne "$total_combined" ]; then
    fail "Expected all findings to start with 'np.' with --rules-include 'np\\..*', but got $all_np out of $total_combined"
fi

pass "Combined include/exclude filters work - found $total_combined findings"
rm -f "$COMBINED_FILE" "$COMBINED_DB"

# Test 11: Context lines extraction
echo "=== Test 11: Context Lines Extraction ==="

# Test with default context (3 lines)
CONTEXT_FILE="/tmp/titus-context-results.json"
CONTEXT_DB="/tmp/titus-context.db"
rm -f "$CONTEXT_DB"
$TITUS scan "$TESTDATA_DIR" --context-lines=3 --output="$CONTEXT_DB" --format=json > "$CONTEXT_FILE" 2>/dev/null

# Verify output has findings
total_context=$(jq 'length' "$CONTEXT_FILE" 2>/dev/null || echo "0")
if [ "$total_context" -lt 1 ]; then
    fail "Expected at least 1 finding with --context-lines=3, got $total_context"
fi

# Verify at least one finding has non-empty Before or After context
# Note: Some matches might be at file boundaries with no before/after, so we just check for presence
findings_with_context=$(jq '[.[] | select(.Snippet.Before != "" or .Snippet.After != "")] | length' "$CONTEXT_FILE" 2>/dev/null || echo "0")
if [ "$findings_with_context" -lt 1 ]; then
    fail "Expected at least 1 finding with non-empty context, got $findings_with_context"
fi
pass "Context extraction with --context-lines=3 works - $findings_with_context findings have context"

# Test with no context (0 lines)
NO_CONTEXT_FILE="/tmp/titus-no-context-results.json"
NO_CONTEXT_DB="/tmp/titus-no-context.db"
rm -f "$NO_CONTEXT_DB"
$TITUS scan "$TESTDATA_DIR" --context-lines=0 --output="$NO_CONTEXT_DB" --format=json > "$NO_CONTEXT_FILE" 2>/dev/null

# Verify output has findings
total_no_context=$(jq 'length' "$NO_CONTEXT_FILE" 2>/dev/null || echo "0")
if [ "$total_no_context" -lt 1 ]; then
    fail "Expected at least 1 finding with --context-lines=0, got $total_no_context"
fi

# Verify all findings have empty or null Before and After fields
findings_with_no_context=$(jq '[.[] | select((.Snippet.Before == "" or .Snippet.Before == null) and (.Snippet.After == "" or .Snippet.After == null))] | length' "$NO_CONTEXT_FILE" 2>/dev/null || echo "0")
if [ "$findings_with_no_context" -ne "$total_no_context" ]; then
    fail "Expected all findings to have empty context with --context-lines=0, but only $findings_with_no_context out of $total_no_context have empty context"
fi
pass "Context extraction with --context-lines=0 works - all $total_no_context findings have empty context"

rm -f "$CONTEXT_FILE" "$CONTEXT_DB" "$NO_CONTEXT_FILE" "$NO_CONTEXT_DB"

# Test 12: Report Command
echo "=== Test 12: Report Command ==="
REPORT_DB="/tmp/titus-report.db"
rm -f "$REPORT_DB"

# Run scan to create datastore
$TITUS scan "$TESTDATA_DIR" --output="$REPORT_DB" --format=json > /dev/null 2>&1

# Verify database was created
if [ ! -f "$REPORT_DB" ]; then
    fail "Scan did not create database at $REPORT_DB"
fi

# Run report command with human format
REPORT_OUTPUT="/tmp/titus-report-human.txt"
$TITUS report --datastore="$REPORT_DB" --format=human > "$REPORT_OUTPUT" 2>&1

# Verify report contains expected sections
if ! grep -q "=== Titus Report ===" "$REPORT_OUTPUT"; then
    fail "Report missing header"
fi

if ! grep -q "Total findings:" "$REPORT_OUTPUT"; then
    fail "Report missing findings count"
fi

if ! grep -q "By Rule:" "$REPORT_OUTPUT"; then
    fail "Report missing by-rule breakdown"
fi

# Verify report shows findings count > 0 (we scanned test data)
total_findings=$(grep "Total findings:" "$REPORT_OUTPUT" | grep -oE '[0-9]+')
if [ "$total_findings" -lt 1 ]; then
    fail "Expected at least 1 finding in report, got $total_findings"
fi

pass "Report command works - found $total_findings findings"

# Test report with JSON format
REPORT_JSON="/tmp/titus-report.json"
$TITUS report --datastore="$REPORT_DB" --format=json > "$REPORT_JSON" 2>&1

# Verify JSON output is valid
if ! jq empty "$REPORT_JSON" 2>/dev/null; then
    fail "Report JSON output is not valid"
fi

# Verify JSON contains findings
json_findings=$(jq 'length' "$REPORT_JSON" 2>/dev/null || echo "0")
if [ "$json_findings" -lt 1 ]; then
    fail "Expected at least 1 finding in JSON report, got $json_findings"
fi

pass "Report JSON format works - found $json_findings findings"

rm -f "$REPORT_DB" "$REPORT_OUTPUT" "$REPORT_JSON"

# Test 13: Incremental Scanning
echo "=== Test 13: Incremental Scanning ==="
INCREMENTAL_DB="/tmp/titus-incremental.db"
rm -f "$INCREMENTAL_DB"

# First scan
$TITUS scan "$TESTDATA_DIR" --output="$INCREMENTAL_DB" --format=human > /tmp/titus-inc1.txt 2>&1

# Second scan with incremental - should skip all blobs
$TITUS scan "$TESTDATA_DIR" --output="$INCREMENTAL_DB" --format=human --incremental > /tmp/titus-inc2.txt 2>&1

# Verify second scan mentions skipped blobs
if ! grep -q "skipped" /tmp/titus-inc2.txt; then
    fail "Expected incremental scan to report skipped blobs"
fi

pass "Incremental scanning works"
rm -f "$INCREMENTAL_DB" /tmp/titus-inc1.txt /tmp/titus-inc2.txt

# Cleanup
rm -f "$RESULTS_FILE"

echo ""
echo "=== All integration tests passed! ==="
