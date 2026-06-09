// pkg/validator/confluent_cassette_test.go
//
// VCR replay tests for the Confluent Cloud API-key validator (LAB-4050).
// These tests skip gracefully when cassettes have not been recorded yet.
//
// To record:
//
//	SECRET_PLAINTEXT=<secret> CONFLUENT_CLIENT_ID=<key-id> RECORD=1 \
//	    go test ./pkg/validator/ -run Test_confluent_
//
// The cassette harness uses the default secretInsensitiveMatcher (method + host +
// path + query). Because the validation URL is FIXED (no client_id in the path),
// replay matching is trivial: any GET to /iam/v2/api-keys matches regardless of
// the Authorization header (which is stripped by the minimization hook before
// the cassette is written to disk).
package validator

import (
	"context"
	"os"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator/internal/vcrtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Package-level replay placeholder constants shared between the cassette driver
// functions and the guard test (TestClusterReplayPlaceholders_MatchExtractionRegexes).
// Keeping them here ensures the guard test exercises the exact values the drivers use.
const (
	// cassetteReplayClientID is the replay placeholder for the Confluent API key ID.
	// Must be exactly 16 chars of [A-Z0-9] so that confluentClientIDPatterns (which
	// requires [A-Z0-9]{16}) can extract it from Snippet.Before during replay.
	// vcrtest.Placeholder ("REDACTED_SECRET") fails this constraint (15 chars, lowercase, underscores).
	cassetteReplayClientID = "REDACTED0SECRET1"

	// cassettePlaceholderEndpoint is the replay placeholder for the Confluent cluster
	// bootstrap endpoint.  Must match confluentClusterEndpointPattern
	// (pkc-[a-z0-9]+\.[a-z0-9.-]+\.confluent\.cloud…) — lowercase only after pkc-.
	cassettePlaceholderEndpoint = "https://pkc-redacted0.example.confluent.cloud:443"

	// cassettePlaceholderLKC is the replay placeholder for the Confluent logical
	// cluster ID (lkc-…).  Must match confluentLKCPattern (lkc-[a-z0-9]+).
	cassettePlaceholderLKC = "lkc-redacted"
)

// Test_confluent_Valid replays the cassette for a valid Confluent API-key pair
// and asserts StatusValid. Skips when the cassette has not been recorded yet.
func Test_confluent_Valid(t *testing.T) {
	runConfluentCassetteCase(t, "testdata/confluent/valid", types.StatusValid)
}

// Test_confluent_Invalid replays the cassette for an invalid Confluent API-key
// pair and asserts StatusInvalid. Skips when the cassette has not been recorded yet.
func Test_confluent_Invalid(t *testing.T) {
	runConfluentCassetteCase(t, "testdata/confluent/invalid", types.StatusInvalid)
}

// runConfluentCassetteCase is the VCR replay driver for the Confluent Go validator.
//
// Record mode (RECORD=1):
//   - SECRET_PLAINTEXT must contain the real API secret (t.Fatal if absent).
//   - CONFLUENT_CLIENT_ID must contain the real key ID (t.Fatal if absent).
//   - Both are placed into the Match so the validator builds a real Basic auth
//     header; the vcrtest redaction hook scrubs them before writing to disk.
//
// Replay mode (default):
//   - secret = vcrtest.Placeholder; client_id = vcrtest.Placeholder.
//   - Snippet.Before = "confluent api_key=REDACTED_SECRET" so the keyword-
//     proximity regex in extractCredentials finds the Placeholder as the client_id.
//   - The cassette matcher ignores the Authorization header (stripped by the
//     minimization hook), so the fixed URL matches regardless of credentials.
func runConfluentCassetteCase(t *testing.T, cassette string, want types.ValidationStatus) {
	t.Helper()

	isRecording := os.Getenv("RECORD") == "1"
	cassetteFile := cassette + ".yaml"
	if !isRecording {
		if _, err := os.Stat(cassetteFile); os.IsNotExist(err) {
			t.Skipf(
				"cassette not recorded yet; run:\n" +
					"  SECRET_PLAINTEXT=<secret> CONFLUENT_CLIENT_ID=<key-id> RECORD=1 " +
					"go test ./pkg/validator/ -run Test_confluent_",
			)
		}
	}

	var (
		secretVal   []byte
		clientIDVal []byte
	)

	if isRecording {
		pt := os.Getenv("SECRET_PLAINTEXT")
		if pt == "" {
			t.Fatal("RECORD=1 requires SECRET_PLAINTEXT=<real-secret>")
		}
		clientID := os.Getenv("CONFLUENT_CLIENT_ID")
		if clientID == "" {
			t.Fatal("RECORD=1 requires CONFLUENT_CLIENT_ID=<real-key-id>")
		}
		secretVal = []byte(pt)
		clientIDVal = []byte(clientID)
	} else {
		// In replay mode the secret placeholder is fine as-is; the cassette
		// matcher ignores the Authorization header. The client_id placeholder
		// must be 16 chars of [A-Z0-9] so that confluentClientIDPatterns can
		// extract it from Snippet.Before — vcrtest.Placeholder ("REDACTED_SECRET")
		// is 15 chars with underscores and lowercase letters, which the regex
		// \b-bounded pattern cannot match.
		secretVal = []byte(vcrtest.Placeholder)
		clientIDVal = []byte(cassetteReplayClientID)
	}

	// Build the Match. Snippet.Before carries the client_id so that
	// extractCredentials can find it via the keyword-proximity pattern.
	snippetBefore := []byte("confluent api_key=" + string(clientIDVal))

	match := &types.Match{
		RuleID:      "kingfisher.confluent.2",
		NamedGroups: map[string][]byte{"secret": secretVal},
		Snippet:     types.Snippet{Before: snippetBefore},
	}

	// status-only validator: response body is elided (no WithResponseBody).
	client := vcrtest.Client(t, cassette)
	v := NewConfluentValidatorWithClient(client)

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err, "Validate must not return a non-nil error")
	assert.Equal(t, want, result.Status,
		"confluent cassette %s: unexpected validation status", cassette)
}

// Test_confluent_cluster_Valid replays the cassette for a valid Confluent cluster
// API-key pair and asserts StatusValid. Skips when the cassette has not been
// recorded yet.
func Test_confluent_cluster_Valid(t *testing.T) {
	runConfluentClusterCassetteCase(t, "testdata/confluent/cluster_valid", types.StatusValid)
}

// Test_confluent_cluster_Invalid replays the cassette for an invalid Confluent
// cluster API-key pair and asserts StatusInvalid. Skips when the cassette has
// not been recorded yet.
func Test_confluent_cluster_Invalid(t *testing.T) {
	runConfluentClusterCassetteCase(t, "testdata/confluent/cluster_invalid", types.StatusInvalid)
}

// runConfluentClusterCassetteCase is the VCR replay driver for the Confluent
// cluster-key validation path.
//
// Cluster URL structure: {endpoint}/kafka/v3/clusters/{lkc_id}/topics
// where endpoint = https://pkc-xxx.region.provider.confluent.cloud[:port]
// and   lkc_id   = lkc-xxxxx
//
// Record mode (RECORD=1):
//   - SECRET_PLAINTEXT: real API secret.
//   - CONFLUENT_CLIENT_ID: real key ID (16 uppercase alphanumeric chars).
//   - CONFLUENT_CLUSTER_ENDPOINT: real cluster bootstrap URL, e.g.
//     "https://pkc-419q3.us-east4.gcp.confluent.cloud:443"
//   - CONFLUENT_LKC_ID: real logical cluster ID, e.g. "lkc-nvodzyv"
//
// The vcrtest redaction hook scrubs the real secret to vcrtest.Placeholder.
// WithExtraRedactions replaces the real cluster endpoint and lkc-id with fixed
// replay-safe placeholders so no account-identifying data is committed:
//   - cluster endpoint -> "https://pkc-redacted0.example.confluent.cloud:443"
//   - lkc-id           -> "lkc-redacted"
//
// Both placeholders match the extraction regexes so replay works correctly.
//
// Replay mode (default):
//   - Snippet context contains the placeholder cluster endpoint and lkc-id.
//   - extractClusterContext extracts them; Validate builds the request URL from
//     the placeholder endpoint, which the VCR transport matches against the
//     cassette (no real TCP connection is made).
func runConfluentClusterCassetteCase(t *testing.T, cassette string, want types.ValidationStatus) {
	t.Helper()

	isRecording := os.Getenv("RECORD") == "1"
	cassetteFile := cassette + ".yaml"
	if !isRecording {
		if _, err := os.Stat(cassetteFile); os.IsNotExist(err) {
			t.Skipf(
				"cassette not recorded yet; run:\n" +
					"  SECRET_PLAINTEXT=<secret> CONFLUENT_CLIENT_ID=<key-id> " +
					"CONFLUENT_CLUSTER_ENDPOINT=<endpoint> CONFLUENT_LKC_ID=<lkc-id> " +
					"RECORD=1 go test ./pkg/validator/ -run Test_confluent_cluster_",
			)
		}
	}

	var (
		secretVal       []byte
		clientIDVal     []byte
		clusterEndpoint string
		lkcID           string
		clientOpts      []vcrtest.Option
	)

	if isRecording {
		pt := os.Getenv("SECRET_PLAINTEXT")
		if pt == "" {
			t.Fatal("RECORD=1 requires SECRET_PLAINTEXT=<real-secret>")
		}
		clientID := os.Getenv("CONFLUENT_CLIENT_ID")
		if clientID == "" {
			t.Fatal("RECORD=1 requires CONFLUENT_CLIENT_ID=<real-key-id>")
		}
		clusterEndpoint = os.Getenv("CONFLUENT_CLUSTER_ENDPOINT")
		if clusterEndpoint == "" {
			t.Fatal("RECORD=1 requires CONFLUENT_CLUSTER_ENDPOINT=<endpoint>")
		}
		lkcID = os.Getenv("CONFLUENT_LKC_ID")
		if lkcID == "" {
			t.Fatal("RECORD=1 requires CONFLUENT_LKC_ID=<lkc-id>")
		}
		secretVal = []byte(pt)
		clientIDVal = []byte(clientID)
		// Redact real cluster endpoint and lkc-id from the cassette so no
		// account-identifying data is committed to testdata/.
		clientOpts = append(clientOpts,
			vcrtest.WithExtraRedactions(
				[2]string{clusterEndpoint, cassettePlaceholderEndpoint},
				[2]string{lkcID, cassettePlaceholderLKC},
			),
		)
	} else {
		// In replay mode use the fixed placeholder credentials. The cassette
		// was written with the placeholder cluster endpoint and lkc-id, so the
		// VCR transport matches against them directly.
		secretVal = []byte(vcrtest.Placeholder)
		clientIDVal = []byte(cassetteReplayClientID)
		clusterEndpoint = cassettePlaceholderEndpoint
		lkcID = cassettePlaceholderLKC
	}

	// Build the Match with cluster context in Snippet.Before.
	// extractClusterContext reads clusterEndpoint and lkcID from Before.
	// extractCredentials reads clientIDVal from Before (keyword-proximity pattern).
	snippetBefore := []byte(
		"confluent api_key=" + string(clientIDVal) +
			" bootstrap=" + clusterEndpoint +
			" cluster=" + lkcID,
	)

	match := &types.Match{
		RuleID:      "kingfisher.confluent.2",
		NamedGroups: map[string][]byte{"secret": secretVal},
		Snippet:     types.Snippet{Before: snippetBefore},
	}

	client := vcrtest.Client(t, cassette, clientOpts...)
	v := NewConfluentValidatorWithClient(client)
	// No clusterBaseURL override: in record mode, the real endpoint is used
	// directly; in replay mode, go-vcr intercepts the request without a real
	// TCP connection, so the placeholder hostname is fine.

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err, "Validate must not return a non-nil error")
	assert.Equal(t, want, result.Status,
		"confluent cluster cassette %s: unexpected validation status", cassette)
}

// TestClusterReplayPlaceholders_MatchExtractionRegexes is a compile-time
// contract guard: it asserts that the fixed replay placeholders used by the
// cluster cassette tests are actually extractable by the production regex
// patterns in confluent.go.
//
// Without this guard a placeholder typo (e.g. uppercase in a [a-z0-9] class)
// silently breaks replay: extractClusterContext returns empty strings, Validate
// falls back to the cloud IAM path, and the cassette matcher misses — but no
// test failure surfaces until after a cassette has been recorded and the replay
// is attempted.
//
// This is the cluster-key analog of the replayClientID-vs-confluentClientIDPatterns
// check introduced for the cloud cassette tests (C-1 reviewer finding).
func TestClusterReplayPlaceholders_MatchExtractionRegexes(t *testing.T) {
	// confluentClusterEndpointPattern must match cassettePlaceholderEndpoint so that
	// extractClusterContext can extract it from the snippet during replay.
	assert.True(t,
		confluentClusterEndpointPattern.MatchString(cassettePlaceholderEndpoint),
		"cassettePlaceholderEndpoint %q must match confluentClusterEndpointPattern; "+
			"if it does not, replay falls back to the cloud path and the cassette never matches",
		cassettePlaceholderEndpoint,
	)

	// confluentLKCPattern must match cassettePlaceholderLKC for the same reason.
	assert.True(t,
		confluentLKCPattern.MatchString(cassettePlaceholderLKC),
		"cassettePlaceholderLKC %q must match confluentLKCPattern; "+
			"if it does not, extractClusterContext returns empty lkcID and replay falls back to cloud path",
		cassettePlaceholderLKC,
	)
}
