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
		secretVal = []byte(vcrtest.Placeholder)
		clientIDVal = []byte(vcrtest.Placeholder)
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
