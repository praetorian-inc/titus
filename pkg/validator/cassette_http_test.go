// pkg/validator/cassette_http_test.go
//
// Generic per-service VCR replay driver. Reused by every Phase 1 cassette test
// (huggingface_cassette_test.go, github_cassette_test.go, ...). Each service
// test file calls runCassetteCase with its own yaml file, rule ID, cassette
// path, and expected status.
package validator

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator/internal/vcrtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// runCassetteCase is a generic replay driver for HTTP validator cassette tests.
//
// It loads the given YAML validator definition from the embedded FS, selects the
// validator that can handle ruleID, creates an *http.Client backed by the named
// cassette (via vcrtest), and asserts that Validate returns the expected status.
//
// cassette is a path relative to the test file, WITHOUT the ".yaml" extension
// (go-vcr appends ".yaml" automatically). Example: "testdata/huggingface/valid".
//
// The Match fed into Validate is pre-populated with all of the common named
// capture group names ("secret", "token", "key") set to vcrtest.Placeholder,
// plus a single positional group equal to vcrtest.Placeholder. This covers
// validators that reference any of those group names or use positional index "1".
//
// Skip behaviour: if not in RECORD mode and the cassette file (<cassette>.yaml)
// does not exist, the test is skipped with a message showing the exact
// one-command record invocation.
func runCassetteCase(t *testing.T, yamlFile, ruleID, cassette string, want types.ValidationStatus) {
	t.Helper()

	// In replay mode, skip gracefully when the cassette has not been recorded yet.
	isRecording := os.Getenv("RECORD") == "1"
	cassetteFile := cassette + ".yaml"
	if !isRecording {
		if _, err := os.Stat(cassetteFile); os.IsNotExist(err) {
			t.Skipf(
				"cassette not recorded yet; run:\n  SECRET_PLAINTEXT=<tok> RECORD=1 make record-fixtures SVC=%s",
				serviceNameFromCassette(cassette),
			)
		}
	}

	// Load YAML from embedded FS.
	data, err := validatorsFS.ReadFile("validators/" + yamlFile)
	require.NoError(t, err, "reading embedded YAML %s", yamlFile)

	var cfg ValidatorsConfig
	require.NoError(t, yaml.Unmarshal(data, &cfg), "parsing %s", yamlFile)

	// Find the validator that handles this rule ID.
	var def *ValidatorDef
	for i := range cfg.Validators {
		v := NewHTTPValidator(cfg.Validators[i], nil)
		if v.CanValidate(ruleID) {
			def = &cfg.Validators[i]
			break
		}
	}
	require.NotNil(t, def, "no validator for rule %s found in %s", ruleID, yamlFile)

	// Build the VCR-backed HTTP client.
	client := vcrtest.Client(t, cassette)

	// Construct the match. Populate the three conventional named group names plus
	// a positional group so the validator works regardless of how secret_group is
	// configured ("secret", "token", "key", or "1").
	ph := []byte(vcrtest.Placeholder)
	match := &types.Match{
		RuleID: ruleID,
		Groups: [][]byte{ph},
		NamedGroups: map[string][]byte{
			"secret": ph,
			"token":  ph,
			"key":    ph,
		},
	}

	v := NewHTTPValidator(*def, client)
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err, "Validate returned unexpected error")
	assert.Equal(t, want, result.Status,
		fmt.Sprintf("validator %s: unexpected status for cassette %s", def.Name, cassette))
}

// serviceNameFromCassette extracts the service directory component from a
// cassette path like "testdata/huggingface/valid" -> "huggingface".
func serviceNameFromCassette(cassette string) string {
	// "testdata/huggingface/valid" -> ["testdata", "huggingface", "valid"]
	for i := len(cassette) - 1; i >= 0; i-- {
		if cassette[i] == '/' {
			// Strip the final segment and look for the next slash.
			prefix := cassette[:i]
			for j := len(prefix) - 1; j >= 0; j-- {
				if prefix[j] == '/' {
					return prefix[j+1:]
				}
			}
			return prefix
		}
	}
	return cassette
}
