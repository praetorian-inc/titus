// pkg/validator/wandb_cassette_test.go
//
// VCR replay tests for the wandb-api-key validator (LAB-4065).
// These tests skip gracefully when cassettes have not been recorded yet.
//
// To record (new wandb_v1_ format key):
//
//	SECRET_PLAINTEXT=<wandb_v1_token> RECORD=1 make record-fixtures SVC=wandb
package validator

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func Test_wandb_Valid(t *testing.T) {
	runCassetteCase(t, "wandb.yaml", "titus.wandb.1", "testdata/wandb/valid", types.StatusValid)
}

func Test_wandb_Invalid(t *testing.T) {
	runCassetteCase(t, "wandb.yaml", "titus.wandb.1", "testdata/wandb/invalid", types.StatusInvalid)
}

// Test_wandb_CanValidateBothRuleIDs asserts that the wandb validator wires both
// rule IDs (the new titus.wandb.1 and the legacy kingfisher.wandb.1). No live
// cassette is needed — CanValidate exercises only in-memory YAML parsing.
//
// Note: live cassettes for kingfisher.wandb.1 are deferred (no legacy 40-hex key
// available for recording). This test documents that the rule_id is wired even
// though its cassette recording is not yet included.
func Test_wandb_CanValidateBothRuleIDs(t *testing.T) {
	data, err := validatorsFS.ReadFile("validators/wandb.yaml")
	require.NoError(t, err, "reading embedded wandb.yaml")

	var cfg ValidatorsConfig
	require.NoError(t, yaml.Unmarshal(data, &cfg), "parsing wandb.yaml")
	require.NotEmpty(t, cfg.Validators, "wandb.yaml must define at least one validator")

	v := NewHTTPValidator(cfg.Validators[0], nil)

	assert.True(t, v.CanValidate("titus.wandb.1"),
		"validator must handle titus.wandb.1 (new wandb_v1_ format)")
	assert.True(t, v.CanValidate("kingfisher.wandb.1"),
		"validator must handle kingfisher.wandb.1 (legacy 40-hex format, cassette deferred)")
	assert.False(t, v.CanValidate("np.some.other.rule"),
		"validator must not handle unrelated rule IDs")
}
