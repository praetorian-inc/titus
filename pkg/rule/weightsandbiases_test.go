package rule

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTitusWandb1_Detection verifies the titus.wandb.1 rule correctly
// detects the new wandb_v1_ key format and rejects unrelated inputs.
//
// This is the first titus.* rule; it covers the self-contained wandb_v1_ prefix
// format which does not require keyword context (unlike kingfisher.wandb.1).
func TestTitusWandb1_Detection(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	var wandbRule *types.Rule
	for _, r := range rules {
		if r.ID == "titus.wandb.1" {
			wandbRule = r
			break
		}
	}
	require.NotNil(t, wandbRule, "titus.wandb.1 rule must exist in built-in rules")

	m, err := matcher.NewPortableRegexp([]*types.Rule{wandbRule}, 0, nil)
	require.NoError(t, err)

	// fakeToken is a clearly synthetic wandb_v1_ token: 77 [A-Za-z0-9_] chars after the prefix.
	const fakeToken = "wandb_v1_ABC123def456GHI789jkl012MNO345pqr678STU901vwx234YZa567bcd890ef"

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
		// expectedGroup1, when non-empty, asserts that the first capture group
		// equals this value.  Only checked when shouldMatch is true.
		expectedGroup1 string
	}{
		// --- Positive cases ---
		{
			name:           "bare token with no surrounding keyword context",
			input:          fakeToken,
			shouldMatch:    true,
			expectedGroup1: fakeToken,
		},
		{
			name:           "token embedded in export statement",
			input:          "export WANDB_API_KEY=" + fakeToken,
			shouldMatch:    true,
			expectedGroup1: fakeToken,
		},
		{
			name:           "token in quoted config value",
			input:          `api_key="` + fakeToken + `"`,
			shouldMatch:    true,
			expectedGroup1: fakeToken,
		},
		{
			name:           "token in YAML-style assignment",
			input:          "wandb_api_key: " + fakeToken,
			shouldMatch:    true,
			expectedGroup1: fakeToken,
		},
		{
			name:           "token in wandb login command",
			input:          "wandb login " + fakeToken,
			shouldMatch:    true,
			expectedGroup1: fakeToken,
		},

		// --- Negative cases ---
		{
			name:        "legacy 40-hex key without keyword context does not match",
			input:       "872ab943740b34157041da2529fb160d89632710",
			shouldMatch: false,
		},
		{
			name:        "wandb_v1_ prefix with too-short body (38 chars, below 40 minimum) does not match",
			input:       "wandb_v1_ABC123def456GHI789jkl012MNO345pqr678ST",
			shouldMatch: false,
		},
		{
			name:        "random UUID-style token without wandb_v1_ prefix does not match",
			input:       "550e8400-e29b-41d4-a716-446655440000",
			shouldMatch: false,
		},
		{
			name:        "generic non-wandb_v1_ string does not match",
			input:       "generic-non-wandb-token-1234567890-abcdef",
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.input))
			require.NoError(t, err)

			if tc.shouldMatch {
				require.NotEmpty(t, matches, "expected titus.wandb.1 to match: %s", tc.input)
				if tc.expectedGroup1 != "" {
					require.NotEmpty(t, matches[0].Groups,
						"expected capture group 1 to be present in match")
					assert.Equal(t, tc.expectedGroup1, string(matches[0].Groups[0]),
						"capture group 1 must equal the full wandb_v1_ token")
				}
			} else {
				assert.Empty(t, matches, "expected no match from titus.wandb.1 for: %s", tc.input)
			}
		})
	}
}

// TestTitusWandb1_NoKeywordContextRequired verifies that the titus.wandb.1
// rule fires on a bare wandb_v1_ token with no surrounding "wandb" keyword.
// This distinguishes it from kingfisher.wandb.1 which requires keyword context.
func TestTitusWandb1_NoKeywordContextRequired(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	var wandbRule *types.Rule
	for _, r := range rules {
		if r.ID == "titus.wandb.1" {
			wandbRule = r
			break
		}
	}
	require.NotNil(t, wandbRule, "titus.wandb.1 rule must exist")

	m, err := matcher.NewPortableRegexp([]*types.Rule{wandbRule}, 0, nil)
	require.NoError(t, err)

	// Input contains ONLY the token — no "wandb" keyword anywhere in context.
	// kingfisher.wandb.1 would require a keyword; titus.wandb.1 must not.
	bareToken := "wandb_v1_XYZ987wvu654TSR321qpo098NML765kji432HGF109edc876BAZ543yxw210vut"
	neutralContext := "SECRET_KEY=" + bareToken + " DATABASE_URL=postgres://localhost/db"

	matches, err := m.Match([]byte(neutralContext))
	require.NoError(t, err)
	assert.NotEmpty(t, matches,
		"titus.wandb.1 must fire on a wandb_v1_ token without a 'wandb' keyword in context")
}

// TestTitusWandb1_RuleMetadata verifies that the titus.wandb.1 rule is
// properly loaded with the expected metadata fields.
func TestTitusWandb1_RuleMetadata(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	var wandbRule *types.Rule
	for _, r := range rules {
		if r.ID == "titus.wandb.1" {
			wandbRule = r
			break
		}
	}
	require.NotNil(t, wandbRule, "titus.wandb.1 rule must exist")

	assert.Equal(t, "titus.wandb.1", wandbRule.ID)
	assert.Equal(t, "Weights and Biases API Key (v1)", wandbRule.Name)
	assert.NotEmpty(t, wandbRule.Pattern, "rule must have a non-empty pattern")
	assert.NotEmpty(t, wandbRule.Examples, "rule must have at least one example")
}
