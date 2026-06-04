package rule

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenericPassword5_AllCapsSnakeCaseSuppression verifies that np.generic.5
// suppresses ALL_CAPS_SNAKE_CASE constant values while preserving detection of
// real passwords in double-quoted assignments.
func TestGenericPassword5_AllCapsSnakeCaseSuppression(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	r := findRule(rules, "np.generic.5")
	require.NotNil(t, r, "np.generic.5 should exist")

	m, err := matcher.NewPortableRegexp([]*types.Rule{r}, 0, nil)
	require.NoError(t, err, "np.generic.5 should compile")

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			name:        "real password double-quoted",
			input:       `password = "super$ecret"`,
			shouldMatch: true,
		},
		{
			name:        "real password JSON",
			input:       `"password": "YOURPASSWROD"`,
			shouldMatch: true,
		},
		{
			name:        "real password assignment",
			input:       `password="super$ecret"`,
			shouldMatch: true,
		},
		{
			name:        "real password AdminPassword",
			input:       `"AdminPassword" : "thisismypassword"`,
			shouldMatch: true,
		},
		{
			name:        "real password vm_password",
			input:       `'vm_password': "Pass123!@#"`,
			shouldMatch: true,
		},
		{
			name:        "FP REISSUE_ACCOUNT_PASSWORD",
			input:       `Password = "REISSUE_ACCOUNT_PASSWORD"`,
			shouldMatch: false,
		},
		{
			name:        "FP RESET_PASSWORD_TOKEN",
			input:       `password = "RESET_PASSWORD_TOKEN"`,
			shouldMatch: false,
		},
		{
			name:        "FP ACCOUNT_PASSWORD_FIELD",
			input:       `password: "ACCOUNT_PASSWORD_FIELD"`,
			shouldMatch: false,
		},
		{
			name:        "FP IAMUserChangePassword",
			input:       `IAMUserChangePassword = "arn:aws:iam::aws:policy/IAMUserChangePassword"`,
			shouldMatch: false,
		},
		{
			name:        "single-word ALL_CAPS not suppressed",
			input:       `password = "SECRETVALUE"`,
			shouldMatch: true,
		},
		{
			// The lookahead uses (?i), so [A-Z0-9]* also matches lowercase letters.
			// "My_Secret_Value" matches [A-Z][A-Z0-9]*(_[A-Z0-9]+)+" under case-insensitive
			// matching, so the negative lookahead fires and suppresses this value.
			name:        "mixed case snake suppressed by case-insensitive lookahead",
			input:       `password = "My_Secret_Value"`,
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.input))
			require.NoError(t, err)

			if tc.shouldMatch {
				assert.NotEmpty(t, matches, "expected np.generic.5 to match: %s", tc.input)
			} else {
				assert.Empty(t, matches, "expected np.generic.5 to NOT match: %s", tc.input)
			}
		})
	}
}

// TestGenericPassword6_AllCapsSnakeCaseSuppression verifies that np.generic.6
// suppresses ALL_CAPS_SNAKE_CASE constant values while preserving detection of
// real passwords in single-quoted assignments.
func TestGenericPassword6_AllCapsSnakeCaseSuppression(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	r := findRule(rules, "np.generic.6")
	require.NotNil(t, r, "np.generic.6 should exist")

	m, err := matcher.NewPortableRegexp([]*types.Rule{r}, 0, nil)
	require.NoError(t, err, "np.generic.6 should compile")

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			name:        "real password single-quoted",
			input:       `:password => '4ian1234',`,
			shouldMatch: true,
		},
		{
			name:        "real password login",
			input:       `common.then_log_in({username: 'geronimo', password: '52VeZqtHDCdAr5yM'});`,
			shouldMatch: true,
		},
		{
			name:        "real password host config",
			input:       `password => 'thisismypassword',`,
			shouldMatch: true,
		},
		{
			name:        "FP REISSUE_ACCOUNT_PASSWORD",
			input:       `password = 'REISSUE_ACCOUNT_PASSWORD'`,
			shouldMatch: false,
		},
		{
			name:        "single-word ALL_CAPS not suppressed",
			input:       `password = 'SECRETVALUE'`,
			shouldMatch: true,
		},
		{
			// Same as np.generic.5: the lookahead uses (?i), so mixed-case snake values
			// like "Reset_Token_Value" also match the suppression pattern.
			name:        "mixed case snake suppressed by case-insensitive lookahead",
			input:       `password = 'Reset_Token_Value'`,
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.input))
			require.NoError(t, err)

			if tc.shouldMatch {
				assert.NotEmpty(t, matches, "expected np.generic.6 to match: %s", tc.input)
			} else {
				assert.Empty(t, matches, "expected np.generic.6 to NOT match: %s", tc.input)
			}
		})
	}
}

// TestURIRule_MailtoSuppression verifies that kingfisher.uri.1 continues to
// detect real credential URIs and suppresses known FP patterns via
// ignore_if_contains. The "mailto:" entry in ignore_if_contains provides
// defense-in-depth for any edge case where "mailto:" appears inside a matched
// HTTP URI.
//
// The ignore_if_contains filter is applied by the filtering matcher (matcher.New),
// not by the raw regex engine, so this test uses matcher.New to exercise the full
// post-filter pipeline.
func TestURIRule_MailtoSuppression(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	r := findRule(rules, "kingfisher.uri.1")
	require.NotNil(t, r, "kingfisher.uri.1 should exist")

	// Use matcher.New so the ignore_if_contains post-filter is applied.
	m, err := matcher.New(matcher.Config{Rules: []*types.Rule{r}})
	require.NoError(t, err, "kingfisher.uri.1 should compile")
	defer m.Close()

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			// High-entropy credential URI that passes ignore_if_contains and min_entropy.
			name:        "valid credential URI",
			input:       `https://admin:s3cret@db.example.com/path`,
			shouldMatch: true,
		},
		{
			// Suppressed by ignore_if_contains: "xxxx" is in the filter list.
			name:        "existing negative xxxx",
			input:       `https://user:xxxx@example.com`,
			shouldMatch: false,
		},
		{
			// Suppressed by ignore_if_contains: "username:" appears in the URI.
			name:        "existing negative username:",
			input:       `https://username:password@example.com`,
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.input))
			require.NoError(t, err)

			if tc.shouldMatch {
				assert.NotEmpty(t, matches, "expected kingfisher.uri.1 to match: %s", tc.input)
			} else {
				assert.Empty(t, matches, "expected kingfisher.uri.1 to NOT match: %s", tc.input)
			}
		})
	}
}

// TestModifiedRules_YAMLExamplesMatch verifies that all examples and
// negative_examples declared in the YAML for the three modified rules pass
// through the real matcher pipeline without regression.
func TestModifiedRules_YAMLExamplesMatch(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	for _, id := range []string{"np.generic.5", "np.generic.6", "kingfisher.uri.1"} {
		id := id
		r := findRule(rules, id)
		require.NotNil(t, r, "%s should exist", id)
		require.NotEmpty(t, r.Examples, "%s should have examples", id)

		m, err := matcher.NewPortableRegexp([]*types.Rule{r}, 0, nil)
		require.NoError(t, err, "%s should compile", id)

		for _, ex := range r.Examples {
			ex := ex
			t.Run(id+"/positive/"+ex, func(t *testing.T) {
				matches, err := m.Match([]byte(ex))
				require.NoError(t, err)
				assert.NotEmpty(t, matches, "expected %s to match positive example: %q", id, ex)
			})
		}

		for _, ex := range r.NegativeExamples {
			ex := ex
			t.Run(id+"/negative/"+ex, func(t *testing.T) {
				matches, err := m.Match([]byte(ex))
				require.NoError(t, err)
				assert.Empty(t, matches, "expected %s to NOT match negative example: %q", id, ex)
			})
		}
	}
}
