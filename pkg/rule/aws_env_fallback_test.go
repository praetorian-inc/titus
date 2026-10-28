package rule

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAWSSecretAccessKey_EnvFallbackDefaults covers the layouts reported in
// issue #403: an AWS secret written as the literal default of an
// environment-variable fallback expression (process.env.X || '<secret>',
// os.environ.get('X', '<secret>'), ${X:-<secret>}, ...) is currently only
// caught by the generic rules and loses its AWS classification. The rule
// should accept the fallback expression between the name and the literal,
// and stay silent when there is no literal at all.
func TestAWSSecretAccessKey_EnvFallbackDefaults(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	var awsRule *types.Rule
	for _, r := range rules {
		if r.ID == "np.aws.2" {
			awsRule = r
			break
		}
	}
	require.NotNil(t, awsRule, "np.aws.2 rule should exist")

	m, err := matcher.NewPortableRegexp([]*types.Rule{awsRule}, 0, nil)
	require.NoError(t, err)

	const secret = `FakeValues99cl9bqJFVA3iFUm+yqVe08HxhXFE/`

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Fallback layouts from the issue report: these are AWS secrets,
		// not generic ones.
		{name: "js member access with ||", input: `awsSecretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || '` + secret + `',`, shouldMatch: true},
		{name: "js bracket member access with ||", input: `aws_secret_key: process.env["AWS_SECRET_ACCESS_KEY"] || "` + secret + `"`, shouldMatch: true},
		{name: "js member access with ??", input: `awsSecretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? '` + secret + `'`, shouldMatch: true},
		{name: "python os.environ.get default", input: `AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY', '` + secret + `')`, shouldMatch: true},
		{name: "python os.getenv default", input: `aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY', "` + secret + `")`, shouldMatch: true},
		{name: "shell parameter expansion default", input: `export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-` + secret + `}`, shouldMatch: true},
		{name: "shell parameter expansion default in quotes", input: `AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-` + secret + `}"`, shouldMatch: true},
		{name: "ENV bracket access with or", input: `aws_secret_key: ENV['AWS_SECRET_ACCESS_KEY'] or '` + secret + `'`, shouldMatch: true},

		// Plain-literal behavior must not change.
		{name: "plain literal still matches", input: `aws_secret_access_key=` + secret, shouldMatch: true},
		{name: "quoted literal still matches", input: `awsSecretAccessKey: "` + secret + `"`, shouldMatch: true},

		// No literal default means there is nothing to report.
		{name: "js member access without default", input: `awsSecretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,`, shouldMatch: false},
		{name: "shell expansion without default", input: `export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}`, shouldMatch: false},
		{name: "vault call instead of a literal", input: `awsSecretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || getFromVault(), id = '` + secret + `'`, shouldMatch: false},
		{name: "non-AWS name with fallback literal", input: `someOtherKey: process.env.AWS_SECRET_ACCESS_KEY || '` + secret + `'`, shouldMatch: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.input))
			require.NoError(t, err)

			if tc.shouldMatch {
				assert.NotEmpty(t, matches, "expected match for: %s", tc.input)
			} else {
				assert.Empty(t, matches, "expected no match for: %s", tc.input)
			}
		})
	}
}
