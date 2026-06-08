package rule

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTMLPasswordInput_Detection verifies the np.html.1 rule detects
// pre-populated credentials in HTML <input type="password"> elements
// and suppresses known false-positive patterns.
func TestHTMLPasswordInput_Detection(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	r := findRule(rules, "np.html.1")
	require.NotNil(t, r, "np.html.1 should exist")

	m, err := matcher.New(matcher.Config{Rules: []*types.Rule{r}})
	require.NoError(t, err, "np.html.1 should compile")
	defer m.Close()

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Positive examples
		{
			name:        "password with special chars",
			input:       `<input type="password" value="Jasper@Admin2024!" name="jasper_password" />`,
			shouldMatch: true,
		},
		{
			name:        "smtp_pass mixed quoting",
			input:       "<input name=\"smtp_pass\" type='password' value=\"relay_secret_123\">",
			shouldMatch: true,
		},
		{
			name:        "AWS access key in password field",
			input:       `<input type="password" value="AKIA6GTN2FZMZI2WBMDJ" class="form-control">`,
			shouldMatch: true,
		},
		{
			name:        "value before type attribute",
			input:       `<input class="form-control" value="jasper_secret_XYZ!" type="password" name="jasper_password" />`,
			shouldMatch: true,
		},
		{
			name:        "uppercase tag and attributes",
			input:       `<INPUT TYPE="PASSWORD" VALUE="Admin@1234" NAME="adminPass">`,
			shouldMatch: true,
		},
		{
			name:        "unquoted type attribute",
			input:       `<input type=password value="UnquotedType!2024" name="pass" />`,
			shouldMatch: true,
		},
		// Negative examples
		{
			name:        "empty value",
			input:       `<input type="password" value="" name="password" />`,
			shouldMatch: false,
		},
		{
			name:        "no value attribute",
			input:       `<input type="password" name="password" />`,
			shouldMatch: false,
		},
		{
			name:        "asterisk mask",
			input:       `<input type="password" value="********" />`,
			shouldMatch: false,
		},
		{
			name:        "bullet mask with trailing space",
			input:       "<input type=\"password\" value=\"•••••••• \" />",
			shouldMatch: false,
		},
		{
			name:        "asterisk mask with trailing space",
			input:       `<input type="password" value="*** " />`,
			shouldMatch: false,
		},
		{
			name:        "too short value",
			input:       `<input type="password" value="abc" />`,
			shouldMatch: false,
		},
		{
			name:        "wrong input type",
			input:       `<input type="text" value="not_a_password_field" />`,
			shouldMatch: false,
		},
		{
			name:        "placeholder word password",
			input:       `<input type="password" value="password" />`,
			shouldMatch: false,
		},
		{
			name:        "placeholder word placeholder",
			input:       `<input type="password" value="placeholder" />`,
			shouldMatch: false,
		},
		{
			name:        "placeholder word changeme",
			input:       `<input type="password" value="changeme" />`,
			shouldMatch: false,
		},
		{
			name:        "template tag mustache",
			input:       `<input type="password" value="{{this.value}}" />`,
			shouldMatch: false,
		},
		{
			name:        "spaced template tag",
			input:       `<input type="password" value="{{ this.value }}" />`,
			shouldMatch: false,
		},
		{
			name:        "template expression dollar brace",
			input:       `<input type="password" value="${config.password}" />`,
			shouldMatch: false,
		},
		{
			name:        "ERB/JSP template",
			input:       `<input type="password" value="<%= dbPassword %>" />`,
			shouldMatch: false,
		},
		{
			name:        "PHP template",
			input:       `<input type="password" value="<?= $password ?>" />`,
			shouldMatch: false,
		},
		{
			name:        "Jinja template",
			input:       `<input type="password" value="{% block password %}{% endblock %}" />`,
			shouldMatch: false,
		},
		{
			name:        "data-value not value attribute",
			input:       `<input type="password" data-value="not_the_value_attr" />`,
			shouldMatch: false,
		},
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
