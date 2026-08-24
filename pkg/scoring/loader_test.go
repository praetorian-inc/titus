package scoring

import (
	"io"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadScorers is a test helper that reads YAML from an io.Reader and returns compiled Scorers.
func loadScorers(r io.Reader) ([]*Scorer, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return NewLoader().LoadScorers(data)
}

func TestLoadScorers_ValidSingle(t *testing.T) {
	loader := NewLoader()
	yamlBytes := []byte(`scorers:
  - name: aws-key-scope
    rule_ids: [np.aws.1]
    modifiers:
      - name: akia-long-term
        priority: 100
        match_group:
          name: key_id
          matches: '^AKIA'
        delta: 10
`)
	scorers, err := loader.LoadScorers(yamlBytes)
	require.NoError(t, err)
	require.Len(t, scorers, 1)

	s := scorers[0]
	assert.Equal(t, "aws-key-scope", s.Name)
	assert.Equal(t, []string{"np.aws.1"}, s.RuleIDs)
	require.Len(t, s.Modifiers, 1)
	m := s.Modifiers[0]
	assert.Equal(t, "akia-long-term", m.Name)
	assert.Equal(t, 100, m.Priority)
	assert.Equal(t, ModifierKindDelta, m.Kind)
	assert.Equal(t, 10, m.Value)
	assert.NotNil(t, m.Condition)
}

func TestLoadScorers_InvalidYAML(t *testing.T) {
	loader := NewLoader()
	_, err := loader.LoadScorers([]byte("this is not: [[[ valid"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestLoadScorers_EmptyArray(t *testing.T) {
	loader := NewLoader()
	_, err := loader.LoadScorers([]byte("scorers: []"))
	require.Error(t, err)
}

func TestLoadScorers_MalformedRegex(t *testing.T) {
	loader := NewLoader()
	yamlBytes := []byte(`scorers:
  - name: bad-regex
    rule_ids: [np.test.1]
    modifiers:
      - name: bad
        match_group: { name: x, matches: '[unclosed' }
        delta: 1
`)
	_, err := loader.LoadScorers(yamlBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "regex")
}

func TestLoadScorers_BothDeltaAndSetScore(t *testing.T) {
	loader := NewLoader()
	yamlBytes := []byte(`scorers:
  - name: ambiguous
    rule_ids: [np.test.1]
    modifiers:
      - name: bad
        match_length: { op: gt, value: 0 }
        delta: 5
        set_score: 50
`)
	_, err := loader.LoadScorers(yamlBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one")
}

func TestLoadScorers_NoCondition(t *testing.T) {
	loader := NewLoader()
	yamlBytes := []byte(`scorers:
  - name: no-cond
    rule_ids: [np.test.1]
    modifiers:
      - name: bad
        delta: 5
`)
	_, err := loader.LoadScorers(yamlBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one condition")
}

func TestLoadScorers_NoAction(t *testing.T) {
	loader := NewLoader()
	yamlBytes := []byte(`scorers:
  - name: no-action
    rule_ids: [np.test.1]
    modifiers:
      - name: bad
        match_length: { op: gt, value: 0 }
`)
	_, err := loader.LoadScorers(yamlBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delta or set_score")
}

func TestLoadScorers_SetScoreOutOfRange(t *testing.T) {
	loader := NewLoader()
	yamlBytes := []byte(`scorers:
  - name: out-of-range
    rule_ids: [np.test.1]
    modifiers:
      - name: bad
        match_length: { op: gt, value: 0 }
        set_score: 150
`)
	_, err := loader.LoadScorers(yamlBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "[0, 100]")
}

func TestLoadScorers_MissingRuleIDs(t *testing.T) {
	loader := NewLoader()
	yamlBytes := []byte(`scorers:
  - name: no-rules
    rule_ids: []
    modifiers:
      - name: x
        match_length: { op: gt, value: 0 }
        delta: 1
`)
	_, err := loader.LoadScorers(yamlBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rule_ids")
}

func TestLoadScorers_InvalidMatchLengthOp(t *testing.T) {
	loader := NewLoader()
	yamlBytes := []byte(`scorers:
  - name: bad-op
    rule_ids: [np.test.1]
    modifiers:
      - name: x
        match_length: { op: gte, value: 0 }
        delta: 1
`)
	_, err := loader.LoadScorers(yamlBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gt|lt|eq")
}

func TestLoadBuiltinScorers_AWSScorerParses(t *testing.T) {
	loader := NewLoader()
	scorers, err := loader.LoadBuiltinScorers()
	require.NoError(t, err)

	var awsScorer *Scorer
	for _, s := range scorers {
		if s.Name == "aws-key-scope" {
			awsScorer = s
			break
		}
	}
	require.NotNil(t, awsScorer, "aws-key-scope scorer not found in builtin FS")
	assert.Equal(t, []string{"np.aws.1", "np.aws.6"}, awsScorer.RuleIDs)
	require.Len(t, awsScorer.Modifiers, 3)

	wantNames := []string{"akia-long-term", "asia-temporary-session", "aida-user-identifier"}
	gotNames := make([]string, len(awsScorer.Modifiers))
	for i, m := range awsScorer.Modifiers {
		gotNames[i] = m.Name
	}
	assert.ElementsMatch(t, wantNames, gotNames)
}

func TestLoadBuiltinScorers_GitHubScorerParses(t *testing.T) {
	loader := NewLoader()
	scorers, err := loader.LoadBuiltinScorers()
	require.NoError(t, err)

	var ghScorer *Scorer
	for _, s := range scorers {
		if s.Name == "github-fine-grained-pat" {
			ghScorer = s
			break
		}
	}
	require.NotNil(t, ghScorer)
	assert.Equal(t, []string{"np.github.7"}, ghScorer.RuleIDs)
	require.Len(t, ghScorer.Modifiers, 1)
	assert.Equal(t, "fine-grained-pat-prefix", ghScorer.Modifiers[0].Name)
	assert.Equal(t, ModifierKindDelta, ghScorer.Modifiers[0].Kind)
	assert.Equal(t, -10, ghScorer.Modifiers[0].Value)
}

func TestLoadScorers_HTTPModifier_Parses(t *testing.T) {
	yaml := `
scorers:
  - name: github-scope
    rule_ids: [np.github.1]
    modifiers:
      - name: admin-org-scope
        priority: 90
        http:
          method: GET
          url: https://api.github.com/user
          auth:
            type: bearer
            secret_group: token
        fires_when:
          header_contains:
            name: x-oauth-scopes
            value: "admin:org"
        set_score: 90
`
	scorers, err := loadScorers(strings.NewReader(yaml))
	require.NoError(t, err)
	require.Len(t, scorers, 1)
	require.Len(t, scorers[0].Modifiers, 1)
	mod := scorers[0].Modifiers[0]
	assert.Equal(t, "admin-org-scope", mod.Name)
	assert.NotNil(t, mod.Condition, "HTTP modifier must have a compiled condition")
	assert.True(t, mod.IsDynamic())
}

func TestLoadScorers_FiresWhen_JSONPathEquals_Parses(t *testing.T) {
	yaml := `
scorers:
  - name: s
    rule_ids: [np.x.1]
    modifiers:
      - name: m
        http: {method: GET, url: https://example.com}
        fires_when:
          json_path_equals: {path: ".plan.name", value: enterprise}
        delta: 10
`
	scorers, err := loadScorers(strings.NewReader(yaml))
	require.NoError(t, err)
	assert.NotNil(t, scorers[0].Modifiers[0].Condition)
}

func TestLoadScorers_FiresWhen_MissingHTTPBlock_Errors(t *testing.T) {
	yaml := `
scorers:
  - name: s
    rule_ids: [np.x.1]
    modifiers:
      - name: m
        fires_when:
          status_code: 200
        delta: 10
`
	_, err := loadScorers(strings.NewReader(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fires_when")
}

func TestLoadScorers_HTTPBlock_WithoutFiresWhen_Errors(t *testing.T) {
	yaml := `
scorers:
  - name: s
    rule_ids: [np.x.1]
    modifiers:
      - name: m
        http: {method: GET, url: https://example.com}
        delta: 10
`
	_, err := loadScorers(strings.NewReader(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fires_when")
}

// TestLoadBuiltinScorers_OktaScorerAbsent verifies that the Okta scorer is NOT
// present in the builtin set. The okta.yaml was removed because all three of
// its modifiers pointed at https://placeholder.okta.com — a domain that, if
// registered by an attacker, would exfiltrate every Okta API token seen during
// a --score-scope scan. The scorer will be re-added once a safe domain
// substitution mechanism is available.
func TestLoadBuiltinScorers_OktaScorerAbsent(t *testing.T) {
	loader := NewLoader()
	scorers, err := loader.LoadBuiltinScorers()
	require.NoError(t, err)
	for _, s := range scorers {
		assert.NotEqual(t, "okta-api-key-scope", s.Name,
			"okta-api-key-scope must not be loaded: placeholder.okta.com is a security risk")
	}
}

func TestLoadBuiltinScorers_SlackScorerParses(t *testing.T) {
	loader := NewLoader()
	scorers, err := loader.LoadBuiltinScorers()
	require.NoError(t, err)
	var found bool
	for _, s := range scorers {
		if s.Name == "slack-token-scope" {
			found = true
			assert.Greater(t, len(s.Modifiers), 0)
		}
	}
	assert.True(t, found, "slack-token-scope scorer not found")
}

// Proves that the loader mirrors NewLoaderWithFS from pkg/rule/loader.go:26-30.
func TestLoadBuiltinScorers_WithCustomFS(t *testing.T) {
	mockFS := fstest.MapFS{
		"scorers/test.yaml": &fstest.MapFile{Data: []byte(`scorers:
  - name: test-scorer
    rule_ids: [np.test.1]
    modifiers:
      - name: length-check
        match_length: { op: gt, value: 10 }
        delta: 5
`)},
	}
	loader := NewLoaderWithFS(mockFS)
	scorers, err := loader.LoadBuiltinScorers()
	require.NoError(t, err)
	require.Len(t, scorers, 1)
	assert.Equal(t, "test-scorer", scorers[0].Name)
}

// ----------------------------------------------------------------
// `negative: true` on fires_when (LAB-3371)
// ----------------------------------------------------------------

// negative: is a modifier ON a leaf, not a leaf itself — it must not be counted
// by the "exactly one condition leaf" check, or every negated modifier fails to load.
func TestLoadScorers_NegativeFiresWhen_Loads(t *testing.T) {
	yamlBytes := []byte(`scorers:
  - name: sendgrid-key-scope
    rule_ids: [np.sendgrid.1]
    modifiers:
      - name: narrow-scope-set
        priority: 40
        http:
          method: GET
          url: https://api.sendgrid.com/v3/scopes
          auth:
            type: bearer
            secret_group: "token"
        fires_when:
          negative: true
          json_array_length_gte:
            path: ".scopes"
            value: 25
        delta: -20
`)
	scorers, err := NewLoader().LoadScorers(yamlBytes)
	require.NoError(t, err)
	require.Len(t, scorers, 1)
	require.Len(t, scorers[0].Modifiers, 1)

	m := scorers[0].Modifiers[0]
	assert.Equal(t, ModifierKindDelta, m.Kind)
	assert.Equal(t, -20, m.Value)
	assert.True(t, m.IsDynamic(), "http-backed modifier must still count as dynamic")

	httpCond, ok := m.Condition.(*httpCondition)
	require.True(t, ok, "expected an httpCondition")
	_, ok = httpCond.firesWhen.(*negatedLeaf)
	assert.True(t, ok, "fires_when leaf should be wrapped in negatedLeaf")
}

// negative: alone is not a condition — it still needs a leaf to negate.
func TestLoadScorers_NegativeWithoutLeaf_Errors(t *testing.T) {
	yamlBytes := []byte(`scorers:
  - name: broken
    rule_ids: [np.sendgrid.1]
    modifiers:
      - name: no-leaf
        http:
          method: GET
          url: https://api.sendgrid.com/v3/scopes
          auth:
            type: bearer
            secret_group: "token"
        fires_when:
          negative: true
        delta: -10
`)
	_, err := NewLoader().LoadScorers(yamlBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fires_when")
}

// The switch in buildFiresWhenLeafInner returns on the first field it finds, so
// extra leaves were silently discarded -- a scorer could declare two conditions
// and quietly get only one, with no indication which.
func TestLoadScorers_MultipleFiresWhenLeaves_Errors(t *testing.T) {
	yamlBytes := []byte(`scorers:
  - name: ambiguous
    rule_ids: [np.sendgrid.1]
    modifiers:
      - name: two-leaves
        http:
          method: GET
          url: https://api.sendgrid.com/v3/scopes
          auth:
            type: bearer
            secret_group: "token"
        fires_when:
          status_code: 401
          response_body_contains: '"billing.read"'
        delta: -10
`)
	_, err := NewLoader().LoadScorers(yamlBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one")
}
