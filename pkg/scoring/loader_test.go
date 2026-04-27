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

func TestLoadBuiltinScorers_GitHubScorerHasDynamicModifiers(t *testing.T) {
	loader := NewLoader()
	scorers, err := loader.LoadBuiltinScorers()
	require.NoError(t, err)
	var githubScorer *Scorer
	for _, s := range scorers {
		if s.Name == "github-pat-scope" {
			githubScorer = s
			break
		}
	}
	require.NotNil(t, githubScorer, "github-pat-scope scorer not found")

	dynamicCount := 0
	for _, m := range githubScorer.Modifiers {
		if m.IsDynamic() {
			dynamicCount++
		}
	}
	assert.Greater(t, dynamicCount, 0, "github scorer should have at least 1 dynamic modifier")
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
