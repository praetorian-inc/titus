package scoring

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
