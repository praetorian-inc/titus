package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuiltinGoScorers_ReturnsSlice(t *testing.T) {
	scorers := BuiltinGoScorers()
	assert.NotNil(t, scorers)
}

func TestBuiltinGoScorers_IncludesAWS(t *testing.T) {
	scorers := BuiltinGoScorers()
	var found bool
	for _, s := range scorers {
		if s.Name == "aws-iam-scope" {
			found = true
			assert.Contains(t, s.RuleIDs, "np.aws.6", "AWS scorer must target np.aws.6")
			assert.Greater(t, len(s.Modifiers), 0, "AWS scorer must have modifiers")
		}
	}
	assert.True(t, found, "BuiltinGoScorers must include aws-iam-scope scorer")
}

func TestBuiltinGoScorers_IncludesGitHub(t *testing.T) {
	scorers := BuiltinGoScorers()
	var found bool
	for _, s := range scorers {
		if s.Name == "github-fine-grained-scope" {
			found = true
			assert.Contains(t, s.RuleIDs, "np.github.7")
		}
	}
	assert.True(t, found)
}

func TestAllBuiltinScorers_IncludesGoAndYAML(t *testing.T) {
	scorers, err := AllBuiltinScorers()
	if err != nil {
		t.Fatalf("AllBuiltinScorers: %v", err)
	}
	goIdx, yamlIdx := -1, -1
	for i, s := range scorers {
		switch s.Name {
		case "github-classic-pat-scope": // Go scorer
			goIdx = i
		case "github-fine-grained-pat": // YAML scorer
			yamlIdx = i
		}
	}
	if goIdx == -1 {
		t.Error("AllBuiltinScorers missing Go scorer github-classic-pat-scope")
	}
	if yamlIdx == -1 {
		t.Error("AllBuiltinScorers missing YAML scorer github-fine-grained-pat")
	}
	if goIdx != -1 && yamlIdx != -1 && goIdx > yamlIdx {
		t.Errorf("Go scorers must precede YAML for first-match-wins: goIdx=%d yamlIdx=%d", goIdx, yamlIdx)
	}
}

func TestBuiltinGoScorers_IncludesGitLab(t *testing.T) {
	scorers := BuiltinGoScorers()
	var found bool
	for _, s := range scorers {
		if s.Name == "gitlab-pat-scope" {
			found = true
			assert.Contains(t, s.RuleIDs, "np.gitlab.2")
			assert.Contains(t, s.RuleIDs, "np.gitlab.4")
		}
	}
	assert.True(t, found, "BuiltinGoScorers must include gitlab-pat-scope scorer")
}
