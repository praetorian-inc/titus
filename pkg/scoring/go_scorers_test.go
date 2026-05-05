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
