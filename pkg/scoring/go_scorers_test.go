package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuiltinGoScorers_ReturnsSlice(t *testing.T) {
	scorers := BuiltinGoScorers()
	assert.NotNil(t, scorers)
	// Empty now; AWSGoScorer and GitHubGoScorer added in Phase 1/2
}
