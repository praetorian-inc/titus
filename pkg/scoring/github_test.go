package scoring

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestExtractGitHubToken_Present(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"token": []byte("github_pat_11AAAAAAA"),
		},
	}
	tok, ok := extractGitHubToken(m)
	assert.True(t, ok)
	assert.Equal(t, "github_pat_11AAAAAAA", tok)
}

func TestExtractGitHubToken_Missing(t *testing.T) {
	m := &types.Match{NamedGroups: map[string][]byte{}}
	_, ok := extractGitHubToken(m)
	assert.False(t, ok)
}

func TestGitHubFineGrainedPermCondition_IsDynamic(t *testing.T) {
	cond := &githubFineGrainedPermCondition{requiredPerm: "write"}
	var mod Modifier
	mod.Condition = cond
	assert.True(t, mod.IsDynamic())
}
