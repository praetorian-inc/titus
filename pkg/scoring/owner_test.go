package scoring

import (
	"context"
	"testing"

	"github.com/google/go-github/v57/github"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ownerSettingCondition is a test condition that always fires and sets owner info.
type ownerSettingCondition struct {
	owner *types.OwnerInfo
}

func (c *ownerSettingCondition) Evaluate(_ context.Context, m *types.Match) (bool, error) {
	m.Owner = c.owner
	return true, nil
}

func TestEngine_CopiesOwnerFromMatchToFinding(t *testing.T) {
	owner := &types.OwnerInfo{
		Service: "test",
		User:    "alice",
		Email:   "alice@example.com",
	}
	scorer := &Scorer{
		Name:    "test-owner",
		RuleIDs: []string{"test.1"},
		Modifiers: []Modifier{
			{
				Name:      "set-owner",
				Priority:  100,
				Kind:      ModifierKindDelta,
				Value:     5,
				Condition: &ownerSettingCondition{owner: owner},
			},
		},
	}

	engine := NewEngine([]*Scorer{scorer}, EngineConfig{ScopeEnabled: true, Timeout: 5e9})
	finding := &types.Finding{ID: "f1", RuleID: "test.1"}
	match := &types.Match{RuleID: "test.1"}
	rule := &types.Rule{ID: "test.1", BaseScore: 50}

	engine.Score(context.Background(), finding, []*types.Match{match}, rule)

	require.NotNil(t, finding.Owner)
	assert.Equal(t, "test", finding.Owner.Service)
	assert.Equal(t, "alice", finding.Owner.User)
	assert.Equal(t, "alice@example.com", finding.Owner.Email)
}

func TestEngine_DoesNotOverwriteExistingOwner(t *testing.T) {
	existing := &types.OwnerInfo{Service: "existing", User: "bob"}
	scorer := &Scorer{
		Name:    "test-owner",
		RuleIDs: []string{"test.1"},
		Modifiers: []Modifier{
			{
				Name:      "set-owner",
				Priority:  100,
				Kind:      ModifierKindDelta,
				Value:     5,
				Condition: &ownerSettingCondition{owner: &types.OwnerInfo{Service: "new", User: "alice"}},
			},
		},
	}

	engine := NewEngine([]*Scorer{scorer}, EngineConfig{ScopeEnabled: true, Timeout: 5e9})
	finding := &types.Finding{ID: "f1", RuleID: "test.1", Owner: existing}
	match := &types.Match{RuleID: "test.1"}
	rule := &types.Rule{ID: "test.1", BaseScore: 50}

	engine.Score(context.Background(), finding, []*types.Match{match}, rule)

	assert.Equal(t, "existing", finding.Owner.Service)
	assert.Equal(t, "bob", finding.Owner.User)
}

func TestEngine_NilOwnerWhenNoConditionSetsIt(t *testing.T) {
	scorer := &Scorer{
		Name:    "test-no-owner",
		RuleIDs: []string{"test.1"},
		Modifiers: []Modifier{
			{
				Name:      "noop",
				Priority:  100,
				Kind:      ModifierKindDelta,
				Value:     5,
				Condition: &ccFailsLuhnCondition{},
			},
		},
	}

	engine := NewEngine([]*Scorer{scorer}, EngineConfig{ScopeEnabled: true, Timeout: 5e9})
	finding := &types.Finding{ID: "f1", RuleID: "test.1"}
	match := &types.Match{RuleID: "test.1", NamedGroups: map[string][]byte{"card": []byte("4532015112830366")}}
	rule := &types.Rule{ID: "test.1", BaseScore: 50}

	engine.Score(context.Background(), finding, []*types.Match{match}, rule)

	assert.Nil(t, finding.Owner)
}

func TestSetGitHubOwner_NilUser(t *testing.T) {
	m := &types.Match{}
	setGitHubOwner(m, githubUserResult{})
	assert.Nil(t, m.Owner)
}

func TestSetGitHubOwner_DoesNotOverwrite(t *testing.T) {
	m := &types.Match{Owner: &types.OwnerInfo{Service: "existing"}}
	setGitHubOwner(m, githubUserResult{user: &github.User{}})
	assert.Equal(t, "existing", m.Owner.Service)
}

func TestSetGitLabOwner(t *testing.T) {
	m := &types.Match{}
	user := &gitlabUserResponse{
		Username: "jsmith",
		Email:    "jsmith@gitlab.com",
		Name:     "John Smith",
	}

	setGitLabOwner(m, user)

	require.NotNil(t, m.Owner)
	assert.Equal(t, "gitlab", m.Owner.Service)
	assert.Equal(t, "jsmith", m.Owner.User)
	assert.Equal(t, "jsmith@gitlab.com", m.Owner.Email)
	assert.Equal(t, "John Smith", m.Owner.DisplayName)
}

func TestSetGitLabOwner_DoesNotOverwrite(t *testing.T) {
	m := &types.Match{
		Owner: &types.OwnerInfo{Service: "existing"},
	}
	user := &gitlabUserResponse{Username: "new"}

	setGitLabOwner(m, user)

	assert.Equal(t, "existing", m.Owner.Service)
}

func TestSetGitLabOwner_NilUser(t *testing.T) {
	m := &types.Match{}
	setGitLabOwner(m, nil)
	assert.Nil(t, m.Owner)
}

func TestSetGitLabOwner_EmptyUsername(t *testing.T) {
	m := &types.Match{}
	setGitLabOwner(m, &gitlabUserResponse{})
	assert.Nil(t, m.Owner)
}
