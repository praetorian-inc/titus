package scoring

import (
	"context"
	"testing"

	"github.com/praetorian-inc/titus/pkg/llm"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLLMClient struct {
	response string
	err      error
}

func (m *mockLLMClient) Complete(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &llm.Response{Content: m.response}, nil
}

func TestLLMCondition_FiresWhenMatches(t *testing.T) {
	mock := &mockLLMClient{response: "admin"}
	c := newLLMCondition(mock, "What access level? {{secret}}", "admin")

	match := &types.Match{
		NamedGroups: map[string][]byte{"secret": []byte("AKIA1234")},
		Snippet:     types.Snippet{Matching: []byte("AKIA1234")},
	}

	fired, err := c.Evaluate(context.Background(), match)
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestLLMCondition_FiresWhenNoMatch(t *testing.T) {
	mock := &mockLLMClient{response: "read_only"}
	c := newLLMCondition(mock, "What access level? {{secret}}", "admin")

	match := &types.Match{
		NamedGroups: map[string][]byte{"secret": []byte("AKIA1234")},
		Snippet:     types.Snippet{Matching: []byte("AKIA1234")},
	}

	fired, err := c.Evaluate(context.Background(), match)
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestLLMCondition_CaseInsensitive(t *testing.T) {
	mock := &mockLLMClient{response: "ADMIN access granted"}
	c := newLLMCondition(mock, "test", "admin")

	match := &types.Match{Snippet: types.Snippet{Matching: []byte("x")}}
	fired, err := c.Evaluate(context.Background(), match)
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestLLMCondition_ErrorReturnsFalse(t *testing.T) {
	mock := &mockLLMClient{err: assert.AnError}
	c := newLLMCondition(mock, "test", "admin")

	match := &types.Match{Snippet: types.Snippet{Matching: []byte("x")}}
	fired, err := c.Evaluate(context.Background(), match)
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestLLMCondition_TemplateSubstitution(t *testing.T) {
	var capturedPrompt string
	mock := &mockLLMClient{response: "admin"}
	c := newLLMCondition(mock, "Key {{secret}} from rule {{rule_name}}", "admin")
	c.capturePrompt = &capturedPrompt

	match := &types.Match{
		RuleID:      "np.aws.1",
		NamedGroups: map[string][]byte{"secret": []byte("AKIA1234")},
		Snippet:     types.Snippet{Matching: []byte("AKIA1234")},
	}
	_, _ = c.Evaluate(context.Background(), match)
	assert.Contains(t, capturedPrompt, "AKIA1234")
}

func TestLLMCondition_FiresWhenDoesNotMatchSubstring(t *testing.T) {
	mock := &mockLLMClient{response: "not_admin"}
	c := newLLMCondition(mock, "test", "admin")
	match := &types.Match{Snippet: types.Snippet{Matching: []byte("x")}}
	fired, err := c.Evaluate(context.Background(), match)
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestLLMCondition_IsNetworkCondition(t *testing.T) {
	mock := &mockLLMClient{response: "x"}
	c := newLLMCondition(mock, "test", "x")
	var nc networkCondition = c
	nc.markDynamic()
}
