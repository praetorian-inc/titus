// pkg/validator/verifier_test.go
package validator

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/praetorian-inc/titus/pkg/llm"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLLMClient struct {
	response string
	err      error
	calls    atomic.Int32
}

func (m *mockLLMClient) Complete(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	m.calls.Add(1)
	if m.err != nil {
		return nil, m.err
	}
	return &llm.Response{
		Content: m.response,
		Usage:   llm.Usage{InputTokens: 100, OutputTokens: 50},
	}, nil
}

type staticValidator struct {
	result *types.ValidationResult
}

func (v *staticValidator) Name() string                   { return "static" }
func (v *staticValidator) CanValidate(ruleID string) bool { return ruleID == "test.1" }
func (v *staticValidator) Validate(ctx context.Context, m *types.Match) (*types.ValidationResult, error) {
	return v.result, nil
}

func TestLLMVerifier_HighConfidenceSkipsLLM(t *testing.T) {
	sv := &staticValidator{result: &types.ValidationResult{
		Status: types.StatusValid, Confidence: 1.0, Message: "confirmed",
	}}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{response: `{"status":"invalid"}`}

	v := NewLLMVerifier(engine, mock, 256, 100)
	match := &types.Match{
		RuleID:  "test.1",
		Groups:  [][]byte{[]byte("secret")},
		Snippet: types.Snippet{Matching: []byte("secret")},
	}

	result, err := v.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, int32(0), mock.calls.Load(), "LLM should not be called for high-confidence valid")
}

func TestLLMVerifier_UndeterminedWithResponseMetaCallsLLM(t *testing.T) {
	undetermined := &types.ValidationResult{
		Status: types.StatusUndetermined, Confidence: 0.5, Message: "unclear",
		ResponseMeta: &types.ResponseMeta{
			StatusCode: 200,
			Body:       []byte(`{"user":"admin"}`),
			URL:        "https://api.example.com",
		},
	}
	sv := &staticValidator{result: undetermined}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{response: `{"status":"valid","confidence":0.9,"reason":"response shows admin access"}`}

	v := NewLLMVerifier(engine, mock, 256, 100)
	match := &types.Match{
		RuleID: "test.1",
		Groups: [][]byte{[]byte("secret")},
		Snippet: types.Snippet{
			Before:   []byte("API_KEY="),
			Matching: []byte("secret"),
			After:    []byte("\n"),
		},
	}

	result, err := v.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, int32(1), mock.calls.Load())
}

func TestLLMVerifier_UndeterminedNilResponseMetaSkipsLLM(t *testing.T) {
	undetermined := &types.ValidationResult{
		Status: types.StatusUndetermined, Confidence: 0.5, Message: "no response",
	}
	sv := &staticValidator{result: undetermined}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{response: `{"status":"valid"}`}

	v := NewLLMVerifier(engine, mock, 256, 100)
	match := &types.Match{
		RuleID:  "test.1",
		Groups:  [][]byte{[]byte("secret")},
		Snippet: types.Snippet{Matching: []byte("secret")},
	}

	result, err := v.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Equal(t, int32(0), mock.calls.Load())
}

func TestLLMVerifier_NeverDowngrades(t *testing.T) {
	lowConfidence := &types.ValidationResult{
		Status: types.StatusValid, Confidence: 0.6, Message: "maybe valid",
		ResponseMeta: &types.ResponseMeta{StatusCode: 200, Body: []byte("ok")},
	}
	sv := &staticValidator{result: lowConfidence}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{response: `{"status":"invalid","confidence":0.9,"reason":"looks invalid"}`}

	v := NewLLMVerifier(engine, mock, 256, 100)
	match := &types.Match{
		RuleID:  "test.1",
		Groups:  [][]byte{[]byte("secret")},
		Snippet: types.Snippet{Matching: []byte("secret")},
	}

	result, err := v.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status, "LLM must never downgrade valid to invalid")
}

func TestLLMVerifier_LLMErrorKeepsOriginal(t *testing.T) {
	undetermined := &types.ValidationResult{
		Status: types.StatusUndetermined, Confidence: 0.5, Message: "unclear",
		ResponseMeta: &types.ResponseMeta{StatusCode: 200, Body: []byte("x")},
	}
	sv := &staticValidator{result: undetermined}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{err: fmt.Errorf("API timeout")}

	v := NewLLMVerifier(engine, mock, 256, 100)
	match := &types.Match{
		RuleID:  "test.1",
		Groups:  [][]byte{[]byte("secret")},
		Snippet: types.Snippet{Matching: []byte("secret")},
	}

	result, err := v.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Equal(t, "unclear", result.Message)
}

func TestLLMVerifier_BudgetEnforcement(t *testing.T) {
	undetermined := &types.ValidationResult{
		Status: types.StatusUndetermined, Confidence: 0.5, Message: "unclear",
		ResponseMeta: &types.ResponseMeta{StatusCode: 200, Body: []byte("x")},
	}
	sv := &staticValidator{result: undetermined}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{response: `{"status":"valid","confidence":0.9,"reason":"ok"}`}

	v := NewLLMVerifier(engine, mock, 256, 2) // budget of 2

	for i := 0; i < 5; i++ {
		match := &types.Match{
			RuleID:  "test.1",
			Groups:  [][]byte{[]byte(fmt.Sprintf("secret%d", i))},
			Snippet: types.Snippet{Matching: []byte(fmt.Sprintf("secret%d", i))},
		}
		_, _ = v.ValidateMatch(context.Background(), match)
	}

	assert.LessOrEqual(t, mock.calls.Load(), int32(2), "should not exceed budget")
}

func TestLLMVerifier_ParseError(t *testing.T) {
	undetermined := &types.ValidationResult{
		Status: types.StatusUndetermined, Confidence: 0.5, Message: "unclear",
		ResponseMeta: &types.ResponseMeta{StatusCode: 200, Body: []byte("x")},
	}
	sv := &staticValidator{result: undetermined}
	engine := NewEngine(1, sv)
	mock := &mockLLMClient{response: "this is not json at all"}

	v := NewLLMVerifier(engine, mock, 256, 100)
	match := &types.Match{
		RuleID:  "test.1",
		Groups:  [][]byte{[]byte("secret")},
		Snippet: types.Snippet{Matching: []byte("secret")},
	}

	result, err := v.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status, "parse failure keeps original")
}
