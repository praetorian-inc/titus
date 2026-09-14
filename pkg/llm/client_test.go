package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient_Anthropic(t *testing.T) {
	c, err := NewClient("anthropic", "test-key", "claude-haiku-4-5-20251001")
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestNewClient_UnknownProvider(t *testing.T) {
	_, err := NewClient("openai", "test-key", "gpt-4")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported provider")
}

func TestNewClient_EmptyAPIKey(t *testing.T) {
	_, err := NewClient("anthropic", "", "claude-haiku-4-5-20251001")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API key")
}

func TestMessage_Roles(t *testing.T) {
	m := Message{Role: "user", Content: "hello"}
	assert.Equal(t, "user", m.Role)

	m2 := Message{Role: "assistant", Content: "hi"}
	assert.Equal(t, "assistant", m2.Role)
}

func TestRequest_Defaults(t *testing.T) {
	r := &Request{
		System:    "You are helpful.",
		Messages:  []Message{{Role: "user", Content: "test"}},
		MaxTokens: 256,
	}
	assert.Equal(t, 256, r.MaxTokens)
	assert.Len(t, r.Messages, 1)
}
