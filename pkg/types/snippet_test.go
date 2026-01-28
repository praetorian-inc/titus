package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSnippet(t *testing.T) {
	snippet := Snippet{
		Before:   []byte("context before "),
		Matching: []byte("secret_key=abc123"),
		After:    []byte(" more context"),
	}

	assert.Equal(t, "context before ", string(snippet.Before))
	assert.Equal(t, "secret_key=abc123", string(snippet.Matching))
	assert.Equal(t, " more context", string(snippet.After))
}

func TestSnippet_EmptyContext(t *testing.T) {
	snippet := Snippet{
		Before:   []byte(""),
		Matching: []byte("match"),
		After:    []byte(""),
	}

	assert.Empty(t, snippet.Before)
	assert.Equal(t, "match", string(snippet.Matching))
	assert.Empty(t, snippet.After)
}

func TestSnippet_NilBytes(t *testing.T) {
	// Snippet with nil byte slices should be valid
	snippet := Snippet{
		Before:   nil,
		Matching: []byte("match"),
		After:    nil,
	}

	assert.Nil(t, snippet.Before)
	assert.NotNil(t, snippet.Matching)
	assert.Nil(t, snippet.After)
}
