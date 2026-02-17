//go:build !wasm

package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_MemoryPath(t *testing.T) {
	s, err := New(Config{Path: ":memory:"})
	require.NoError(t, err)
	require.NotNil(t, s)
	defer s.Close()
}

func TestNew_EmptyPath(t *testing.T) {
	_, err := New(Config{Path: ""})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "path is required")
}

func TestNew_FilePath(t *testing.T) {
	// Create temp file for testing
	tmpFile := t.TempDir() + "/test.db"
	s, err := New(Config{Path: tmpFile})
	require.NoError(t, err)
	require.NotNil(t, s)
	defer s.Close()
}
