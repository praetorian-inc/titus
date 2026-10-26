package datastore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloneCache_clonePath_RejectsEscape(t *testing.T) {
	c := &CloneCache{Root: t.TempDir()}

	tests := []struct {
		name string
		url  string
	}{
		{"dotdot path", "https://github.com/../../etc/x"},
		{"encoded dotdot", "https://github.com/a/%2e%2e/%2e%2e/x"},
		{"encoded dotdot uppercase", "https://github.com/%2E%2E/%2E%2E/%2E%2E/x"},
		{"dotdot to sibling host", "https://github.com/../gitlab.com/x"},
		{"host dotdot", "https://../x"},
		{"ssh host dotdot", "git@..:x"},
		{"ssh host with separator", "git@../../etc:x"},
		{"ssh empty host", "git@:acme/api"},
		{"ssh dotdot path", "git@github.com:../../../etc/x"},
		{"path collapses to root", "https://github.com/a/.."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.clonePath(tt.url)
			require.Error(t, err, "got path %q", got)
			assert.Empty(t, got)
		})
	}
}
