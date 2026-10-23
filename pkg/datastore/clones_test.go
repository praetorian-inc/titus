package datastore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloneCache_clonePath_ValidURLs(t *testing.T) {
	root := t.TempDir()
	c := &CloneCache{Root: root}

	tests := []struct {
		name string
		url  string
		want string
	}{
		{"https github", "https://github.com/acme/api", filepath.Join(root, "github.com", "acme", "api.git")},
		{"https .git suffix", "https://github.com/acme/api.git", filepath.Join(root, "github.com", "acme", "api.git")},
		{"gitlab nested groups", "https://gitlab.com/group/sub/deeper/proj", filepath.Join(root, "gitlab.com", "group", "sub", "deeper", "proj.git")},
		{"ssh scp form", "git@github.com:acme/api.git", filepath.Join(root, "github.com", "acme", "api.git")},
		{"host with port", "https://git.example.com:8443/acme/api", filepath.Join(root, "git.example.com:8443", "acme", "api.git")},
		{"dots inside segment", "https://github.com/acme/my..repo", filepath.Join(root, "github.com", "acme", "my..repo.git")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.clonePath(tt.url)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

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

func TestCloneCache_Exists_RejectsEscape(t *testing.T) {
	base := t.TempDir()
	c := &CloneCache{Root: filepath.Join(base, "root")}
	require.NoError(t, os.MkdirAll(filepath.Join(base, "etc", "x.git", "refs"), 0o755))
	assert.False(t, c.Exists("https://github.com/../../etc/x"))
}
