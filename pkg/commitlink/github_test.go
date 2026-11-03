package commitlink

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitHub_RepositoryShape(t *testing.T) {
	tests := []struct {
		name string
		repo string
		want string
	}{
		{"owner/repo", "github.com/acme/api", "https://github.com/acme/api/commit/" + sha40},
		{"subgroup path is not a GitHub shape", "github.com/acme/team/api", ""},
		{"deep path", "github.com/a/b/c/d", ""},
		{"owner only", "github.com/acme", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, URL(gitOcc("github.com", tt.repo, sha40)))
		})
	}
}
