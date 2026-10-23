package enum

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAPIRepoIdentity(t *testing.T) {
	tests := []struct {
		name, baseURL, defaultHost, fullPath, want string
	}{
		{"default host", "", "github.com", "acme/api", "github.com/acme/api"},
		{"enterprise github host", "https://github.example.com", "github.com", "acme/api", "github.example.com/acme/api"},
		{"self-managed gitlab host", "https://gitlab.example.com", "gitlab.com", "acme/api", "gitlab.example.com/acme/api"},
		{"invalid path falls back to sanitized typed name", "https://", "github.com", "acme/api\x1b", `acme/api\x1b`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, apiRepoIdentity(tt.baseURL, tt.defaultHost, tt.fullPath))
		})
	}
}
