package repoid

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalize_Accepted(t *testing.T) {
	tests := []struct {
		name     string
		remote   string
		expected string
	}{
		{"scp form", "git@github.com:acme/api.git", "github.com/acme/api"},
		{"scp form without user", "github.com:acme/api", "github.com/acme/api"},
		{"https with credentials", "https://user:" + "tok@GitHub.com/acme/api.git", "github.com/acme/api"},
		{"ssh with non-default port", "ssh://git@gitlab.example.com:2222/group/sub/api.git", "gitlab.example.com/group/sub/api"},
		{"ssh default port", "ssh://git@github.com:22/acme/api", "github.com/acme/api"},
		{"query and fragment stripped", "https://github.com/acme/api.git?ref=main#readme", "github.com/acme/api"},
		{"trailing slash", "https://github.com/acme/api/", "github.com/acme/api"},
		{"trailing slash after .git", "https://github.com/acme/api.git/", "github.com/acme/api"},
		{"path keeps case", "https://GITHUB.COM/Acme/API.git", "github.com/Acme/API"},
		{"git protocol", "git://github.com/acme/api.git", "github.com/acme/api"},
		{"git+ssh", "git+ssh://git@github.com/acme/api.git", "github.com/acme/api"},
		{"http", "http://git.example.com/acme/api", "git.example.com/acme/api"},
		{"uppercase scheme", "HTTPS://github.com/acme/api", "github.com/acme/api"},
		{"github app token", "https://x-access-token:" + "ghs_X@github.com/o/r.git", "github.com/o/r"},
		{"gitlab token, port, query, fragment", "https://oauth2:" + "glpat-X@gitlab.example.com:8443/g/s/p.git?private_token=Y#frag", "gitlab.example.com/g/s/p"},
		{"azure devops org userinfo", "https://org@dev.azure.com/org/proj/_git/repo", "dev.azure.com/org/proj/_git/repo"},
		{"percent-encoded userinfo", "https://u%3Ap@h/o/r", "h/o/r"},
		{"percent-encoded path decoded once", "https://github.com/acme/my%2Dapi", "github.com/acme/my-api"},
		{"bracketed ipv6 url", "ssh://git@[2001:db8::1]:2222/o/r", "[2001:db8::1]/o/r"},
		{"bracketed ipv6 scp", "git@[::1]:o/r.git", "[::1]/o/r"},
		{"scp with absolute path", "git@host.example.com:/srv/git/api.git", "host.example.com/srv/git/api"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, ok := Normalize(tt.remote)
			require.True(t, ok)
			assert.Equal(t, tt.expected, id)
		})
	}
}

func TestNormalize_CredentialsNeverInOutput(t *testing.T) {
	id, ok := Normalize("https://user:" + "tok@GitHub.com/acme/api.git")
	require.True(t, ok)
	assert.NotContains(t, id, "tok")
	assert.NotContains(t, id, "user")

	id, ok = Normalize("https://oauth2:" + "glpat-X@gitlab.example.com:8443/g/s/p.git?private_token=Y#frag")
	require.True(t, ok)
	assert.NotContains(t, id, "glpat")
	assert.NotContains(t, id, "private_token")
	assert.NotContains(t, id, "frag")
}
