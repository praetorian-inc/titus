package repoid

import (
	"net/url"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// C-NORMALIZE-1: every origin form of one repository yields the same identity.
func TestNormalize_SpecExamples(t *testing.T) {
	for _, remote := range []string{
		"git@github.com:acme/api.git",
		"https://user:tok@GitHub.com/acme/api.git",
		"ssh://git@github.com:22/acme/api",
	} {
		t.Run(remote, func(t *testing.T) {
			id, ok := Normalize(remote)
			require.True(t, ok)
			assert.Equal(t, "github.com/acme/api", id)
		})
	}
}

func TestNormalize_Accepted(t *testing.T) {
	tests := []struct {
		name     string
		remote   string
		expected string
	}{
		{"scp form", "git@github.com:acme/api.git", "github.com/acme/api"},
		{"scp form without user", "github.com:acme/api", "github.com/acme/api"},
		{"https with credentials", "https://user:tok@GitHub.com/acme/api.git", "github.com/acme/api"},
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
		{"github app token", "https://x-access-token:ghs_X@github.com/o/r.git", "github.com/o/r"},
		{"gitlab token, port, query, fragment", "https://oauth2:glpat-X@gitlab.example.com:8443/g/s/p.git?private_token=Y#frag", "gitlab.example.com/g/s/p"},
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
	id, ok := Normalize("https://user:tok@GitHub.com/acme/api.git")
	require.True(t, ok)
	assert.NotContains(t, id, "tok")
	assert.NotContains(t, id, "user")

	id, ok = Normalize("https://oauth2:glpat-X@gitlab.example.com:8443/g/s/p.git?private_token=Y#frag")
	require.True(t, ok)
	assert.NotContains(t, id, "glpat")
	assert.NotContains(t, id, "private_token")
	assert.NotContains(t, id, "frag")
}

// SEC-2 / SEC-4 / C-HOSTS-2: anything unrecognized fails closed with an empty
// identity, never the raw input and never a guessed host.
func TestNormalize_Rejected(t *testing.T) {
	for _, remote := range []string{
		"",
		"acme/api",
		"api",
		"/srv/git/api.git",
		"./api",
		"../api",
		"file:///x",
		"file:///srv/git/api.git",
		`C:\repos\api`,
		"C:/repos/api",
		`\\server\share\api`,
		"ext::sh -c touch% /tmp/pwned",
		"fd::17",
		"ext::git@github.com:acme/api",
		"codecommit::us-east-1://api",
		"persistent-https::https://github.com/acme/api",
		"https:///acme/api",
		"https://user:tok@/acme/api",
		"https://github.com",
		"https://github.com/",
		"https://github.com/.git",
		"https://h/../../etc/passwd",
		"https://h/o/%2e%2e/r",
		"https://h/o/./r",
		"https://h/o//r",
		"https://h/o/r%5Cx",
		"https://h/o/r%00",
		"https://h/o/r%0a",
		"https://h/o/my%20api",
		"https://h/o/%2540/r",
		"https://h/o/r%3Fx",
		"https://h/o/r%23x",
		"https://h/o/r%3Ax",
		"https://ho st/o/r",
		"ftp://github.com/acme/api",
		"git@github.com:",
		"git@:acme/api",
		"git@github.com:../etc",
		"https://u:p@h:notaport/o/r",
	} {
		t.Run(remote, func(t *testing.T) {
			id, ok := Normalize(remote)
			assert.False(t, ok)
			assert.Empty(t, id)
		})
	}
}

// C-HOSTS-1: API-mode identity takes its host from the configured base URL.
func TestFromBaseURL(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		defaultHost string
		fullPath    string
		expected    string
	}{
		{"default github", "", "github.com", "acme/api", "github.com/acme/api"},
		{"github enterprise api url", "https://github.example.com/api/v3/", "github.com", "acme/api", "github.example.com/acme/api"},
		{"github enterprise web url", "https://github.example.com", "github.com", "acme/api", "github.example.com/acme/api"},
		{"gitlab self-hosted", "https://gitlab.example.com", "gitlab.com", "acme/api", "gitlab.example.com/acme/api"},
		{"default gitlab nested group", "", "gitlab.com", "group/sub/api", "gitlab.com/group/sub/api"},
		{"base url credentials and port dropped", "https://u:tok@GitLab.Example.com:8443/", "gitlab.com", "acme/api", "gitlab.example.com/acme/api"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, FromBaseURL(tt.baseURL, tt.defaultHost, tt.fullPath))
		})
	}
}

// The C-HOSTS-1 scans produce three distinct identities for one owner/repo.
func TestFromBaseURL_HostsStayDistinct(t *testing.T) {
	got := []string{
		FromBaseURL("", "github.com", "acme/api"),
		FromBaseURL("https://github.example.com", "github.com", "acme/api"),
		FromBaseURL("https://gitlab.example.com", "gitlab.com", "acme/api"),
	}
	assert.Equal(t, []string{
		"github.com/acme/api",
		"github.example.com/acme/api",
		"gitlab.example.com/acme/api",
	}, got)
}

// An unusable base URL never borrows the default host (no guessed host) and
// never echoes credentials; an unusable path yields no identity at all.
func TestFromBaseURL_Unusable(t *testing.T) {
	assert.Equal(t, "acme/api", FromBaseURL("://bad", "github.com", "acme/api"))
	assert.Equal(t, "acme/api", FromBaseURL("https://u:tok@/", "github.com", "acme/api"))
	assert.Equal(t, "", FromBaseURL("", "github.com", "../etc"))
}

func TestRedactUserinfo(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		expected string
	}{
		{"credentials", "https://u:SECRET@h/o/r", "https://h/o/r"},
		{"user only", "https://org@dev.azure.com/org/p", "https://dev.azure.com/org/p"},
		{"at sign in password", "https://u:p@ss@h/o/r", "https://h/o/r"},
		{"no userinfo", "https://github.com/acme/api", "https://github.com/acme/api"},
		{"no path", "https://u:SECRET@h", "https://h"},
		{"query ends authority", "https://u:SECRET@h?x=1", "https://h?x=1"},
		{"at sign after authority kept", "https://h/o/r@v1", "https://h/o/r@v1"},
		{"ssh", "ssh://git@github.com:22/acme/api", "ssh://github.com:22/acme/api"},
		{"bare owner/repo", "acme/api", "acme/api"},
		{"local path", "/srv/git/api", "/srv/git/api"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := RedactUserinfo(tt.in)
			assert.Equal(t, tt.expected, out)
			assert.NotContains(t, out, "SECRET")
		})
	}
}

// assertIdentityInvariant checks SEC-1's output invariant: no '@', '?', '#',
// '%', whitespace or control character, ':' only inside a leading bracketed
// IPv6 host, and a non-empty host followed by clean path segments.
func assertIdentityInvariant(t *testing.T, id string) {
	t.Helper()
	rest := id
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		require.Positive(t, end, "unterminated bracketed host in %q", id)
		rest = rest[end+1:]
	}
	assert.NotContains(t, rest, ":", "identity %q", id)
	for _, r := range id {
		assert.False(t, strings.ContainsRune(`@?#%\`, r), "identity %q contains %q", id, r)
		assert.False(t, unicode.IsSpace(r) || unicode.IsControl(r), "identity %q contains %q", id, r)
	}
	host, path, found := strings.Cut(id, "/")
	assert.True(t, found, "identity %q has no path", id)
	assert.NotEmpty(t, host)
	for seg := range strings.SplitSeq(path, "/") {
		assert.NotContains(t, []string{"", ".", ".."}, seg, "identity %q", id)
	}
}

// secretWindows returns every 4-rune substring of s. A leaked substring of
// length >= 4 always contains one of them.
func secretWindows(s string) []string {
	r := []rune(s)
	var out []string
	for i := 0; i+4 <= len(r); i++ {
		out = append(out, string(r[i:i+4]))
	}
	return out
}

func FuzzNormalize(f *testing.F) {
	for _, seed := range []string{
		"git@github.com:acme/api.git",
		"https://user:tok@GitHub.com/acme/api.git",
		"ssh://git@github.com:22/acme/api",
		"ssh://git@gitlab.example.com:2222/group/sub/api.git",
		"https://x-access-token:ghs_X@github.com/o/r.git",
		"https://oauth2:glpat-X@gitlab.example.com:8443/g/s/p.git?private_token=Y#frag",
		"https://org@dev.azure.com/org/proj/_git/repo",
		"ssh://git@[2001:db8::1]:2222/o/r",
		"git@[::1]:o/r.git",
		"https://u%3Ap@h/o/r",
		"https://h/../../etc/passwd",
		"ext::sh -c touch% /tmp/pwned",
		"file:///x",
		"acme/api",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, remote string) {
		id, ok := Normalize(remote)
		if !ok {
			assert.Empty(t, id)
			return
		}
		assertIdentityInvariant(t, id)

		// No 4+ rune piece of the userinfo, query or fragment may reach the
		// output unless it also appears in the host or path the output is built
		// from. Comparison is case-insensitive because the host is lowercased.
		u, err := url.Parse(remote)
		if err != nil || u.Host == "" {
			return
		}
		source := strings.ToLower(u.Host + u.Path + u.EscapedPath())
		var secrets []string
		if u.User != nil {
			pw, _ := u.User.Password()
			secrets = append(secrets, u.User.Username(), pw)
		}
		secrets = append(secrets, u.RawQuery, u.Fragment)
		lowerID := strings.ToLower(id)
		for _, s := range secrets {
			for _, w := range secretWindows(strings.ToLower(s)) {
				if strings.Contains(source, w) {
					continue
				}
				assert.NotContains(t, lowerID, w, "input %q leaked %q", remote, w)
			}
		}
	})
}
