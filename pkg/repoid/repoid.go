// Package repoid derives a credential-free repository identity
// ("<host>/<path>") from git remote URLs and API base URLs.
//
// It is a pure leaf package: no exec, no I/O. Identities are display and
// grouping keys only and must never be used as filesystem paths.
package repoid

import (
	"net"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// remoteSchemes are the URL schemes git uses for network remotes.
var remoteSchemes = map[string]bool{
	"ssh":     true,
	"git":     true,
	"http":    true,
	"https":   true,
	"git+ssh": true,
}

// Normalize returns "<host>/<path>" for a network remote; ok=false otherwise.
// It lowercases the host and strips scheme, userinfo, port, query, fragment,
// and a trailing "/" and ".git". The scp form "git@host:owner/repo.git" is
// accepted. Local paths, file:// and "<transport>::<address>" remotes, and
// anything that fails validation return ("", false); the raw input is never
// returned.
func Normalize(remote string) (id string, ok bool) {
	if hasTransportPrefix(remote) {
		return "", false
	}
	var host, path string
	if strings.Contains(remote, "://") {
		host, path, ok = parseURL(remote)
	} else {
		host, path, ok = parseSCP(remote)
	}
	if !ok {
		return "", false
	}
	return join(host, path)
}

// FromBaseURL joins the host of baseURL (or defaultHost when baseURL is empty)
// with fullPath. Used for API-mode identities (GitHub/GitLab, incl. --url).
// When baseURL is set but has no usable host, it returns fullPath without a
// host rather than guessing one. It returns "" when fullPath is not a valid
// repository path.
func FromBaseURL(baseURL, defaultHost, fullPath string) string {
	host := defaultHost
	if baseURL != "" {
		host = ""
		if u, err := url.Parse(baseURL); err == nil {
			host, _ = cleanHost(u.Hostname())
		}
	}
	if host == "" {
		if path, ok := cleanPath(fullPath); ok {
			return path
		}
		return ""
	}
	id, _ := join(host, fullPath)
	return id
}

// RedactUserinfo is the display-safe form of a stored repository value that
// predates Normalize. It applies to a value that contains "://", has an '@'
// before its first '/' (the scp-like "user:token@host:org/repo"), or starts
// with "//" and has an '@' in the authority that follows. It then:
//   - cuts the value at the first '?' or '#' (query and fragment);
//   - drops everything up to and including the last '@' in its lead: the text
//     before the first "://" when there is one, else the text before the
//     first '/'. This removes scp-like userinfo and userinfo in text that
//     only looks like a scheme, as in "u:token@h/x://y";
//   - drops the userinfo from the authority after the first "://", or after a
//     leading "//" when there is no "://".
//
// Every other value (a local path or "owner/repo") is returned byte-for-byte
// unchanged, including any '?' or '#' it contains.
func RedactUserinfo(s string) string {
	if !strings.Contains(s, "://") && !strings.Contains(leadOf(s), "@") && !strings.Contains(netAuthority(s), "@") {
		return s
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if at := strings.LastIndexByte(leadOf(s), '@'); at >= 0 {
		s = s[at+1:]
	}
	start := len("//")
	if i := strings.Index(s, "://"); i >= 0 {
		start = i + len("://")
	} else if !strings.HasPrefix(s, "//") {
		return s
	}
	authority, _, _ := strings.Cut(s[start:], "/")
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		s = s[:start] + s[start+at+1:]
	}
	return s
}

// leadOf returns the text of s before its first "://", or before its first
// '/' when s has no "://".
func leadOf(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		return s[:i]
	}
	lead, _, _ := strings.Cut(s, "/")
	return lead
}

// netAuthority returns the authority of a network-path reference
// ("//authority/path"), or "" when s does not start with "//".
func netAuthority(s string) string {
	rest, found := strings.CutPrefix(s, "//")
	if !found {
		return ""
	}
	authority, _, _ := strings.Cut(rest, "/")
	return authority
}

// hasTransportPrefix reports whether remote uses git's "<transport>::<address>"
// remote-helper syntax (ext::, fd::, codecommit::, ...). Those fail closed.
func hasTransportPrefix(remote string) bool {
	name, _, found := strings.Cut(remote, "::")
	if !found || name == "" {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// parseURL splits a "scheme://[userinfo@]host[:port]/path" remote. Query,
// fragment, userinfo and port are discarded.
func parseURL(remote string) (host, path string, ok bool) {
	u, err := url.Parse(remote)
	if err != nil || !remoteSchemes[strings.ToLower(u.Scheme)] {
		return "", "", false
	}
	host, ok = cleanHost(u.Hostname())
	return host, u.Path, ok
}

// parseSCP splits the scp-like form "[user@]host:path", including a bracketed
// IPv6 host. As in git, the form requires a ':' before the first '/'.
func parseSCP(remote string) (host, path string, ok bool) {
	slash := strings.IndexByte(remote, '/')
	if slash < 0 {
		slash = len(remote)
	}
	at := strings.LastIndexByte(remote[:slash], '@')
	rest := remote[at+1:]

	var rawHost string
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]:")
		if end < 0 {
			return "", "", false
		}
		rawHost, path = rest[1:end], rest[end+2:]
	} else {
		var found bool
		rawHost, path, found = strings.Cut(rest, ":")
		// A missing ':' or one after the first '/' means a local path. A
		// one-letter host is a Windows drive ("C:/repo"), also local.
		if !found || strings.Contains(rawHost, "/") || len(rawHost) == 1 {
			return "", "", false
		}
	}
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return "", "", false
	}
	host, ok = cleanHost(rawHost)
	return host, decoded, ok
}

// cleanHost lowercases a hostname (without port) and validates it. IPv6
// literals are returned in brackets.
func cleanHost(h string) (string, bool) {
	h = strings.ToLower(h)
	if h == "" {
		return "", false
	}
	if strings.Contains(h, ":") {
		if net.ParseIP(h) == nil {
			return "", false
		}
		return "[" + h + "]", true
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return "", false
		}
	}
	return h, true
}

// cleanPath trims a decoded repository path and rejects traversal, empty
// segments, and characters that are not allowed in an identity.
func cleanPath(p string) (string, bool) {
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimRight(p, "/")
	p = strings.TrimSuffix(p, ".git")
	p = strings.TrimRight(p, "/")
	if p == "" || !utf8.ValidString(p) {
		return "", false
	}
	for _, r := range p {
		if strings.ContainsRune(`@?#%:\`, r) || unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", false
		}
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", false
		}
	}
	return p, true
}

// join validates path and returns "<host>/<path>".
func join(host, path string) (string, bool) {
	p, ok := cleanPath(path)
	if !ok {
		return "", false
	}
	return host + "/" + p, true
}
