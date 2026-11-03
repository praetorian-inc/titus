// Package commitlink builds a web link to the commit Titus recorded for a
// location. It is a pure leaf helper: no I/O, no remote parsing. A link is
// built only from recorded fields, never guessed, so a location with no
// recorded commit or an unsupported host has no link.
//
// Each supported host lives in its own file and registers itself from init. A
// file may also register a single-label host suffix with registerSuffix.
package commitlink

import (
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

// builder formats the commit URL for one host. path is the repository path
// after "<host>/" (e.g. "owner/repo" or "group/sub/repo"), already validated;
// sha is 40 or 64 lowercase hex. It returns "" if path has the wrong shape
// for the host.
type builder func(path, sha string) string

var hosts = map[string]builder{}

// register adds the builder for an exact, lowercased host. It panics on an
// empty or duplicate host, which is a programmer error at init time.
func register(host string, b builder) {
	if host == "" {
		panic("commitlink: register with empty host")
	}
	if _, dup := hosts[host]; dup {
		panic("commitlink: duplicate host " + host)
	}
	hosts[host] = b
}

// suffixBuilder is a builder for every host "<label><suffix>"; label is the
// text before suffix, one DNS label with no dots.
type suffixBuilder func(label, path, sha string) string

var suffixes = map[string]suffixBuilder{}

// registerSuffix adds the builder for every host of the form "<label><suffix>"
// (suffix includes its leading dot). It panics on an empty or duplicate
// suffix, which is a programmer error at init time.
func registerSuffix(suffix string, b suffixBuilder) {
	if suffix == "" {
		panic("commitlink: registerSuffix with empty suffix")
	}
	if _, dup := suffixes[suffix]; dup {
		panic("commitlink: duplicate suffix " + suffix)
	}
	suffixes[suffix] = b
}

// lookup returns the builder for host: an exact registration wins, else a
// registered suffix with a single non-empty label before it.
func lookup(host string) (builder, bool) {
	if b, ok := hosts[host]; ok {
		return b, true
	}
	for suffix, sb := range suffixes {
		label, ok := strings.CutSuffix(host, suffix)
		if !ok || label == "" || strings.Contains(label, ".") {
			continue
		}
		return func(path, sha string) string { return sb(label, path, sha) }, true
	}
	return nil, false
}

// URL returns the commit link for o, or "" when none can be built: o must be
// a committed git location on a registered host, with a safe repository path
// and a full lowercase hex commit.
func URL(o types.Occurrence) string {
	if o.Kind != "git" || o.WorkingTree || o.Commit == "" || o.Host == "" {
		return ""
	}
	b, ok := lookup(o.Host)
	if !ok {
		return ""
	}
	path, ok := strings.CutPrefix(o.Repository, o.Host+"/")
	if !ok || !safePath(path) || !fullHex(o.Commit) {
		return ""
	}
	return b(path, o.Commit)
}

// safePath reports whether every "/"-separated segment is non-empty, not "."
// or "..", and made only of [A-Za-z0-9._-].
func safePath(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// fullHex reports whether s is 40 or 64 lowercase hex characters.
func fullHex(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
