package types

import "strings"

// commitPathInfix maps a recorded host to the path between the repository and
// the commit id in that host's commit URLs. Adding a host is one entry.
var commitPathInfix = map[string]string{
	"gitlab.com": "/-/commit/",
}

// CommitURL returns the web URL of the commit an occurrence was found in, or
// "" when there is no link to give: not a committed git location, a host not
// in commitPathInfix or not recorded, or a repository or commit that does not
// look like what the host serves. It never invents a link.
func CommitURL(o Occurrence) string {
	if o.Kind != "git" || o.WorkingTree || !o.HostRecorded {
		return ""
	}
	infix, ok := commitPathInfix[o.Host]
	if !ok || !validCommitID(o.Commit) {
		return ""
	}
	project, ok := strings.CutPrefix(o.Repository, o.Host+"/")
	if !ok || !validProjectPath(project) {
		return ""
	}
	return "https://" + o.Repository + infix + o.Commit
}

// validProjectPath reports whether p is at least two non-empty path segments
// of letters, digits, '.', '_' and '-', none of them "." or "..".
func validProjectPath(p string) bool {
	segs := strings.Split(p, "/")
	if len(segs) < 2 {
		return false
	}
	// A project path ending ".git" is a clone URL, not a project name.
	if strings.HasSuffix(segs[len(segs)-1], ".git") {
		return false
	}
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return false
		}
		// "-" is GitLab's route separator, never a namespace or project name.
		if s == "-" {
			return false
		}
		for _, c := range s {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// validCommitID reports whether c is a full lowercase hex object id (SHA-1 or
// SHA-256).
func validCommitID(c string) bool {
	if len(c) != 40 && len(c) != 64 {
		return false
	}
	for _, r := range c {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
