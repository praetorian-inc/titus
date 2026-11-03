package commitlink

import "strings"

const adoHost = "https://dev.azure.com/"

// Every Azure DevOps clone form links to the one canonical dev.azure.com
// commit page; the legacy *.visualstudio.com hosts are documented to redirect
// there (not verified against a live tenant). The ssh hosts map to
// dev.azure.com because an SSH clone's origin identity is v3/org/project/repo.
// The project is optional ("org/_git/repo"). On *.visualstudio.com a leading
// legacy "DefaultCollection" segment is dropped; it is not part of
// dev.azure.com URLs.
func init() {
	register("dev.azure.com", func(path, sha string) string {
		if !gitShape(strings.Split(path, "/"), 3) {
			return ""
		}
		return adoHost + path + "/commit/" + sha
	})
	registerSuffix(".visualstudio.com", func(org, path, sha string) string {
		s := strings.Split(path, "/")
		if len(s) > 0 && strings.EqualFold(s[0], "DefaultCollection") {
			s = s[1:]
		}
		if !gitShape(s, 2) || !isOrgLabel(org) {
			return ""
		}
		return adoHost + org + "/" + strings.Join(s, "/") + "/commit/" + sha
	})
	for _, host := range []string{"ssh.dev.azure.com", "vs-ssh.visualstudio.com"} {
		register(host, sshURL)
	}
}

// sshURL maps the SSH identity "v3/org/project/repo".
func sshURL(path, sha string) string {
	s := strings.Split(path, "/")
	if len(s) != 4 || s[0] != "v3" {
		return ""
	}
	return adoHost + s[1] + "/" + s[2] + "/_git/" + s[3] + "/commit/" + sha
}

// isOrgLabel reports whether s is non-empty and made only of [a-z0-9-].
func isOrgLabel(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// gitShape reports whether s is a project-less (min segments) or
// project-qualified (min+1 segments) path whose second-to-last segment is
// "_git".
func gitShape(s []string, min int) bool {
	return (len(s) == min || len(s) == min+1) && s[len(s)-2] == "_git"
}
