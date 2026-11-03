package commitlink

import "strings"

const adoHost = "https://dev.azure.com/"

// Every Azure DevOps clone form links to the one canonical dev.azure.com
// commit page; the legacy *.visualstudio.com hosts redirect there. Shapes
// that do not carry org, project and repo (project-less "org/_git/repo",
// legacy "DefaultCollection/...") return "": mapping them is unverified.
func init() {
	register("dev.azure.com", func(path, sha string) string {
		if s := strings.Split(path, "/"); len(s) != 4 || s[2] != "_git" {
			return ""
		}
		return adoHost + path + "/commit/" + sha
	})
	registerSuffix(".visualstudio.com", func(org, path, sha string) string {
		if s := strings.Split(path, "/"); len(s) != 3 || s[1] != "_git" || !isOrgLabel(org) {
			return ""
		}
		return adoHost + org + "/" + path + "/commit/" + sha
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
