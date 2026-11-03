package commitlink

import "strings"

func init() {
	register("gitlab.com", func(path, sha string) string {
		segs := strings.Split(path, "/")
		if len(segs) < 2 { // group/project; subgroups allowed
			return ""
		}
		for _, seg := range segs {
			if seg == "-" { // GitLab's reserved route separator, never a path segment
				return ""
			}
		}
		if strings.HasSuffix(segs[len(segs)-1], ".git") {
			return ""
		}
		return "https://gitlab.com/" + path + "/-/commit/" + sha
	})
}
