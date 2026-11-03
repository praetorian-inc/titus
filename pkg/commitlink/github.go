package commitlink

import "strings"

func init() {
	register("github.com", func(path, sha string) string {
		if strings.Count(path, "/") != 1 { // exactly owner/repo; GitHub has no subgroups
			return ""
		}
		return "https://github.com/" + path + "/commit/" + sha
	})
}
