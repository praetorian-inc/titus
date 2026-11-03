package commitlink

import "strings"

func init() {
	register("bitbucket.org", func(path, sha string) string {
		if strings.Count(path, "/") != 1 { // exactly workspace/repo
			return ""
		}
		return "https://bitbucket.org/" + path + "/commits/" + sha
	})
}
