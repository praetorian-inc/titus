package enum

import "strings"

// AsanaScope identifies which Asana resource to scan.
type AsanaScope int

const (
	AsanaScopeAll       AsanaScope = iota // asana://         — all workspaces visible to token
	AsanaScopeWorkspace                   // asana://workspace/<gid>
	AsanaScopeTeam                        // asana://team/<gid>
	AsanaScopeProject                     // asana://project/<gid>
)

// ParseAsanaURL parses asana:// URL forms. Returns (scope, gid, true) on
// success, or (_, _, false) if the target is not an Asana URL.
//
//	asana://                  -> AsanaScopeAll, ""
//	asana://workspace/<gid>   -> AsanaScopeWorkspace, gid
//	asana://team/<gid>        -> AsanaScopeTeam, gid
//	asana://project/<gid>     -> AsanaScopeProject, gid
func ParseAsanaURL(target string) (AsanaScope, string, bool) {
	if !strings.HasPrefix(target, "asana://") {
		return 0, "", false
	}
	path := strings.TrimPrefix(target, "asana://")
	if path == "" {
		return AsanaScopeAll, "", true
	}
	parts := strings.SplitN(path, "/", 3)
	kind := parts[0]
	var gid string
	if len(parts) >= 2 {
		gid = parts[1]
	}
	if len(parts) > 2 && parts[2] != "" {
		return AsanaScopeAll, "", false
	}
	switch kind {
	case "workspace":
		if gid == "" {
			return 0, "", false
		}
		return AsanaScopeWorkspace, gid, true
	case "team":
		if gid == "" {
			return 0, "", false
		}
		return AsanaScopeTeam, gid, true
	case "project":
		if gid == "" {
			return 0, "", false
		}
		return AsanaScopeProject, gid, true
	default:
		return 0, "", false
	}
}
