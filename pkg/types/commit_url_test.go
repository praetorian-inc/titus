package types

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	hex40  = "0123456789abcdef0123456789abcdef01234567"
	hex40b = "fedcba9876543210fedcba9876543210fedcba98"
	hex64  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func gitlabOcc(mut func(*Occurrence)) Occurrence {
	o := Occurrence{Kind: "git", Repository: "gitlab.com/acme/widgets", Host: "gitlab.com", Path: "src/a.go", Commit: hex40, HostRecorded: true}
	if mut != nil {
		mut(&o)
	}
	return o
}

func TestCommitURL_Links(t *testing.T) {
	tests := []struct {
		name string
		occ  Occurrence
		want string
	}{
		{"C1 group/project", gitlabOcc(nil), "https://gitlab.com/acme/widgets/-/commit/" + hex40},
		{"C2 subgroup keeps every segment", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/team/widgets"; o.Commit = hex40b }),
			"https://gitlab.com/acme/team/widgets/-/commit/" + hex40b},
		{"C6 first commit", gitlabOcc(func(o *Occurrence) { o.Commit = strings.Repeat("1", 40) }), "https://gitlab.com/acme/widgets/-/commit/" + strings.Repeat("1", 40)},
		{"C6 second commit", gitlabOcc(func(o *Occurrence) { o.Commit = strings.Repeat("2", 40) }), "https://gitlab.com/acme/widgets/-/commit/" + strings.Repeat("2", 40)},
		{"64-hex commit", gitlabOcc(func(o *Occurrence) { o.Commit = hex64 }), "https://gitlab.com/acme/widgets/-/commit/" + hex64},
		{"dots dashes underscores in segments", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/a-b/c_d.e/f.g-h" }), "https://gitlab.com/a-b/c_d.e/f.g-h/-/commit/" + hex40},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, CommitURL(tt.occ))
		})
	}
}

func TestCommitURL_NoLink(t *testing.T) {
	tests := []struct {
		name string
		occ  Occurrence
	}{
		{"C3 other gitlab host", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.example.com/acme/widgets"; o.Host = "gitlab.example.com" })},
		{"C4 github.com", gitlabOcc(func(o *Occurrence) { o.Repository = "github.com/acme/widgets"; o.Host = "github.com" })},
		{"C5 working tree, empty commit", gitlabOcc(func(o *Occurrence) { o.WorkingTree = true; o.Commit = "" })},
		{"working tree even with a commit", gitlabOcc(func(o *Occurrence) { o.WorkingTree = true })},
		{"empty commit", gitlabOcc(func(o *Occurrence) { o.Commit = "" })},
		{"C7 legacy row, host not recorded", gitlabOcc(func(o *Occurrence) { o.HostRecorded = false; o.Host = "" })},
		{"host not recorded even if host text is gitlab.com", gitlabOcc(func(o *Occurrence) { o.HostRecorded = false })},
		{"recorded empty host", gitlabOcc(func(o *Occurrence) { o.Host = "" })},
		{"Host case differs", gitlabOcc(func(o *Occurrence) { o.Host = "GitLab.com" })},
		{"Kind file", gitlabOcc(func(o *Occurrence) { o.Kind = "file" })},
		{"repository on another host while Host is gitlab.com", gitlabOcc(func(o *Occurrence) { o.Repository = "github.com/acme/widgets" })},
		{"lookalike host prefix", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com.evil.example/a/b" })},
		{"repository without gitlab.com/ prefix", gitlabOcc(func(o *Occurrence) { o.Repository = "acme/widgets" })},
		{"query char", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/wid?gets" })},
		{"fragment char", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/wid#gets" })},
		{"userinfo char", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/wid@gets" })},
		{"percent char", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/wid%2Fgets" })},
		{"space", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/wid gets" })},
		{"control char", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/wid\x1bgets" })},
		{"newline in repository", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/wid\ngets" })},
		{"non-ASCII", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/widégets" })},
		{"dot-dot segment", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/../widgets" })},
		{"dot segment", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/./widgets" })},
		{"trailing dot-dot segment", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/.." })},
		{"empty segment", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme//widgets" })},
		{"trailing slash", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/widgets/" })},
		{"one segment", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme" })},
		{"dash route separator mid-path", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/-/widgets" })},
		{"dash route separator trailing", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/widgets/-" })},
		{"project ending in .git", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/acme/widgets.git" })},
		{"zero segments", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com/" })},
		{"bare host", gitlabOcc(func(o *Occurrence) { o.Repository = "gitlab.com" })},
		{"short commit", gitlabOcc(func(o *Occurrence) { o.Commit = "0123456" })},
		{"39 hex", gitlabOcc(func(o *Occurrence) { o.Commit = hex40[:39] })},
		{"41 hex", gitlabOcc(func(o *Occurrence) { o.Commit = hex40 + "a" })},
		{"non-hex 40", gitlabOcc(func(o *Occurrence) { o.Commit = strings.Repeat("g", 40) })},
		{"uppercase hex", gitlabOcc(func(o *Occurrence) { o.Commit = strings.ToUpper(hex40) })},
		{"newline in commit", gitlabOcc(func(o *Occurrence) { o.Commit = hex40[:39] + "\n" })},
		{"commit with trailing newline", gitlabOcc(func(o *Occurrence) { o.Commit = hex40 + "\n" })},
		{"path traversal in commit", gitlabOcc(func(o *Occurrence) { o.Commit = "/../" + hex40[:36] })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, "", CommitURL(tt.occ))
		})
	}
}
