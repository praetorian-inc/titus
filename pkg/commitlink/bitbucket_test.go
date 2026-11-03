package commitlink

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func TestBitbucketURL(t *testing.T) {
	sha40 := strings.Repeat("ab12cd34ef", 4)
	sha64 := strings.Repeat("0123456789abcdef", 4)

	tests := []struct {
		name   string
		mutate func(o *types.Occurrence)
		want   string
	}{
		{"40-hex commit", func(o *types.Occurrence) {}, "https://bitbucket.org/acme/widgets/commits/" + sha40},
		{"64-hex commit", func(o *types.Occurrence) { o.Commit = sha64 }, "https://bitbucket.org/acme/widgets/commits/" + sha64},
		{"no commit", func(o *types.Occurrence) { o.Commit = "" }, ""},
		{"working tree", func(o *types.Occurrence) { o.WorkingTree = true }, ""},
		{"empty host", func(o *types.Occurrence) { o.Host = "" }, ""},
		{"self-hosted host", func(o *types.Occurrence) {
			o.Host = "bitbucket.corp.example"
			o.Repository = "bitbucket.corp.example/acme/widgets"
		}, ""},
		{"lookalike suffix host", func(o *types.Occurrence) {
			o.Host = "bitbucket.org.evil.example"
			o.Repository = "bitbucket.org.evil.example/acme/widgets"
		}, ""},
		{"lookalike prefix host", func(o *types.Occurrence) {
			o.Host = "evilbitbucket.org"
			o.Repository = "evilbitbucket.org/acme/widgets"
		}, ""},
		{"subgroup path", func(o *types.Occurrence) { o.Repository = "bitbucket.org/acme/team/widgets" }, ""},
		{"owner only", func(o *types.Occurrence) { o.Repository = "bitbucket.org/acme" }, ""},
		{"abbreviated commit", func(o *types.Occurrence) { o.Commit = sha40[:7] }, ""},
		{"segment with space", func(o *types.Occurrence) { o.Repository = "bitbucket.org/acme/wid gets" }, ""},
		{"dot-dot segment", func(o *types.Occurrence) { o.Repository = "bitbucket.org/acme/.." }, ""},
		{"host and repository mismatch", func(o *types.Occurrence) { o.Repository = "github.com/acme/widgets" }, ""},
		{"file kind", func(o *types.Occurrence) { o.Kind = "file" }, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := types.Occurrence{
				Kind:         "git",
				Repository:   "bitbucket.org/acme/widgets",
				Host:         "bitbucket.org",
				Commit:       sha40,
				HostRecorded: true,
			}
			tt.mutate(&o)
			if got := URL(o); got != tt.want {
				t.Errorf("URL() = %q, want %q", got, tt.want)
			}
		})
	}
}
