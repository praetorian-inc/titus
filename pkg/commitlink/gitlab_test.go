package commitlink

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func TestGitLabURL(t *testing.T) {
	sha64 := strings.Repeat("0123456789abcdef", 4)

	tests := []struct {
		name   string
		mutate func(o *types.Occurrence)
		want   string
	}{
		{"group and project", func(o *types.Occurrence) {}, "https://gitlab.com/acme/widgets/-/commit/" + sha40},
		{"nested subgroups", func(o *types.Occurrence) { o.Repository = "gitlab.com/acme/team/sub/widgets" },
			"https://gitlab.com/acme/team/sub/widgets/-/commit/" + sha40},
		{"64-hex commit", func(o *types.Occurrence) { o.Commit = sha64 }, "https://gitlab.com/acme/widgets/-/commit/" + sha64},
		{"single segment", func(o *types.Occurrence) { o.Repository = "gitlab.com/acme" }, ""},
		{"dash segment in the middle", func(o *types.Occurrence) { o.Repository = "gitlab.com/acme/-/widgets" }, ""},
		{"dash segment last", func(o *types.Occurrence) { o.Repository = "gitlab.com/acme/widgets/-" }, ""},
		{"dot-git final segment", func(o *types.Occurrence) { o.Repository = "gitlab.com/acme/widgets.git" }, ""},
		{"self-hosted host", func(o *types.Occurrence) {
			o.Host = "gitlab.example.com"
			o.Repository = "gitlab.example.com/acme/widgets"
		}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := gitOcc("gitlab.com", "gitlab.com/acme/widgets", sha40)
			tt.mutate(&o)
			if got := URL(o); got != tt.want {
				t.Errorf("URL() = %q, want %q", got, tt.want)
			}
		})
	}
}
