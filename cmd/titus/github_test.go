package main

import (
	"testing"
)

func TestSplitOwnerRepo(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid owner/repo",
			input: "praetorian-inc/titus",
			want:  []string{"praetorian-inc", "titus"},
		},
		{
			name:  "owner with hyphens",
			input: "my-org/my-repo",
			want:  []string{"my-org", "my-repo"},
		},
		{
			name:  "single slash",
			input: "owner/repo",
			want:  []string{"owner", "repo"},
		},
		{
			name:  "no slash",
			input: "invalid",
			want:  []string{"invalid"},
		},
		{
			name:  "multiple slashes",
			input: "owner/repo/extra",
			want:  []string{"owner", "repo", "extra"},
		},
		{
			name:  "empty string",
			input: "",
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitOwnerRepo(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("splitOwnerRepo(%q) length = %d, want %d", tt.input, len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitOwnerRepo(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}
