package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ENG-9178: a blob's location list is truncated when any of its git
// provenance rows says so; other provenance kinds never mark it.
func TestLocationsTruncated(t *testing.T) {
	tests := []struct {
		name  string
		provs []Provenance
		want  bool
	}{
		{"none", nil, false},
		{"git not truncated", []Provenance{GitProvenance{RepoPath: "r"}, FileProvenance{FilePath: "f"}}, false},
		{"later git row truncated", []Provenance{
			FileProvenance{FilePath: "f"},
			GitProvenance{RepoPath: "r", BlobPath: "a"},
			GitProvenance{RepoPath: "r", BlobPath: "b", LocationsTruncated: true},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, LocationsTruncated(tt.provs))
		})
	}
}

// The notice is the user-visible marker every output shows verbatim.
func TestLocationsTruncatedNotice_ExactText(t *testing.T) {
	assert.Equal(t, "locations truncated: history index limit reached; more locations exist", LocationsTruncatedNotice)
}
