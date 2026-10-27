package types

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var jun15 = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

func TestMergeOccurrences_CloneMergeDropsCommitlessDuplicate(t *testing.T) {
	// C-CLONEMERGE-1: a local --git scan and titus github acme/api share one location.
	rows := []Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", Commit: "c1", CommitDate: jun15, HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", HostRecorded: true},
		{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", WorkingTree: true,
			AbsolutePath: "/src/api/config.yml", HostRecorded: true},
	}
	got := MergeOccurrences(rows, nil)
	require.Len(t, got, 2)
	repos := map[string]bool{}
	committed := 0
	for _, o := range got {
		repos[o.Repository] = true
		if !o.WorkingTree {
			committed++
			assert.Equal(t, "c1", o.Commit)
		}
	}
	assert.Equal(t, map[string]bool{"github.com/acme/api": true}, repos)
	assert.Equal(t, 1, committed, "locations_for_config.yml")
}

func TestDisambiguateDisplay_FoldersCollision(t *testing.T) {
	// C-FOLDERS-1: identical config.yml in /x/one and /x/two.
	occs := []Occurrence{
		{Kind: "file", Path: "config.yml", AbsolutePath: "/x/one/config.yml", HostRecorded: true},
		{Kind: "file", Path: "config.yml", AbsolutePath: "/x/two/config.yml", HostRecorded: true},
	}
	assert.Equal(t, []string{"/x/one/config.yml", "/x/two/config.yml"}, DisambiguateDisplay(occs))
}

func TestSanitizeDisplay_OutputHasNoControlOrBidi(t *testing.T) {
	var all strings.Builder
	for r := rune(0); r < 0x2100; r++ {
		all.WriteRune(r)
	}
	all.WriteString("\xff\xfe\x80")
	out := SanitizeDisplay(all.String())
	assert.True(t, utf8.ValidString(out))
	for _, r := range out {
		assert.False(t, r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || isBidiControl(r), "rune %U", r)
	}
	assert.Equal(t, out, SanitizeDisplay(out), "idempotent")
}
