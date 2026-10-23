package explore

import (
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// ENG-9178: a truncated location list ends with the notice, once, as the
// last line of the Locations block; an untruncated list has no notice.
func TestRenderLocations_TruncatedNoticeAfterList(t *testing.T) {
	occs := []types.Occurrence{occAPI1, occAPI2}
	for _, truncated := range []bool{false, true} {
		m := matchWith(12, occs...)
		m.Provenance = []types.Provenance{types.GitProvenance{RepoPath: occAPI1.Repository, BlobPath: occAPI1.Path, LocationsTruncated: truncated}}

		lines := plainLines(m, nil, 500)
		_, body := locationBlock(t, lines)
		want := expectedLines(occs, 12)
		if truncated {
			want = append(want, "    "+types.LocationsTruncatedNotice)
		}
		if !slices.Equal(body, want) {
			t.Errorf("truncated=%v: Locations body\n got %q\nwant %q", truncated, body, want)
		}
		n := strings.Count(strings.Join(lines, "\n"), types.LocationsTruncatedNotice)
		if wantN := map[bool]int{false: 0, true: 1}[truncated]; n != wantN {
			t.Errorf("truncated=%v: notice appears %d times, want %d", truncated, n, wantN)
		}
	}
}

// A narrow pane wraps the notice like a location line: first line indented
// four spaces, continuations six, text intact.
func TestRenderLocations_TruncatedNoticeWraps(t *testing.T) {
	m := matchWith(12, occAPI1)
	m.Provenance = []types.Provenance{types.GitProvenance{LocationsTruncated: true}}
	_, body := locationBlock(t, plainLines(m, nil, 40))
	i := slices.IndexFunc(body, func(l string) bool { return strings.HasPrefix(l, "    locations truncated") })
	if i < 0 {
		t.Fatalf("no notice in %q", body)
	}
	notice := body[i:]
	if len(notice) < 2 {
		t.Fatalf("notice did not wrap at width 40: %q", notice)
	}
	parts := []string{strings.TrimPrefix(notice[0], "    ")}
	for _, l := range notice[1:] {
		rest, ok := strings.CutPrefix(l, "      ")
		if !ok {
			t.Fatalf("continuation %q not indented six spaces", l)
		}
		parts = append(parts, rest)
	}
	if got := strings.Join(parts, ""); got != types.LocationsTruncatedNotice {
		t.Errorf("wrapped notice reads %q", got)
	}
}
