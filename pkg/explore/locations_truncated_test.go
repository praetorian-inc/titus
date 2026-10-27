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
