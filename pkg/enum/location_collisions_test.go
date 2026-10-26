package enum

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allLocs collects the locations of every callback for each blob, so a
// location delivered on a second callback for the same BlobID still counts.
// A location dropped by every callback is missing from the result.
type allLocs struct {
	mu   sync.Mutex
	locs map[types.BlobID][]wtLoc
}

func (a *allLocs) callback(_ []byte, id types.BlobID, prov types.Provenance) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	gp, ok := prov.(types.GitProvenance)
	if !ok {
		return nil
	}
	locs := gp.Locations
	if len(locs) == 0 {
		locs = []types.GitLocation{{Path: gp.BlobPath, Commit: gp.Commit}}
	}
	a.locs[id] = append(a.locs[id], wtLocsOf(locs)...)
	return nil
}

// of returns the deduplicated, sorted locations reported for id.
func (a *allLocs) of(id types.BlobID) []wtLoc {
	out := slices.Clone(a.locs[id])
	slices.SortFunc(out, func(x, y wtLoc) int { return strings.Compare(x.path+"\x00"+x.commit, y.path+"\x00"+y.commit) })
	return slices.Compact(out)
}

func newAllLocs() *allLocs { return &allLocs{locs: map[types.BlobID][]wtLoc{}} }

// utf16TwinFixture commits utf8Name (UTF-8) and utf16Name (UTF-16LE with BOM)
// holding the same token text in one commit. The two are different git
// objects, but the UTF-16 file's decoded text is the UTF-8 file's content, so
// both have the same BlobID. With removeUTF16, a second commit git-rm's the
// UTF-16 file, so it exists in history only. It returns the repository, the
// first commit, and the shared BlobID.
func utf16TwinFixture(t *testing.T, utf8Name, utf16Name string, removeUTF16 bool) (dir, commit string, id types.BlobID) {
	t.Helper()
	skipIfNoGit(t)
	dir = t.TempDir()
	initGitRepo(t, dir)
	text := fakeTokenLine('z')
	writeFile(t, filepath.Join(dir, utf8Name), text)
	require.NoError(t, os.WriteFile(filepath.Join(dir, utf16Name), encodeUTF16(t, text, false, true), 0o644))
	commit = commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	if removeUTF16 {
		runGit(t, dir, "rm", "-q", utf16Name)
		commitAt(t, dir, "B", "2026-01-02T00:00:00Z")
	}
	return dir, commit, types.ComputeBlobID([]byte(text))
}

// utf16TwinCase is one name order for utf16TwinFixture and the locations
// expected for the shared BlobID.
type utf16TwinCase struct {
	name            string
	utf8, utf16     string
	remove          bool
	wantPathsSorted [2]string
}

// utf16TwinCases covers both name orders. In the r3 cases the UTF-8 file sorts
// first. In the r4 cases (ENG-9178 review r4) the UTF-16 file sorts first:
// a.ps1 is UTF-16 and b.txt is UTF-8. Both orders must give each file exactly
// one location, with its commit, and no working-tree location.
var utf16TwinCases = []utf16TwinCase{
	{"both files in working tree", "a.txt", "b.ps1", false, [2]string{"a.txt", "b.ps1"}},
	{"utf16 file removed in a later commit", "a.txt", "b.ps1", true, [2]string{"a.txt", "b.ps1"}},
	{"r4 utf16 sorts first, both files in working tree", "b.txt", "a.ps1", false, [2]string{"a.ps1", "b.txt"}},
	{"r4 utf16 sorts first, utf16 file removed in a later commit", "b.txt", "a.ps1", true, [2]string{"a.ps1", "b.txt"}},
}

func (tc utf16TwinCase) want(commit string) []wtLoc {
	return []wtLoc{{tc.wantPathsSorted[0], commit, false}, {tc.wantPathsSorted[1], commit, false}}
}

// C1 (ENG-9178 review r3): a UTF-8 file and a UTF-16 file with the same text
// share one BlobID. Under the scan --git shape (git history merged with the
// working tree) every location of that BlobID is still delivered: a.txt and
// b.ps1, each with its commit. Dropping the second git object as "already
// seen" loses b.ps1, the UTF-16 copy, from the report. The case where b.ps1
// was later git-rm'd checks the historical-only location is kept too.
//
// ENG-9178 review r4: when the UTF-16 file sorts first (a.ps1 UTF-16, b.txt
// UTF-8), the working-tree pass must not take the decoded UTF-16 content for
// b.txt's HEAD object. If it does, b.txt is reported twice: once with its
// commit and again as a spurious working-tree location.
func TestCombinedEnumerator_UTF16TwinOfUTF8BlobKeepsEveryLocation(t *testing.T) {
	for _, tc := range utf16TwinCases {
		t.Run(tc.name, func(t *testing.T) {
			dir, a, id := utf16TwinFixture(t, tc.utf8, tc.utf16, tc.remove)

			got := newAllLocs()
			require.NoError(t, gitAndWorktree(dir, Config{}).Enumerate(context.Background(), got.callback))

			assert.Equal(t, tc.want(a), got.of(id),
				"locations of the shared BlobID across all callbacks")
		})
	}
}
