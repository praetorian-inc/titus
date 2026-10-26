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

// utf16TwinFixture commits a.txt (UTF-8) and b.ps1 (UTF-16LE with BOM) holding
// the same token text in one commit. The two are different git objects, but
// b.ps1's decoded text is a.txt's content, so both have the same BlobID.
// With removeUTF16, a second commit git-rm's b.ps1, so it exists in history
// only. It returns the repository, the first commit, and the shared BlobID.
func utf16TwinFixture(t *testing.T, removeUTF16 bool) (dir, commit string, id types.BlobID) {
	t.Helper()
	skipIfNoGit(t)
	dir = t.TempDir()
	initGitRepo(t, dir)
	text := fakeTokenLine('z')
	writeFile(t, filepath.Join(dir, "a.txt"), text)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.ps1"), encodeUTF16(t, text, false, true), 0o644))
	commit = commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	if removeUTF16 {
		runGit(t, dir, "rm", "-q", "b.ps1")
		commitAt(t, dir, "B", "2026-01-02T00:00:00Z")
	}
	return dir, commit, types.ComputeBlobID([]byte(text))
}

// C1 (ENG-9178 review r3): a UTF-8 file and a UTF-16 file with the same text
// share one BlobID. Under the scan --git shape (git history merged with the
// working tree) every location of that BlobID is still delivered: a.txt and
// b.ps1, each with its commit. Dropping the second git object as "already
// seen" loses b.ps1, the UTF-16 copy, from the report. The case where b.ps1
// was later git-rm'd checks the historical-only location is kept too.
func TestCombinedEnumerator_UTF16TwinOfUTF8BlobKeepsEveryLocation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remove bool
	}{
		{"both files in working tree", false},
		{"utf16 file removed in a later commit", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, a, id := utf16TwinFixture(t, tc.remove)

			got := newAllLocs()
			require.NoError(t, gitAndWorktree(dir, Config{}).Enumerate(context.Background(), got.callback))

			assert.Equal(t, []wtLoc{{"a.txt", a, false}, {"b.ps1", a, false}}, got.of(id),
				"locations of the shared BlobID across all callbacks")
		})
	}
}

// C1, history side: each history walk on its own delivers both locations of
// the shared BlobID, whether in one callback or several.
func TestGitHistory_UTF16TwinOfUTF8BlobKeepsEveryLocation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remove bool
	}{
		{"both files in working tree", false},
		{"utf16 file removed in a later commit", true},
	} {
		for name, walk := range map[string]func(*GitEnumerator, context.Context, blobCallback) error{
			"native": (*GitEnumerator).enumerateAllHistoryNative,
			"go-git": (*GitEnumerator).enumerateAllHistory,
		} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				dir, a, id := utf16TwinFixture(t, tc.remove)

				got := newAllLocs()
				require.NoError(t, walk(nativeEnum(dir), context.Background(), got.callback))

				assert.Equal(t, []wtLoc{{"a.txt", a, false}, {"b.ps1", a, false}}, got.of(id))
			})
		}
	}
}

// C3 (ENG-9178 review r3): a repository with diff.relative=true makes git log
// print paths relative to its working directory and drop changes outside it.
// A scan rooted at a subdirectory must still name history locations relative
// to the repository top level, as it does without that setting: the blob at
// sub/deep/c.yml and top.yml is reported at both, never as "deep/c.yml", and
// top.yml keeps its commit.
func TestDiffRelativeConfigKeepsRepoTopPaths(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	runGit(t, dir, "config", "diff.relative", "true")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub", "deep"), 0o755))
	secret := fakeTokenLine('y')
	writeFile(t, filepath.Join(dir, "sub", "deep", "c.yml"), secret)
	writeFile(t, filepath.Join(dir, "top.yml"), secret)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	id := types.ComputeBlobID([]byte(secret))
	root := filepath.Join(dir, "sub")
	want := []wtLoc{{"sub/deep/c.yml", a, false}, {"top.yml", a, false}}

	t.Run("native history", func(t *testing.T) {
		got := newAllLocs()
		require.NoError(t, nativeEnum(root).enumerateAllHistoryNative(context.Background(), got.callback))
		assert.Equal(t, want, got.of(id))
	})

	t.Run("scan --git shape", func(t *testing.T) {
		got := newAllLocs()
		require.NoError(t, gitAndWorktree(root, Config{}).Enumerate(context.Background(), got.callback))
		assert.Equal(t, want, got.of(id))
	})
}
