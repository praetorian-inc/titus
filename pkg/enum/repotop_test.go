package enum

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gitToplevel is what git itself names as the top level of dir's repository.
func gitToplevel(t *testing.T, dir string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Output()
	require.NoError(t, err)
	return filepath.FromSlash(strings.TrimSuffix(string(out), "\n"))
}

func sameDirT(t *testing.T, a, b string) bool {
	t.Helper()
	sa, err := os.Stat(a)
	require.NoError(t, err)
	sb, err := os.Stat(b)
	require.NoError(t, err)
	return os.SameFile(sa, sb)
}

// ENG-9178: repoTop is "" at the top level, otherwise the top level spelled
// as the scan root was given; when that spelling is not git's top level (a
// symlink in the prefix), it is git's own top level.
func TestRepoTop(t *testing.T) {
	skipIfNoGit(t)
	ctx := context.Background()
	dir := t.TempDir()
	initGitRepo(t, dir)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub", "deeper"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "real", "sub"), 0o755))

	t.Run("top level", func(t *testing.T) {
		assert.Empty(t, repoTop(ctx, dir))
	})
	t.Run("one below top keeps the given spelling", func(t *testing.T) {
		assert.Equal(t, dir, repoTop(ctx, filepath.Join(dir, "sub")))
	})
	t.Run("two below top", func(t *testing.T) {
		assert.Equal(t, dir, repoTop(ctx, filepath.Join(dir, "sub", "deeper")))
	})
	t.Run("not a repository", func(t *testing.T) {
		assert.Empty(t, repoTop(ctx, t.TempDir()))
	})
	t.Run("symlink inside the repository", func(t *testing.T) {
		link := filepath.Join(dir, "l")
		require.NoError(t, os.Symlink(filepath.Join("real", "sub"), link))
		got := repoTop(ctx, link)
		assert.Equal(t, gitToplevel(t, link), got)
		assert.True(t, sameDirT(t, dir, got), "repoTop %q is not the repository %q", got, dir)
	})
	t.Run("symlink from outside the repository", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "link")
		require.NoError(t, os.Symlink(filepath.Join(dir, "sub"), link))
		got := repoTop(ctx, link)
		assert.Equal(t, gitToplevel(t, link), got)
		assert.True(t, sameDirT(t, dir, got), "repoTop %q is not the repository %q", got, dir)
	})
}

// ENG-9178: a --git scan rooted at repo/sub gives a committed location an
// absolute path under the repository's top level (repo/sub/c.yml, which
// exists, never repo/sub/sub/c.yml) and a working-tree location one under
// the scan root (repo/sub/x.yml).
func TestCombinedEnumerator_SubdirRootAbsolutePaths(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	secret := fakeTokenLine('k')
	writeFile(t, filepath.Join(sub, "c.yml"), secret)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	writeFile(t, filepath.Join(sub, "x.yml"), secret) // untracked copy

	r, err := runCombined(t, gitAndWorktree(sub, Config{}))
	require.NoError(t, err)
	assertGitShape(t, r)
	p := mustGitProv(t, r, types.ComputeBlobID([]byte(secret)))
	require.Equal(t, []wtLoc{{"sub/c.yml", a, false}, {"x.yml", "", true}}, wtLocsOf(p.Locations))

	occs := types.OccurrencesOf(p)
	require.Len(t, occs, 2)
	assert.Equal(t, filepath.Join(dir, "sub", "c.yml"), occs[0].AbsolutePath, "committed location")
	assert.FileExists(t, occs[0].AbsolutePath)
	assert.Equal(t, filepath.Join(sub, "x.yml"), occs[1].AbsolutePath, "working-tree location")
	assert.FileExists(t, occs[1].AbsolutePath)
}

func TestMatchLocationPath(t *testing.T) {
	locs := func(paths ...string) []types.GitLocation {
		out := make([]types.GitLocation, len(paths))
		for i, p := range paths {
			out[i] = types.GitLocation{Path: p}
		}
		return out
	}
	cases := []struct {
		name string
		locs []types.GitLocation
		path string
		want locationMatch
	}{
		{"exact", locs("a"), "a", pathExact},
		{"exact beats a cut match", locs("a\nb", "a"), "a", pathExact},
		{"walk path is the cut of a newline path", locs("a\nb"), "a", pathCutOnly},
		{"walk path with newline is never a cut", locs("a\nb\nc"), "a\nb", pathAbsent},
		{"walk path with newline matches exactly", locs("a\nb"), "a\nb", pathExact},
		{"plain prefix is not a cut", locs("ab"), "a", pathAbsent},
		{"prefix before a slash is not a cut", locs("a/b"), "a", pathAbsent},
		{"walk path longer than indexed", locs("a"), "a\nb", pathAbsent},
		{"first line differs", locs("ab\nc"), "a", pathAbsent},
		{"no locations", nil, "a", pathAbsent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, matchLocationPath(tc.locs, tc.path))
		})
	}
}

// ENG-9178: a walk path that is only the cut of an indexed newline path adds
// no location. Whether it marks the blob truncated depends on whether the
// index dropped records it cannot attribute to a blob: then the walk's path
// may be a distinct location the index lost.
func TestBlobProvenance_CutOnlyPath(t *testing.T) {
	c := strings.Repeat("1", 40)
	b := strings.Repeat("a", 40)
	clean := header(c, "s") + raw("100644", b, "A", "a\nb.yml")
	cases := []struct {
		name          string
		stream        string
		walkPath      string
		wantTruncated bool
		wantPaths     []string
	}{
		{"clean index, cut path", clean, "a", false, []string{"a\nb.yml"}},
		{"unattributed malformed drop, cut path", clean + "\n:garbage\x00g\x00", "a", true, []string{"a\nb.yml"}},
		{"unattributed drop, exact path", clean + "\n:garbage\x00g\x00", "a\nb.yml", false, []string{"a\nb.yml"}},
		{"clean index, absent path", clean, "other.yml", false, []string{"a\nb.yml", "other.yml"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idx, err := parseBlobIndex(strings.NewReader(tc.stream))
			require.NoError(t, err)
			hash := mustHash(t, b)
			require.False(t, idx.locationsTruncated(hash), "fixture: no per-blob mark")

			p := blobProvenance(blobEntry{hash: hash, path: tc.walkPath}, idx, repoIdentity{path: ".", root: "/r"})
			paths := make([]string, 0, len(p.Locations))
			for _, l := range p.Locations {
				paths = append(paths, l.Path)
			}
			assert.Equal(t, tc.wantPaths, paths)
			assert.Equal(t, tc.wantTruncated, p.LocationsTruncated)
		})
	}
}

// blobProvenance stamps the repository top level so committed paths resolve
// against it.
func TestBlobProvenance_StampsRepoTop(t *testing.T) {
	idx, err := parseBlobIndex(strings.NewReader(header(strings.Repeat("1", 40), "s") + raw("100644", strings.Repeat("a", 40), "A", "sub/c.yml")))
	require.NoError(t, err)
	p := blobProvenance(blobEntry{hash: mustHash(t, strings.Repeat("a", 40)), path: "sub/c.yml"}, idx,
		repoIdentity{path: ".", root: "/r/repo/sub", top: "/r/repo"})
	assert.Equal(t, "/r/repo/sub", p.RepoRoot)
	assert.Equal(t, "/r/repo", p.RepoTop)
}
