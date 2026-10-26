package types

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ENG-9178: committed location paths are relative to the repository's top
// level and working-tree paths to the scan root. When the scan root is below
// the top level (RepoTop set), each joins its own base; with RepoTop empty
// both join RepoRoot, as before.
func TestOccurrencesOf_GitAbsolutePathBaseByLocationKind(t *testing.T) {
	committed := GitLocation{Path: "sub/c.yml", Commit: &CommitMetadata{CommitID: "c1"}}
	worktree := GitLocation{Path: "x", WorkingTree: true}

	cases := []struct {
		name          string
		root, top     string
		wantCommitted string
		wantWorktree  string
	}{
		{
			name: "scan root below top level", root: "/r/repo/sub", top: "/r/repo",
			wantCommitted: filepath.Join("/r/repo", "sub/c.yml"),
			wantWorktree:  filepath.Join("/r/repo/sub", "x"),
		},
		{
			name: "scan root is top level", root: "/r/repo", top: "",
			wantCommitted: filepath.Join("/r/repo", "sub/c.yml"),
			wantWorktree:  filepath.Join("/r/repo", "x"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := OccurrencesOf(GitProvenance{
				RepoPath: ".", RepoRoot: tc.root, RepoTop: tc.top,
				Locations: []GitLocation{committed, worktree},
			})
			require.Len(t, got, 2)
			assert.Equal(t, tc.wantCommitted, got[0].AbsolutePath, "committed location")
			assert.Equal(t, tc.wantWorktree, got[1].AbsolutePath, "working-tree location")
		})
	}
}

// RepoTop never gives a host-identified repository's committed location an
// absolute path: that content still merges across folders.
func TestOccurrencesOf_GitRepoTopRemoteIdentityCommittedStaysUnrooted(t *testing.T) {
	got := OccurrencesOf(GitProvenance{
		RepoPath: "github.com/acme/api", RepoRoot: "/r/repo/sub", RepoTop: "/r/repo", RemoteIdentity: true,
		Locations: []GitLocation{
			{Path: "sub/c.yml", Commit: &CommitMetadata{CommitID: "c1"}},
			{Path: "x", WorkingTree: true},
		},
	})
	require.Len(t, got, 2)
	assert.Empty(t, got[0].AbsolutePath)
	assert.Equal(t, filepath.Join("/r/repo/sub", "x"), got[1].AbsolutePath)
}
