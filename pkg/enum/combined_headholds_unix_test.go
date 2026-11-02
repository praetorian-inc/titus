//go:build unix

package enum

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// headHoldsWithin runs m.headHolds and fails the test if it does not return
// within a few seconds, so a read that blocks (a FIFO with no writer) shows
// up as a failure instead of hanging the suite.
func headHoldsWithin(t *testing.T, m *worktreeMerge, id types.BlobID, path string) bool {
	t.Helper()
	got := make(chan bool, 1)
	go func() { got <- m.headHolds(id, path) }()
	select {
	case v := <-got:
		return v
	case <-time.After(5 * time.Second):
		require.FailNow(t, "headHolds did not return", "path %q", path)
		return false
	}
}

// ENG-9178: headHolds hashes the working-tree file only when it is a regular
// file within the scanner's size cap. A FIFO, a symlink (even to the exact
// committed content) and an over-cap file count as not held, so their
// working-tree location is kept and the check never blocks. A regular file
// whose content is HEAD's blob is held.
func TestHeadHolds_OnlyRegularFilesWithinCap(t *testing.T) {
	content := []byte(fakeTokenLine('k'))
	oid := gitObjectID(content, 40)
	// A BlobID that differs from the object id forces the content read, as
	// for a transcoded UTF-16 file or a SHA-256 repository.
	var other types.BlobID

	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, dir, path string)
		maxSize int64
		want    bool
	}{
		{
			name:  "regular file with HEAD's content is held",
			setup: func(t *testing.T, _, path string) { require.NoError(t, os.WriteFile(path, content, 0o644)) },
			want:  true,
		},
		{
			name:    "regular file within the cap is held",
			setup:   func(t *testing.T, _, path string) { require.NoError(t, os.WriteFile(path, content, 0o644)) },
			maxSize: int64(len(content)),
			want:    true,
		},
		{
			name:  "regular file with other content is not held",
			setup: func(t *testing.T, _, path string) { require.NoError(t, os.WriteFile(path, []byte("x\n"), 0o644)) },
			want:  false,
		},
		{
			name:    "file over the cap is not held",
			setup:   func(t *testing.T, _, path string) { require.NoError(t, os.WriteFile(path, content, 0o644)) },
			maxSize: int64(len(content)) - 1,
			want:    false,
		},
		{
			name: "symlink to HEAD's content is not held",
			setup: func(t *testing.T, dir, path string) {
				target := filepath.Join(dir, "target.yml")
				require.NoError(t, os.WriteFile(target, content, 0o644))
				require.NoError(t, os.Symlink(target, path))
			},
			want: false,
		},
		{
			name:  "FIFO is not held and does not block",
			setup: func(t *testing.T, _, path string) { require.NoError(t, syscall.Mkfifo(path, 0o644)) },
			want:  false,
		},
		{
			name:  "missing file is not held",
			setup: func(*testing.T, string, string) {},
			want:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir, filepath.Join(dir, "c.yml"))
			m := &worktreeMerge{
				fs:   NewFilesystemEnumerator(Config{Root: dir, MaxFileSize: tc.maxSize}),
				root: dir,
				head: map[string]string{"c.yml": oid},
			}
			assert.Equal(t, tc.want, headHoldsWithin(t, m, other, "c.yml"))
		})
	}
}

// A path HEAD does not hold is never held, whatever the file is.
func TestHeadHolds_PathNotInHead(t *testing.T) {
	dir := t.TempDir()
	content := []byte(fakeTokenLine('k'))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "c.yml"), content, 0o644))
	m := &worktreeMerge{
		fs:   NewFilesystemEnumerator(Config{Root: dir}),
		root: dir,
		head: map[string]string{"other.yml": gitObjectID(content, 40)},
	}
	assert.False(t, headHoldsWithin(t, m, types.ComputeBlobID(content), "c.yml"))
}
