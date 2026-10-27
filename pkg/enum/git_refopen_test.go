//go:build !windows

package enum

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/filesystem"
)

// refFileResult is what readRefFile returned for one name.
type refFileResult struct {
	content     string
	exists, bad bool
}

// readRefWithin runs read under a hard timeout: a ref file that is a FIFO
// with no writer blocks a plain open forever, so a wait is a failure.
func readRefWithin(t *testing.T, what string, read func() ([]byte, bool, bool)) refFileResult {
	t.Helper()
	done := make(chan refFileResult, 1)
	go func() {
		b, exists, bad := read()
		done <- refFileResult{string(b), exists, bad}
	}()
	select {
	case r := <-done:
		return r
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: still blocked after 10s (a FIFO was waited on)", what)
		return refFileResult{}
	}
}

// mkfifo creates a FIFO at name, or skips the test where it cannot.
func mkfifo(t *testing.T, name string) {
	t.Helper()
	if err := syscall.Mkfifo(name, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
}

// SF-1: the two callers of openRegularRefFile, the host filesystem one
// (os.Lstat and osOpenRef, used for HEAD files and packed-refs) and the
// billy chroot one go-git's storage hands out (used for other worktrees'
// HEADs), give the same answer for every kind of entry: a regular file is
// read, a missing one is not there, and a symlink, a FIFO, a symlink to a
// FIFO or a directory is bad, without waiting on the FIFO.
func TestOpenRegularRefFile_BothCallersAgree(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	wt := filepath.Join(dir, ".git", "worktrees", "w")
	if err := os.MkdirAll(wt, 0o755); err != nil {
		t.Fatal(err)
	}
	const head = "0123456789abcdef0123456789abcdef01234567\n"
	writeFile(t, filepath.Join(wt, "HEAD"), head)
	writeFile(t, filepath.Join(dir, "outside"), head)
	if err := os.Symlink(filepath.Join(dir, "outside"), filepath.Join(wt, "LINK")); err != nil {
		t.Fatal(err)
	}
	mkfifo(t, filepath.Join(wt, "FIFO"))
	if err := os.Symlink("FIFO", filepath.Join(wt, "FIFOLINK")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(wt, "DIR"), 0o755); err != nil {
		t.Fatal(err)
	}

	repo, err := git.PlainOpen(dir)
	if err != nil {
		t.Fatal(err)
	}
	wfs, err := repo.Storer.(*filesystem.Storage).Filesystem().Chroot("worktrees")
	if err != nil {
		t.Fatal(err)
	}
	wopen := func(n string, flag int) (io.ReadCloser, error) { return wfs.OpenFile(n, flag, 0) }

	want := map[string]refFileResult{
		"HEAD":     {content: head, exists: true},
		"GONE":     {},
		"LINK":     {exists: true, bad: true},
		"FIFO":     {exists: true, bad: true},
		"FIFOLINK": {exists: true, bad: true},
		"DIR":      {exists: true, bad: true},
	}
	for name, w := range want {
		t.Run(name, func(t *testing.T) {
			host := readRefWithin(t, "host "+name, func() ([]byte, bool, bool) {
				return readRefFile(os.Lstat, osOpenRef, filepath.Join(wt, name))
			})
			chroot := readRefWithin(t, "chroot "+name, func() ([]byte, bool, bool) {
				return readRefFile(wfs.Lstat, wopen, path.Join("w", name))
			})
			if host != w {
				t.Errorf("host caller: %+v, want %+v", host, w)
			}
			if chroot != w {
				t.Errorf("billy chroot caller: %+v, want %+v", chroot, w)
			}
		})
	}
}

// R8-1: lookupPackedRef classifies a packed-refs lookup the way git does.
// A missing file or a missing name is an unborn ref (neither found nor
// bad). A file that cannot be read, a symlink, a FIFO, or a line for the
// name whose id is not an object id of this repository's width is bad: git
// would use the ref, and it is not read here. A FIFO must not be waited on.
func TestLookupPackedRef(t *testing.T) {
	const (
		id     = "0123456789abcdef0123456789abcdef01234567"
		header = "# pack-refs with: peeled fully-peeled sorted \n"
		name   = "refs/heads/target"
	)
	sha256ID := strings.Repeat("ab", 32)
	type want struct{ found, bad bool }
	cases := []struct {
		name  string
		setup func(t *testing.T, common string)
		want  want
	}{
		{"missing file", func(t *testing.T, common string) {}, want{}},
		{"match", func(t *testing.T, common string) {
			writeFile(t, filepath.Join(common, "packed-refs"), header+id+" refs/heads/other\n"+id+" "+name+"\n")
		}, want{found: true}},
		{"name absent", func(t *testing.T, common string) {
			writeFile(t, filepath.Join(common, "packed-refs"), header+id+" refs/heads/other\n")
		}, want{}},
		{"bad line for another name", func(t *testing.T, common string) {
			writeFile(t, filepath.Join(common, "packed-refs"), header+"zz refs/heads/other\n"+id+" "+name+"\n")
		}, want{found: true}},
		{"matching line not an id", func(t *testing.T, common string) {
			writeFile(t, filepath.Join(common, "packed-refs"), header+"not-an-object-id-at-all-but-forty-chars "+name+"\n")
		}, want{bad: true}},
		{"matching line wrong width", func(t *testing.T, common string) {
			writeFile(t, filepath.Join(common, "packed-refs"), header+sha256ID+" "+name+"\n")
		}, want{bad: true}},
		{"FIFO", func(t *testing.T, common string) {
			mkfifo(t, filepath.Join(common, "packed-refs"))
		}, want{bad: true}},
		{"symlink", func(t *testing.T, common string) {
			real := filepath.Join(t.TempDir(), "packed-refs")
			writeFile(t, real, header+id+" "+name+"\n")
			if err := os.Symlink(real, filepath.Join(common, "packed-refs")); err != nil {
				t.Fatal(err)
			}
		}, want{bad: true}},
		{"directory", func(t *testing.T, common string) {
			if err := os.Mkdir(filepath.Join(common, "packed-refs"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, want{bad: true}},
		{"unreadable", func(t *testing.T, common string) {
			if os.Geteuid() == 0 {
				t.Skip("root reads a mode-000 file")
			}
			p := filepath.Join(common, "packed-refs")
			writeFile(t, p, header+id+" "+name+"\n")
			if err := os.Chmod(p, 0); err != nil {
				t.Fatal(err)
			}
		}, want{bad: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			common := t.TempDir()
			c.setup(t, common)
			type res struct {
				h          plumbing.Hash
				found, bad bool
			}
			done := make(chan res, 1)
			go func() {
				h, found, bad := lookupPackedRef(common, name)
				done <- res{h, found, bad}
			}()
			var r res
			select {
			case r = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("lookupPackedRef still blocked after 10s (a FIFO was waited on)")
			}
			if r.found != c.want.found || r.bad != c.want.bad {
				t.Errorf("lookupPackedRef = found %v bad %v, want found %v bad %v", r.found, r.bad, c.want.found, c.want.bad)
			}
			if r.found && r.h != plumbing.NewHash(id) {
				t.Errorf("lookupPackedRef hash = %s, want %s", r.h, id)
			}
		})
	}
}
