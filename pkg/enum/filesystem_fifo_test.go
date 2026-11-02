//go:build !windows

package enum

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Non-regular entries in the scanned tree: a FIFO with no writer blocks a
// plain open forever, and a socket cannot be read. The walk must skip both
// without opening them, in plain filesystem mode and in the --git working
// tree prewalk. These tests swap os.Stderr, so none may call t.Parallel.

const fifoSecret = "FIFO_TREE_SECRET=ghp_example\n"

// fsRun is what one enumeration reported.
type fsRun struct {
	mu    sync.Mutex
	files []string // FileProvenance paths, relative to the root
	provs map[types.BlobID]types.Provenance
}

// enumerateWithin runs e under a hard timeout. A wait is a failure: on
// timeout each FIFO in fifos is opened for writing and closed, which releases
// a reader blocked on it, so the leaked enumeration can end.
func enumerateWithin(t *testing.T, e Enumerator, root string, fifos ...string) (*fsRun, error) {
	t.Helper()
	r := &fsRun{provs: map[types.BlobID]types.Provenance{}}
	done := make(chan error, 1)
	go func() {
		done <- e.Enumerate(context.Background(), func(_ []byte, id types.BlobID, prov types.Provenance) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.provs[id] = prov
			if fp, ok := prov.(types.FileProvenance); ok {
				if rel, err := filepath.Rel(root, fp.FilePath); err == nil {
					r.files = append(r.files, filepath.ToSlash(rel))
				}
			}
			return nil
		})
	}()
	select {
	case err := <-done:
		r.mu.Lock()
		defer r.mu.Unlock()
		slices.Sort(r.files)
		return r, err
	case <-time.After(10 * time.Second):
		for _, f := range fifos {
			if w, err := os.OpenFile(f, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = w.Close()
			}
		}
		t.Fatal("enumeration still blocked after 10s (a FIFO in the tree was opened)")
		return nil, nil
	}
}

// listenUnix creates a Unix socket at name, or skips the test where it
// cannot (path length limits, sandboxes).
func listenUnix(t *testing.T, name string) {
	t.Helper()
	l, err := net.Listen("unix", name)
	if err != nil {
		t.Skipf("unix socket: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
}

// shortTempDir returns a fresh directory with a short path, so a Unix socket
// path inside it fits the platform limit (104 bytes on macOS).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// The walk reports resolved paths; compare against the same spelling.
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

// assertNoWarningFor fails if a warning on stderr names any of the entries:
// a skipped entry is skipped silently, not opened and reported as an error.
func assertNoWarningFor(t *testing.T, stderr string, names ...string) {
	t.Helper()
	for _, n := range names {
		if strings.Contains(stderr, n) {
			t.Errorf("stderr names %s, want it skipped without an open: %q", n, stderr)
		}
	}
}

// Plain filesystem mode: a FIFO and a socket next to a regular file are
// skipped without a hang or a warning, and the regular file is still read.
func TestFilesystemEnumerator_SkipsFIFOAndSocket(t *testing.T) {
	root := shortTempDir(t)
	writeFile(t, filepath.Join(root, "secret.txt"), fifoSecret)
	fifo := filepath.Join(root, "pipe")
	mkfifo(t, fifo)
	listenUnix(t, filepath.Join(root, "sock"))

	stderr := captureStderr(t)
	r, err := enumerateWithin(t, NewFilesystemEnumerator(Config{Root: root}), root, fifo)
	warn := stderr()
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if want := []string{"secret.txt"}; !slices.Equal(r.files, want) {
		t.Errorf("files = %q, want %q", r.files, want)
	}
	assertNoWarningFor(t, warn, "pipe", "sock")
}

// --git mode: the working-tree prewalk skips an untracked FIFO. The scan ends,
// the committed secret keeps its history location, and an untracked regular
// file beside the FIFO is still folded in as a working-tree location.
func TestCombinedEnumerator_WorktreeSkipsFIFO(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "config.yml"), fifoSecret)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "copy.yml"), fifoSecret)
	fifo := filepath.Join(dir, "pipe")
	mkfifo(t, fifo)

	stderr := captureStderr(t)
	r, err := enumerateWithin(t, gitAndWorktree(dir, Config{}), dir, fifo)
	warn := stderr()
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	p, ok := r.provs[types.ComputeBlobID([]byte(fifoSecret))].(types.GitProvenance)
	if !ok {
		t.Fatalf("secret provenance = %T, want types.GitProvenance", r.provs[types.ComputeBlobID([]byte(fifoSecret))])
	}
	want := []wtLoc{{"config.yml", a, false}, {"copy.yml", "", true}}
	if got := wtLocsOf(p.Locations); !slices.Equal(got, want) {
		t.Errorf("locations = %v, want %v", got, want)
	}
	assertNoWarningFor(t, warn, "pipe")
}

// FollowSymlinks: a followed link is read through, so it gets the checks a
// regular entry gets. A link to a FIFO is skipped without a hang; a dangling
// link is reported on stderr and the scan goes on; a link to a regular file
// is read under the link's path. Without FollowSymlinks a link is not read.
func TestFilesystemEnumerator_FollowedSymlinks(t *testing.T) {
	setup := func(t *testing.T) (root, fifo string) {
		root = shortTempDir(t)
		// The targets live outside the root, so only the links can reach them.
		outside := shortTempDir(t)
		writeFile(t, filepath.Join(outside, "target.txt"), fifoSecret)
		fifo = filepath.Join(outside, "pipe")
		mkfifo(t, fifo)
		for link, target := range map[string]string{
			"to-file":     filepath.Join(outside, "target.txt"),
			"to-fifo":     fifo,
			"to-nowhere":  filepath.Join(outside, "missing.txt"),
			"another.txt": "",
		} {
			if target == "" {
				writeFile(t, filepath.Join(root, link), "plain\n")
				continue
			}
			if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
				t.Fatal(err)
			}
		}
		return root, fifo
	}

	t.Run("followed", func(t *testing.T) {
		root, fifo := setup(t)
		stderr := captureStderr(t)
		r, err := enumerateWithin(t, NewFilesystemEnumerator(Config{Root: root, FollowSymlinks: true}), root, fifo)
		warn := stderr()
		if err != nil {
			t.Fatalf("Enumerate: %v", err)
		}
		if want := []string{"another.txt", "to-file"}; !slices.Equal(r.files, want) {
			t.Errorf("files = %q, want %q (the link to a regular file is read, the link to a FIFO is not)", r.files, want)
		}
		if !strings.Contains(warn, "to-nowhere") {
			t.Errorf("stderr = %q, want a warning naming the dangling link to-nowhere", warn)
		}
		assertNoWarningFor(t, warn, "to-fifo", "pipe")
	})

	t.Run("not followed", func(t *testing.T) {
		root, fifo := setup(t)
		stderr := captureStderr(t)
		r, err := enumerateWithin(t, NewFilesystemEnumerator(Config{Root: root}), root, fifo)
		warn := stderr()
		if err != nil {
			t.Fatalf("Enumerate: %v", err)
		}
		if want := []string{"another.txt"}; !slices.Equal(r.files, want) {
			t.Errorf("files = %q, want %q (links are not read)", r.files, want)
		}
		assertNoWarningFor(t, warn, "to-nowhere", "to-fifo", "to-file")
	})
}
