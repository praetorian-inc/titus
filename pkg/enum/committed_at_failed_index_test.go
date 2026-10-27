//go:build !windows

package enum

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// An index that could not be built marks every blob and has no location, so
// committedAt must answer without reading the file. A FIFO with no writer
// blocks os.ReadFile forever: a read shows up as a timeout.
func TestCommittedAt_FailedIndexDoesNotReadFile(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	type result struct {
		commit *types.CommitMetadata
		marked bool
	}
	done := make(chan result, 1)
	go func() {
		c, m := committedAt(unavailableIndex(), types.ComputeBlobID([]byte("x")), fifo, "fifo")
		done <- result{c, m}
	}()
	select {
	case r := <-done:
		if !r.marked || r.commit != nil {
			t.Errorf("committedAt = (%v, %v), want (nil, true)", r.commit, r.marked)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("committedAt read the file although the index could not be built")
	}
}
