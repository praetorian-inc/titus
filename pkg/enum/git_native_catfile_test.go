package enum

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// fakeCatFile puts a "git" on PATH that prints out (with printf %b escapes)
// and then floods stdout forever, ignoring stdin. A caller that closes stdin
// and waits without draining or killing it hangs (M1).
func fakeCatFile(t *testing.T, out string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake git is a POSIX shell script")
	}
	bin := t.TempDir()
	script := "#!/bin/sh\nprintf '%b' \"$TITUS_FAKE_CATFILE\"\nexec yes\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TITUS_FAKE_CATFILE", out)
}

// M1: an early error in streamBlobContents returns promptly, even when git
// keeps writing to stdout and ignores the closed stdin.
func TestStreamBlobContents_EarlyErrorReturnsPromptly(t *testing.T) {
	id := strings.Repeat("a", 40)
	errStop := errors.New("stop")
	cases := []struct {
		name     string
		out      string
		callback error
		wantErr  func(error) bool
	}{
		{"malformed header", "garbage\\n", nil, func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "unexpected header")
		}},
		{"header for another id", strings.Repeat("b", 40) + " blob 5\\n", nil, func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "unexpected header")
		}},
		{"callback error", id + " blob 6\\nhello\\n", errStop, func(err error) bool {
			return errors.Is(err, errStop)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeCatFile(t, tc.out)
			rl, err := parseRevList(strings.NewReader(id + " path.env\n"))
			if err != nil || len(rl.blobs) != 1 {
				t.Fatalf("fixture: parseRevList = %d blobs, %v", len(rl.blobs), err)
			}
			// Cancelled at cleanup so a hung run cannot leak the fake git.
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			e := nativeEnum(t.TempDir())
			done := make(chan error, 1)
			go func() {
				done <- e.streamBlobContents(ctx, &rl, &blobIndex{}, repoIdentity{}, func([]byte, types.BlobID, types.Provenance) error {
					return tc.callback
				})
			}()
			select {
			case err := <-done:
				if !tc.wantErr(err) {
					t.Errorf("err = %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("streamBlobContents did not return within 10s after an early error: git was not stopped or drained")
			}
		})
	}
}

// M2: a commit whose id and subject overflow the 32-bit arena is stored with
// empty strings. It must never read back another commit's bytes.
func TestParseBlobIndex_ArenaOverflowStoresEmpty(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("needs a 64-bit address space")
	}
	if testing.Short() {
		t.Skip("reserves a 4 GiB arena (untouched pages)")
	}
	c1 := strings.Repeat("1", 40)
	c2 := strings.Repeat("2", 40)
	b1 := strings.Repeat("a", 40)
	b2 := strings.Repeat("b", 40)

	p := &indexParser{
		z:       newNulReader(strings.NewReader(header(c1, "LEAKED-SUBJECT")+raw("100644", b1, "A", "one.txt")), nulReaderBuffer, maxRecord),
		pathIDs: make(map[string]uint32),
		nameIDs: make(map[string]uint32),
		cur:     -1,
	}
	if err := p.run(); err != nil {
		t.Fatal(err)
	}
	// Grow the arena to 10 bytes below the 32-bit limit, keeping c1's
	// bytes at offset 0. cap == len, so finish does not copy it.
	big := make([]byte, math.MaxUint32-10)
	copy(big, p.x.arena)
	p.x.arena = big

	p.z = newNulReader(strings.NewReader(header(c2, "SUBJECT-PAST-THE-LIMIT")+raw("100644", b2, "A", "two.txt")), nulReaderBuffer, maxRecord)
	if err := p.run(); err != nil {
		t.Fatal(err)
	}
	idx := p.finish()

	got := idx.lookup(mustHash(t, b2))
	if len(got) != 1 || got[0].Commit == nil {
		t.Fatalf("lookup(two.txt) = %+v, want one location with commit metadata", got)
	}
	m := got[0].Commit
	if m.CommitID != "" {
		t.Errorf("CommitID = %q, want empty (overflowed), never c1's id", m.CommitID)
	}
	if m.Message != "" {
		t.Errorf("Message = %q, want empty (overflowed), never another commit's bytes", m.Message)
	}
	if first := idx.lookup(mustHash(t, b1)); len(first) != 1 || first[0].Commit.CommitID != c1 || first[0].Commit.Message != "LEAKED-SUBJECT" {
		t.Errorf("lookup(one.txt) = %+v, want c1 intact", first)
	}
}
