package enum

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCollectCommitMetadata_RenamedPath verifies that paths introduced by a
// rename are still mapped to the introducing commit. Git's log machinery
// reports `git mv old new` as a rename (`R`) rather than a delete + add, so
// filtering on `--diff-filter=A` alone misses the post-rename path and leaves
// every blob committed at that path without commit metadata. The filter must
// also include `R` (and `C` for copies).
func TestCollectCommitMetadata_RenamedPath(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)

	// Add a file at the original path.
	writeFile(t, filepath.Join(tmpDir, "old.txt"), "hello")
	gitAddCommit(t, tmpDir, "Add old.txt")

	// Rename it.
	runGit(t, tmpDir, "mv", "old.txt", "new.txt")
	runGit(t, tmpDir, "commit", "-m", "Rename to new.txt")

	// Modify the renamed file so there's a post-rename commit too.
	writeFile(t, filepath.Join(tmpDir, "new.txt"), "hello world")
	gitAddCommit(t, tmpDir, "Update new.txt")

	commitMap, err := collectCommitMetadataForRepo(context.Background(), tmpDir, true /* firstAdded */)
	if err != nil {
		t.Fatalf("collectCommitMetadataForRepo: %v", err)
	}

	if _, ok := commitMap["old.txt"]; !ok {
		t.Errorf("expected old.txt in commit map, got keys: %v", keys(commitMap))
	}
	if _, ok := commitMap["new.txt"]; !ok {
		t.Errorf("expected new.txt in commit map (rename target), got keys: %v", keys(commitMap))
	}
}

// TestCollectCommitMetadata_PlainAdd verifies the unchanged behaviour for
// regular file additions: every newly added path lands in the commit map
// and is mapped to the commit that introduced it.
func TestCollectCommitMetadata_PlainAdd(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)

	writeFile(t, filepath.Join(tmpDir, "a.txt"), "a")
	gitAddCommit(t, tmpDir, "Add a.txt")
	writeFile(t, filepath.Join(tmpDir, "b.txt"), "b")
	gitAddCommit(t, tmpDir, "Add b.txt")

	commitMap, err := collectCommitMetadataForRepo(context.Background(), tmpDir, true)
	if err != nil {
		t.Fatalf("collectCommitMetadataForRepo: %v", err)
	}

	for _, want := range []string{"a.txt", "b.txt"} {
		meta, ok := commitMap[want]
		if !ok {
			t.Errorf("expected %s in commit map, got keys: %v", want, keys(commitMap))
			continue
		}
		if meta.CommitID == "" {
			t.Errorf("%s: empty CommitID", want)
		}
		if meta.AuthorEmail == "" {
			t.Errorf("%s: empty AuthorEmail", want)
		}
		if meta.AuthorTimestamp.IsZero() {
			t.Errorf("%s: zero AuthorTimestamp", want)
		}
	}
}

func keys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// fastImportManyCommits appends n commits to refs/heads/master in one shot, so
// a test can cheaply give git log more output than an OS pipe holds.
func fastImportManyCommits(t *testing.T, dir string, n int) {
	t.Helper()

	var stream bytes.Buffer
	for i := 0; i < n; i++ {
		fmt.Fprintf(&stream,
			"commit refs/heads/master\ncommitter t <t@example.invalid> %d +0000\ndata 6\ncommit\nM 644 inline dir/file_%05d.txt\ndata 6\nhello\n\n",
			1700000000+i, i)
	}
	cmd := exec.Command("git", "fast-import", "--quiet")
	cmd.Dir = dir
	cmd.Stdin = &stream
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git fast-import: %v\n%s", err, out)
	}
	runGit(t, dir, "checkout", "-q", "master")
}

// longSubjectRepo builds a repo whose newest commit has a subject of the
// given length, behind n older commits, so the long header line is the first
// line git log emits and a large amount of output follows it.
func longSubjectRepo(t *testing.T, subjectLen, n int) string {
	t.Helper()

	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)
	fastImportManyCommits(t, tmpDir, n)

	writeFile(t, filepath.Join(tmpDir, "a.txt"), "hello")
	runGit(t, tmpDir, "add", "a.txt")
	writeFile(t, filepath.Join(tmpDir, "longmsg.txt"), strings.Repeat("x", subjectLen))
	runGit(t, tmpDir, "commit", "-q", "-F", "longmsg.txt")
	return tmpDir
}

// TestCollectCommitMetadata_LongCommitSubject verifies that a commit subject
// past bufio's 64 KiB default token limit neither hangs the collector nor
// loses the history behind it. collectCommitMetadataForRepo reads git log
// through a bufio.Scanner; a line past the limit made Scan stop without
// draining stdout, the un-read git log output then filled the pipe, and git
// blocked on write forever while cmd.Wait waited for it to exit.
func TestCollectCommitMetadata_LongCommitSubject(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := longSubjectRepo(t, 100000, 1500)

	// A deadline turns the old deadlock into a bounded failure.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	commitMap, err := collectCommitMetadataForRepo(ctx, tmpDir, true /* firstAdded */)
	if err != nil {
		t.Fatalf("collectCommitMetadataForRepo: %v", err)
	}

	meta, ok := commitMap["a.txt"]
	if !ok {
		t.Fatalf("expected a.txt in commit map, got %d keys", len(commitMap))
	}
	if len(meta.Message) != 100000 {
		t.Errorf("a.txt: message length = %d, want 100000", len(meta.Message))
	}
	if meta.CommitID == "" || meta.AuthorEmail == "" || meta.AuthorTimestamp.IsZero() {
		t.Errorf("a.txt: incomplete metadata: %+v", meta)
	}

	// The commits behind the long line must still be mapped.
	if m, ok := commitMap["dir/file_00000.txt"]; !ok {
		t.Errorf("expected dir/file_00000.txt in commit map, got %d keys", len(commitMap))
	} else if len(m.CommitID) != 40 {
		t.Errorf("dir/file_00000.txt: CommitID %q, want a 40-char hash", m.CommitID)
	}
}

// TestCollectCommitMetadata_OverlongLineStopsCleanly verifies the path past
// the scanner cap: the collector must return promptly with the scan error
// instead of deadlocking, because stdout is drained before waiting on git.
func TestCollectCommitMetadata_OverlongLineStopsCleanly(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := longSubjectRepo(t, maxGitLogLineSize+1, 1500)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	commitMap, err := collectCommitMetadataForRepo(ctx, tmpDir, true /* firstAdded */)

	if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		t.Fatalf("collectCommitMetadataForRepo deadlocked past the deadline: %v", err)
	}
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("collectCommitMetadataForRepo error = %v, want a wrapped bufio.ErrTooLong", err)
	}
	if commitMap == nil {
		t.Errorf("expected a usable (possibly empty) map, got nil")
	}
}
