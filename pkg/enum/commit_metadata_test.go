package enum

import (
	"context"
	"path/filepath"
	"testing"
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
