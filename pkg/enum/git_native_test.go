package enum

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// skipIfNoGit skips the test if the git binary is not available.
func skipIfNoGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
}

func TestGitBinaryAvailable(t *testing.T) {
	// This just exercises the function — result depends on environment.
	_ = gitBinaryAvailable()
}

func TestBlobIDEquivalence(t *testing.T) {
	skipIfNoGit(t)

	// Verify that the git object hash for a blob matches ComputeBlobID.
	// Git computes: SHA-1("blob {len}\0{content}") — same as ComputeBlobID.
	content := []byte("hello from blob id equivalence test")
	expected := types.ComputeBlobID(content)

	// Use git hash-object to compute the same hash.
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("git", "hash-object", tmpFile)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git hash-object: %v", err)
	}

	gitHex := string(out[:40]) // trim newline
	gitBlobID, err := types.ParseBlobID(gitHex)
	if err != nil {
		t.Fatalf("parse git hash: %v", err)
	}

	if gitBlobID != expected {
		t.Errorf("BlobID mismatch: git=%s, ComputeBlobID=%s", gitBlobID.Hex(), expected.Hex())
	}
}

func TestNativeGitEnumerator_Basic(t *testing.T) {
	skipIfNoGit(t)

	repoPath := setupTestGitRepo(t) // 3 files: file1.txt, file2.txt, subdir/nested.txt

	config := Config{Root: repoPath}
	enumerator := NewGitEnumerator(config)
	enumerator.WalkAll = true

	var foundFiles []string
	err := enumerator.enumerateAllHistoryNative(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, prov.Path())

		// Verify BlobID matches content.
		expectedID := types.ComputeBlobID(content)
		if blobID != expectedID {
			t.Errorf("BlobID mismatch for %s: got %s, want %s", prov.Path(), blobID.Hex(), expectedID.Hex())
		}

		// Verify provenance.
		if prov.Kind() != "git" {
			t.Errorf("expected git provenance, got %s", prov.Kind())
		}
		gitProv, ok := prov.(types.GitProvenance)
		if !ok {
			t.Errorf("expected GitProvenance, got %T", prov)
		}
		if gitProv.RepoPath != repoPath {
			t.Errorf("unexpected repo path: %s", gitProv.RepoPath)
		}
		// Native mode does not track commit metadata.
		if gitProv.Commit != nil {
			t.Error("expected nil commit metadata in native mode")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	if len(foundFiles) != 3 {
		t.Errorf("expected 3 files, got %d: %v", len(foundFiles), foundFiles)
	}

	expected := map[string]bool{"file1.txt": false, "file2.txt": false, "subdir/nested.txt": false}
	for _, name := range foundFiles {
		if _, ok := expected[name]; ok {
			expected[name] = true
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("expected file not found: %s", name)
		}
	}
}

func TestNativeGitEnumerator_Deduplication(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)

	// Commit 1: file1.txt with "same"
	writeFile(t, filepath.Join(tmpDir, "file1.txt"), "same")
	gitAddCommit(t, tmpDir, "Commit 1")

	// Commit 2: file2.txt with "same" content (same blob hash)
	writeFile(t, filepath.Join(tmpDir, "file2.txt"), "same")
	gitAddCommit(t, tmpDir, "Commit 2")

	config := Config{Root: tmpDir}
	enumerator := NewGitEnumerator(config)
	enumerator.WalkAll = true

	var callCount int
	blobIDs := make(map[types.BlobID]int)
	err := enumerator.enumerateAllHistoryNative(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		callCount++
		blobIDs[blobID]++
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected callback called 1 time (deduplication), got %d", callCount)
	}

	for id, count := range blobIDs {
		if count > 1 {
			t.Errorf("blob ID %s appeared %d times, expected 1", id.Hex(), count)
		}
	}
}

func TestNativeGitEnumerator_BinarySkipping(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)

	// Text file.
	writeFile(t, filepath.Join(tmpDir, "text.txt"), "text content")

	// Binary file (contains null bytes).
	if err := os.WriteFile(filepath.Join(tmpDir, "binary.bin"), []byte{0x00, 0x01, 0x02, 0x03}, 0644); err != nil {
		t.Fatal(err)
	}
	gitAddCommit(t, tmpDir, "Add files")

	config := Config{Root: tmpDir}
	enumerator := NewGitEnumerator(config)
	enumerator.WalkAll = true

	var foundFiles []string
	err := enumerator.enumerateAllHistoryNative(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, prov.Path())
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	if len(foundFiles) != 1 {
		t.Errorf("expected 1 file (binary skipped), got %d: %v", len(foundFiles), foundFiles)
	}
	if len(foundFiles) > 0 && foundFiles[0] != "text.txt" {
		t.Errorf("expected text.txt, got %s", foundFiles[0])
	}
}

func TestNativeGitEnumerator_MaxFileSize(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)

	writeFile(t, filepath.Join(tmpDir, "small.txt"), "small")

	// Large file: 2000 bytes of text.
	large := make([]byte, 2000)
	for i := range large {
		large[i] = 'A'
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "large.txt"), large, 0644); err != nil {
		t.Fatal(err)
	}
	gitAddCommit(t, tmpDir, "Add files")

	config := Config{Root: tmpDir, MaxFileSize: 1000}
	enumerator := NewGitEnumerator(config)
	enumerator.WalkAll = true

	var foundFiles []string
	err := enumerator.enumerateAllHistoryNative(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, prov.Path())
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	if len(foundFiles) != 1 {
		t.Errorf("expected 1 file (large skipped), got %d: %v", len(foundFiles), foundFiles)
	}
	if len(foundFiles) > 0 && foundFiles[0] != "small.txt" {
		t.Errorf("expected small.txt, got %s", foundFiles[0])
	}
}

func TestNativeGitEnumerator_MultipleBranches(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)

	// Main branch: main.txt
	writeFile(t, filepath.Join(tmpDir, "main.txt"), "main content")
	gitAddCommit(t, tmpDir, "Main commit")

	// Feature branch: feature.txt
	runGit(t, tmpDir, "checkout", "-b", "feature")
	writeFile(t, filepath.Join(tmpDir, "feature.txt"), "feature content")
	gitAddCommit(t, tmpDir, "Feature commit")

	// Switch back to default branch.
	cmd := exec.Command("git", "checkout", "master")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("git", "checkout", "main")
		cmd.Dir = tmpDir
		_ = cmd.Run()
	}

	config := Config{Root: tmpDir}
	enumerator := NewGitEnumerator(config)
	enumerator.WalkAll = true

	contentSet := make(map[string]bool)
	err := enumerator.enumerateAllHistoryNative(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		contentSet[string(content)] = true
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	if !contentSet["main content"] {
		t.Error("missing main branch content")
	}
	if !contentSet["feature content"] {
		t.Error("missing feature branch content")
	}
}

func TestNativeGitEnumerator_MultipleCommits(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)

	// Commit 1: file1.txt
	writeFile(t, filepath.Join(tmpDir, "file1.txt"), "content1")
	gitAddCommit(t, tmpDir, "Commit 1")

	// Commit 2: file2.txt (file1 still exists)
	writeFile(t, filepath.Join(tmpDir, "file2.txt"), "content2")
	gitAddCommit(t, tmpDir, "Commit 2")

	// Commit 3: modify file1, delete file2
	writeFile(t, filepath.Join(tmpDir, "file1.txt"), "content1-modified")
	os.Remove(filepath.Join(tmpDir, "file2.txt"))
	gitAddCommit(t, tmpDir, "Commit 3")

	config := Config{Root: tmpDir}
	enumerator := NewGitEnumerator(config)
	enumerator.WalkAll = true

	contentSet := make(map[string]bool)
	err := enumerator.enumerateAllHistoryNative(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		contentSet[string(content)] = true
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	// Should find all 3 unique blobs (even deleted file2).
	expected := []string{"content1", "content2", "content1-modified"}
	for _, c := range expected {
		if !contentSet[c] {
			t.Errorf("missing expected content: %q", c)
		}
	}
	if len(contentSet) != 3 {
		t.Errorf("expected 3 unique contents, got %d", len(contentSet))
	}
}

func TestNativeGitEnumerator_ContextCancellation(t *testing.T) {
	skipIfNoGit(t)

	repoPath := setupTestGitRepo(t)

	config := Config{Root: repoPath}
	enumerator := NewGitEnumerator(config)
	enumerator.WalkAll = true

	ctx, cancel := context.WithCancel(context.Background())

	var count int
	err := enumerator.enumerateAllHistoryNative(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		if count == 1 {
			cancel()
		}
		return nil
	})

	// Should get context canceled error (may also be wrapped).
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		// The error might come from a subprocess, so accept any error after cancel.
		t.Logf("got non-context error after cancel (acceptable): %v", err)
	}
}

func TestNativeGitEnumerator_EmptyRepo(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)

	// Empty repo with no commits — git rev-list will exit with error or empty output.
	config := Config{Root: tmpDir}
	enumerator := NewGitEnumerator(config)
	enumerator.WalkAll = true

	var count int
	err := enumerator.enumerateAllHistoryNative(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		return nil
	})

	// Either no error with 0 blobs, or a non-fatal error is acceptable.
	if err == nil && count != 0 {
		t.Errorf("expected 0 blobs from empty repo, got %d", count)
	}
}

func TestNativeGitEnumerator_DispatchFromEnumerate(t *testing.T) {
	skipIfNoGit(t)

	// Verify that Enumerate() dispatches to native path when WalkAll=true.
	repoPath := setupTestGitRepo(t)

	config := Config{Root: repoPath}
	enumerator := NewGitEnumerator(config)
	enumerator.WalkAll = true

	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, prov.Path())
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	if len(foundFiles) != 3 {
		t.Errorf("expected 3 files from dispatch, got %d: %v", len(foundFiles), foundFiles)
	}
}

// --- Test helpers ---

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test User")
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func gitAddCommit(t *testing.T, dir, msg string) {
	t.Helper()
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", msg)
}
