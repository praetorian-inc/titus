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

// setupTestGitRepo creates a test git repository with some files.
func setupTestGitRepo(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to init git repo: %v", err)
	}

	// Configure git user
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to config git user email: %v", err)
	}

	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to config git user name: %v", err)
	}

	// Create some files
	file1 := filepath.Join(tmpDir, "file1.txt")
	if err := os.WriteFile(file1, []byte("hello from git"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	file2 := filepath.Join(tmpDir, "file2.txt")
	if err := os.WriteFile(file2, []byte("another file"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create subdirectory with file
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	subFile := filepath.Join(subDir, "nested.txt")
	if err := os.WriteFile(subFile, []byte("nested content"), 0644); err != nil {
		t.Fatalf("failed to create nested file: %v", err)
	}

	// Add and commit
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "Initial commit")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to git commit: %v", err)
	}

	return tmpDir
}

func TestGitEnumerator(t *testing.T) {
	repoPath := setupTestGitRepo(t)

	config := Config{
		Root: repoPath,
	}
	enumerator := NewGitEnumerator(config)

	var foundFiles []string
	var foundContents []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, prov.Path())
		foundContents = append(foundContents, string(content))

		// Verify blob ID
		expectedID := types.ComputeBlobID(content)
		if blobID != expectedID {
			t.Errorf("blob ID mismatch for %s: got %s, want %s", prov.Path(), blobID.Hex(), expectedID.Hex())
		}

		// Verify provenance is GitProvenance
		if prov.Kind() != "git" {
			t.Errorf("expected git provenance, got %s", prov.Kind())
		}

		// Verify git-specific fields
		gitProv, ok := prov.(types.GitProvenance)
		if !ok {
			t.Errorf("expected GitProvenance type, got %T", prov)
		}
		if gitProv.RepoPath != repoPath {
			t.Errorf("unexpected repo path: %s", gitProv.RepoPath)
		}
		if gitProv.Commit == nil {
			t.Error("commit metadata is nil")
		}
		if gitProv.Commit.AuthorEmail != "test@example.com" {
			t.Errorf("unexpected author email: %s", gitProv.Commit.AuthorEmail)
		}

		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	// Should find 3 files
	if len(foundFiles) != 3 {
		t.Errorf("expected 3 files, got %d: %v", len(foundFiles), foundFiles)
	}

	// Verify file names
	expectedFiles := map[string]bool{
		"file1.txt":       false,
		"file2.txt":       false,
		"subdir/nested.txt": false,
	}
	for _, name := range foundFiles {
		if _, ok := expectedFiles[name]; ok {
			expectedFiles[name] = true
		}
	}
	for name, found := range expectedFiles {
		if !found {
			t.Errorf("expected file not found: %s", name)
		}
	}
}

func TestGitEnumerator_BinaryFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to init git repo: %v", err)
	}

	// Configure git user
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to config git: %v", err)
	}

	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to config git: %v", err)
	}

	// Create text file
	textFile := filepath.Join(tmpDir, "text.txt")
	if err := os.WriteFile(textFile, []byte("text content"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create binary file
	binaryFile := filepath.Join(tmpDir, "binary.bin")
	binaryContent := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	if err := os.WriteFile(binaryFile, binaryContent, 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Add and commit
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "Add files")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to git commit: %v", err)
	}

	// Enumerate
	config := Config{
		Root: tmpDir,
	}
	enumerator := NewGitEnumerator(config)

	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, prov.Path())
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	// Should only find text file (binary is skipped)
	if len(foundFiles) != 1 {
		t.Errorf("expected 1 file, got %d", len(foundFiles))
	}
	if len(foundFiles) > 0 && foundFiles[0] != "text.txt" {
		t.Errorf("expected text.txt, got %s", foundFiles[0])
	}
}

func TestGitEnumerator_MaxFileSize(t *testing.T) {
	tmpDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to init git repo: %v", err)
	}

	// Configure git user
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to config git: %v", err)
	}

	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to config git: %v", err)
	}

	// Create small file
	smallFile := filepath.Join(tmpDir, "small.txt")
	if err := os.WriteFile(smallFile, []byte("small"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create large file
	largeFile := filepath.Join(tmpDir, "large.txt")
	if err := os.WriteFile(largeFile, make([]byte, 2000), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Add and commit
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "Add files")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to git commit: %v", err)
	}

	// Enumerate with size limit
	config := Config{
		Root:        tmpDir,
		MaxFileSize: 1000,
	}
	enumerator := NewGitEnumerator(config)

	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, prov.Path())
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	// Should only find small file
	if len(foundFiles) != 1 {
		t.Errorf("expected 1 file, got %d", len(foundFiles))
	}
	if len(foundFiles) > 0 && foundFiles[0] != "small.txt" {
		t.Errorf("expected small.txt, got %s", foundFiles[0])
	}
}

func TestGitEnumerator_ContextCancellation(t *testing.T) {
	repoPath := setupTestGitRepo(t)

	config := Config{
		Root: repoPath,
	}
	enumerator := NewGitEnumerator(config)

	ctx, cancel := context.WithCancel(context.Background())

	var count int
	err := enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		if count == 2 {
			cancel() // Cancel after processing 2 files
		}
		return nil
	})

	// Should get context canceled error
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}

func TestGitEnumerator_DuplicateBlobs(t *testing.T) {
	tmpDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to init git repo: %v", err)
	}

	// Configure git user
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to config git: %v", err)
	}

	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to config git: %v", err)
	}

	// Create file
	file1 := filepath.Join(tmpDir, "file1.txt")
	content := "duplicate content"
	if err := os.WriteFile(file1, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Add and commit
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "First commit")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to git commit: %v", err)
	}

	// Enumerate and track blob IDs
	config := Config{
		Root: tmpDir,
	}
	enumerator := NewGitEnumerator(config)

	blobIDs := make(map[types.BlobID]int)
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobIDs[blobID]++
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	// Verify each blob ID appears only once
	for id, count := range blobIDs {
		if count > 1 {
			t.Errorf("blob ID %s appeared %d times, expected 1", id.Hex(), count)
		}
	}
}
