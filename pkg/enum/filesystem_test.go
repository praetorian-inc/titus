package enum

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func TestFilesystemEnumerator(t *testing.T) {
	// Create temp directory for test files
	tmpDir := t.TempDir()

	// Create test files
	testFile1 := filepath.Join(tmpDir, "file1.txt")
	if err := os.WriteFile(testFile1, []byte("hello world"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	testFile2 := filepath.Join(tmpDir, "file2.txt")
	if err := os.WriteFile(testFile2, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Create a subdirectory with a file
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdirectory: %v", err)
	}
	subFile := filepath.Join(subDir, "subfile.txt")
	if err := os.WriteFile(subFile, []byte("nested content"), 0644); err != nil {
		t.Fatalf("failed to create nested file: %v", err)
	}

	// Enumerate and collect results
	config := Config{
		Root:          tmpDir,
		IncludeHidden: false,
		MaxFileSize:   0,
	}
	enumerator := NewFilesystemEnumerator(config)

	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, prov.Path())
		// Verify blob ID is computed correctly
		expectedID := types.ComputeBlobID(content)
		if blobID != expectedID {
			t.Errorf("blob ID mismatch: got %s, want %s", blobID.Hex(), expectedID.Hex())
		}
		// Verify provenance is FileProvenance
		if prov.Kind() != "file" {
			t.Errorf("expected file provenance, got %s", prov.Kind())
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
}

func TestFilesystemEnumerator_HiddenFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create visible and hidden files
	visibleFile := filepath.Join(tmpDir, "visible.txt")
	if err := os.WriteFile(visibleFile, []byte("visible"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	hiddenFile := filepath.Join(tmpDir, ".hidden.txt")
	if err := os.WriteFile(hiddenFile, []byte("hidden"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Test without including hidden files
	config := Config{
		Root:          tmpDir,
		IncludeHidden: false,
	}
	enumerator := NewFilesystemEnumerator(config)

	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, filepath.Base(prov.Path()))
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	if len(foundFiles) != 1 {
		t.Errorf("expected 1 file, got %d", len(foundFiles))
	}
	if len(foundFiles) > 0 && foundFiles[0] != "visible.txt" {
		t.Errorf("expected visible.txt, got %s", foundFiles[0])
	}

	// Test with including hidden files
	config.IncludeHidden = true
	enumerator = NewFilesystemEnumerator(config)

	foundFiles = nil
	err = enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, filepath.Base(prov.Path()))
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	if len(foundFiles) != 2 {
		t.Errorf("expected 2 files, got %d", len(foundFiles))
	}
}

func TestFilesystemEnumerator_MaxFileSize(t *testing.T) {
	tmpDir := t.TempDir()

	// Create small and large files
	smallFile := filepath.Join(tmpDir, "small.txt")
	if err := os.WriteFile(smallFile, []byte("small"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	largeFile := filepath.Join(tmpDir, "large.txt")
	if err := os.WriteFile(largeFile, make([]byte, 2000), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Enumerate with size limit
	config := Config{
		Root:        tmpDir,
		MaxFileSize: 1000,
	}
	enumerator := NewFilesystemEnumerator(config)

	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, filepath.Base(prov.Path()))
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

func TestFilesystemEnumerator_BinaryFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create text file
	textFile := filepath.Join(tmpDir, "text.txt")
	if err := os.WriteFile(textFile, []byte("text content"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create binary file (with null bytes)
	binaryFile := filepath.Join(tmpDir, "binary.bin")
	binaryContent := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	if err := os.WriteFile(binaryFile, binaryContent, 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Enumerate
	config := Config{
		Root: tmpDir,
	}
	enumerator := NewFilesystemEnumerator(config)

	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, filepath.Base(prov.Path()))
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

func TestFilesystemEnumerator_Gitignore(t *testing.T) {
	tmpDir := t.TempDir()

	// Create .gitignore
	gitignorePath := filepath.Join(tmpDir, ".gitignore")
	gitignoreContent := "ignored.txt\n*.log\n"
	if err := os.WriteFile(gitignorePath, []byte(gitignoreContent), 0644); err != nil {
		t.Fatalf("failed to create .gitignore: %v", err)
	}

	// Create files
	includedFile := filepath.Join(tmpDir, "included.txt")
	if err := os.WriteFile(includedFile, []byte("included"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	ignoredFile1 := filepath.Join(tmpDir, "ignored.txt")
	if err := os.WriteFile(ignoredFile1, []byte("ignored1"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	ignoredFile2 := filepath.Join(tmpDir, "test.log")
	if err := os.WriteFile(ignoredFile2, []byte("ignored2"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Enumerate
	config := Config{
		Root:          tmpDir,
		IncludeHidden: true, // Include .gitignore itself
	}
	enumerator := NewFilesystemEnumerator(config)

	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, filepath.Base(prov.Path()))
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	// Should find .gitignore and included.txt (but not ignored files)
	if len(foundFiles) != 2 {
		t.Errorf("expected 2 files, got %d: %v", len(foundFiles), foundFiles)
	}

	foundIncluded := false
	foundGitignore := false
	for _, name := range foundFiles {
		if name == "included.txt" {
			foundIncluded = true
		}
		if name == ".gitignore" {
			foundGitignore = true
		}
	}

	if !foundIncluded {
		t.Error("included.txt not found")
	}
	if !foundGitignore {
		t.Error(".gitignore not found")
	}
}

func TestFilesystemEnumerator_CurrentDirectory(t *testing.T) {
	// Regression test: scanning "." should not skip the entire directory
	// because "." starts with a dot (isHidden should not treat it as hidden)
	tmpDir := t.TempDir()

	// Create a test file
	testFile := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(testFile, []byte("AWS_SECRET_ACCESS_KEY=test"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Change to the temp directory and scan "."
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current directory: %v", err)
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	// Enumerate using "." as root (this was the bug: it would skip everything)
	config := Config{
		Root:          ".",
		IncludeHidden: false, // The bug manifests when hidden files are NOT included
	}
	enumerator := NewFilesystemEnumerator(config)

	var foundFiles []string
	err = enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		foundFiles = append(foundFiles, filepath.Base(prov.Path()))
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	// Should find the test file even though we used "." as root
	if len(foundFiles) != 1 {
		t.Errorf("expected 1 file when scanning '.', got %d: %v", len(foundFiles), foundFiles)
	}
	if len(foundFiles) > 0 && foundFiles[0] != "secret.txt" {
		t.Errorf("expected secret.txt, got %s", foundFiles[0])
	}
}

func TestIsHidden(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{"current dir", ".", false},
		{"parent dir", "..", false},
		{"hidden file", ".hidden", true},
		{"hidden directory", ".git", true},
		{"normal file", "file.txt", false},
		{"normal directory", "src", false},
		{"dotfile", ".gitignore", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHidden(tt.filename); got != tt.want {
				t.Errorf("isHidden(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestFilesystemEnumerator_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple files
	for i := 0; i < 10; i++ {
		filename := filepath.Join(tmpDir, filepath.Join(string(rune('a'+i))+".txt"))
		if err := os.WriteFile(filename, []byte("content"), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
	}

	config := Config{
		Root: tmpDir,
	}
	enumerator := NewFilesystemEnumerator(config)

	ctx, cancel := context.WithCancel(context.Background())

	var count int
	err := enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		if count == 3 {
			cancel() // Cancel after processing 3 files
		}
		return nil
	})

	// Should get context canceled error
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}
