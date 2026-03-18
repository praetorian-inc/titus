package enum

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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
		Root:        tmpDir,
		MaxFileSize: 0,
	}
	enumerator := NewFilesystemEnumerator(config)

	var mu sync.Mutex
	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
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

	var mu sync.Mutex
	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
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

	var mu sync.Mutex
	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
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

func TestFilesystemEnumerator_GitignoreNotRespected(t *testing.T) {
	tmpDir := t.TempDir()

	// Create .gitignore that would exclude secret.txt
	gitignorePath := filepath.Join(tmpDir, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte("secret.txt\n"), 0644); err != nil {
		t.Fatalf("failed to create .gitignore: %v", err)
	}

	// Create files
	if err := os.WriteFile(filepath.Join(tmpDir, "secret.txt"), []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "public.txt"), []byte("public"), 0644); err != nil {
		t.Fatal(err)
	}

	config := Config{
		Root: tmpDir,
	}
	enumerator := NewFilesystemEnumerator(config)

	var mu sync.Mutex
	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
		foundFiles = append(foundFiles, filepath.Base(prov.Path()))
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	// A secrets scanner should NOT respect .gitignore — secret.txt must be found
	foundSet := make(map[string]bool)
	for _, f := range foundFiles {
		foundSet[f] = true
	}
	if !foundSet["secret.txt"] {
		t.Error("secret.txt should be found (secrets scanner must not respect .gitignore)")
	}
	if !foundSet["public.txt"] {
		t.Error("public.txt should be found")
	}
}

func TestFilesystemEnumerator_IgnorePatterns(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files that should be ignored by default patterns
	nodeDir := filepath.Join(tmpDir, "node_modules", "@aws-sdk")
	if err := os.MkdirAll(nodeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "secret.txt"), []byte("aws key"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a lockfile that should be ignored
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a file that should NOT be ignored
	if err := os.WriteFile(filepath.Join(tmpDir, "app.js"), []byte("const x = 1"), 0644); err != nil {
		t.Fatal(err)
	}

	// Enumerate with default ignore (empty IgnoreFile = use defaults)
	config := Config{
		Root: tmpDir,
	}
	enumerator := NewFilesystemEnumerator(config)

	var mu sync.Mutex
	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
		relPath, _ := filepath.Rel(tmpDir, prov.Path())
		foundFiles = append(foundFiles, relPath)
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	if len(foundFiles) != 1 {
		t.Errorf("expected 1 file, got %d: %v", len(foundFiles), foundFiles)
	}
	if len(foundFiles) > 0 && foundFiles[0] != "app.js" {
		t.Errorf("expected app.js, got %s", foundFiles[0])
	}
}

func TestFilesystemEnumerator_CustomIgnoreFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create custom ignore file
	ignoreFile := filepath.Join(tmpDir, "my-ignore.conf")
	if err := os.WriteFile(ignoreFile, []byte("secret.txt\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create files
	if err := os.WriteFile(filepath.Join(tmpDir, "secret.txt"), []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "public.txt"), []byte("public"), 0644); err != nil {
		t.Fatal(err)
	}
	// Also create a lockfile — should NOT be ignored since custom file replaces defaults
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	config := Config{
		Root:       tmpDir,
		IgnoreFile: ignoreFile,
	}
	enumerator := NewFilesystemEnumerator(config)

	var mu sync.Mutex
	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
		foundFiles = append(foundFiles, filepath.Base(prov.Path()))
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	foundSet := make(map[string]bool)
	for _, f := range foundFiles {
		foundSet[f] = true
	}
	if foundSet["secret.txt"] {
		t.Error("secret.txt should have been ignored")
	}
	if !foundSet["public.txt"] {
		t.Error("public.txt should have been found")
	}
	if !foundSet["package-lock.json"] {
		t.Error("package-lock.json should not be ignored with custom ignore file")
	}
}

func TestFilesystemEnumerator_DevNullIgnoreFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a lockfile that default patterns would ignore
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "app.js"), []byte("const x = 1"), 0644); err != nil {
		t.Fatal(err)
	}

	config := Config{
		Root:       tmpDir,
		IgnoreFile: "/dev/null",
	}
	enumerator := NewFilesystemEnumerator(config)

	var mu sync.Mutex
	var foundFiles []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
		foundFiles = append(foundFiles, filepath.Base(prov.Path()))
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	if len(foundFiles) != 2 {
		t.Errorf("expected 2 files (nothing ignored), got %d: %v", len(foundFiles), foundFiles)
	}
}

func TestFilesystemEnumerator_CurrentDirectory(t *testing.T) {
	// Regression test: scanning "." should not skip the entire directory
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
		Root: ".",
	}
	enumerator := NewFilesystemEnumerator(config)

	var mu sync.Mutex
	var foundFiles []string
	err = enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
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

	var count atomic.Int32
	err := enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		n := count.Add(1)
		if n == 3 {
			cancel() // Cancel after processing 3 files
		}
		return nil
	})

	// Should get context canceled error
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}
