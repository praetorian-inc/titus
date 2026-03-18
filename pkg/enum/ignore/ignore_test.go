package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompilePatterns_DefaultPatternsMatch(t *testing.T) {
	ig, err := CompilePatterns("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	shouldIgnore := []string{
		"package-lock.json",
		"go.sum",
		"Cargo.lock",
		"node_modules/@aws-sdk/client-s3/dist/index.js",
		"lib/python3.11/site-packages/botocore/auth.py",
		"objects/pack/pack-abc123.pack",
		"botocore/data/kms/2014-11-01/examples-1.json",
		"vendor/botocore/data/s3/2006-03-01/examples-1.json",
		"styles.min.css",
		"bundle.min.js",
	}
	for _, path := range shouldIgnore {
		if !ig.MatchesPath(path) {
			t.Errorf("expected %q to be ignored by default patterns", path)
		}
	}

	shouldNotIgnore := []string{
		"main.go",
		"src/config.js",
		".env",
		"credentials.json",
		"node_modules/lodash/index.js",
		"botocore/data/kms/2014-11-01/service-2.json",
	}
	for _, path := range shouldNotIgnore {
		if ig.MatchesPath(path) {
			t.Errorf("expected %q to NOT be ignored by default patterns", path)
		}
	}
}

func TestCompilePatterns_InvalidFileReturnsError(t *testing.T) {
	_, err := CompilePatterns("/nonexistent/path/ignore.conf")
	if err == nil {
		t.Fatal("expected error for nonexistent ignore file")
	}
}

func TestCompilePatterns_CustomFileReplacesDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	ignoreFile := filepath.Join(tmpDir, "custom.conf")
	if err := os.WriteFile(ignoreFile, []byte("*.secret\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ig, err := CompilePatterns(ignoreFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Custom pattern should match
	if !ig.MatchesPath("foo.secret") {
		t.Error("expected foo.secret to be ignored by custom pattern")
	}
	// Default pattern should NOT match (custom replaces defaults)
	if ig.MatchesPath("package-lock.json") {
		t.Error("package-lock.json should not be ignored when using custom file")
	}
}
