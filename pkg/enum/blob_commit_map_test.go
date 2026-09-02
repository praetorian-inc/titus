package enum

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func TestBlobCommitMap_ModifiedFileAttribution(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)

	// Commit 1: create file with innocent content.
	writeFile(t, filepath.Join(tmpDir, "config.py"), "DATABASE_URL = 'localhost'")
	gitAddCommit(t, tmpDir, "Initial config")

	// Commit 2: modify file to introduce a secret.
	writeFile(t, filepath.Join(tmpDir, "config.py"), "DATABASE_URL = 'localhost'\nAWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'")
	gitAddCommit(t, tmpDir, "Add AWS key")

	commits := gitLogHashes(t, tmpDir)
	if len(commits) < 2 {
		t.Fatalf("expected 2 commits, got %d", len(commits))
	}
	secretCommit := commits[0]  // newest — "Add AWS key"
	initialCommit := commits[1] // oldest — "Initial config"

	blobMap, err := collectBlobCommitMap(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("collectBlobCommitMap: %v", err)
	}

	initialContent := []byte("DATABASE_URL = 'localhost'")
	secretContent := []byte("DATABASE_URL = 'localhost'\nAWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'")
	initialBlobID := types.ComputeBlobID(initialContent)
	secretBlobID := types.ComputeBlobID(secretContent)

	if meta, ok := blobMap[initialBlobID.Hex()]; !ok {
		t.Error("initial blob not found in commit map")
	} else if meta.CommitID != initialCommit {
		t.Errorf("initial blob: got commit %s, want %s", meta.CommitID, initialCommit)
	}

	if meta, ok := blobMap[secretBlobID.Hex()]; !ok {
		t.Error("secret blob not found in commit map")
	} else {
		if meta.CommitID == initialCommit {
			t.Errorf("secret blob incorrectly attributed to initial commit %s (the --diff-filter=A bug)", initialCommit)
		}
		if meta.CommitID != secretCommit {
			t.Errorf("secret blob: got commit %s, want %s", meta.CommitID, secretCommit)
		}
	}
}

func TestBlobCommitMap_RenamedFile(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)

	content := "secret = 'hunter2'"
	writeFile(t, filepath.Join(tmpDir, "old_name.py"), content)
	gitAddCommit(t, tmpDir, "Add file")

	runGit(t, tmpDir, "mv", "old_name.py", "new_name.py")
	gitAddCommit(t, tmpDir, "Rename file")

	commits := gitLogHashes(t, tmpDir)
	originalCommit := commits[1]

	blobMap, err := collectBlobCommitMap(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("collectBlobCommitMap: %v", err)
	}

	blobID := types.ComputeBlobID([]byte(content))
	meta, ok := blobMap[blobID.Hex()]
	if !ok {
		t.Fatal("blob not found in commit map")
	}
	if meta.CommitID != originalCommit {
		t.Errorf("renamed file blob: got commit %s, want original %s", meta.CommitID, originalCommit)
	}
}

func TestBlobCommitMap_DeletedAndReadded(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)

	content := "password = 'supersecret'"
	writeFile(t, filepath.Join(tmpDir, "creds.txt"), content)
	gitAddCommit(t, tmpDir, "Add creds")

	if err := os.Remove(filepath.Join(tmpDir, "creds.txt")); err != nil {
		t.Fatalf("remove creds.txt: %v", err)
	}
	gitAddCommit(t, tmpDir, "Delete creds")

	writeFile(t, filepath.Join(tmpDir, "creds.txt"), content)
	gitAddCommit(t, tmpDir, "Re-add creds")

	commits := gitLogHashes(t, tmpDir)
	originalCommit := commits[2]

	blobMap, err := collectBlobCommitMap(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("collectBlobCommitMap: %v", err)
	}

	blobID := types.ComputeBlobID([]byte(content))
	meta, ok := blobMap[blobID.Hex()]
	if !ok {
		t.Fatal("blob not found in commit map")
	}
	if meta.CommitID != originalCommit {
		t.Errorf("got commit %s, want original %s", meta.CommitID, originalCommit)
	}
}

func TestNativeEnumerator_ModifiedFileCommitAttribution(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)

	writeFile(t, filepath.Join(tmpDir, "app.py"), "print('hello')")
	gitAddCommit(t, tmpDir, "Initial app")

	secretContent := "print('hello')\nAPI_KEY = 'sk-secret-key-12345'"
	writeFile(t, filepath.Join(tmpDir, "app.py"), secretContent)
	gitAddCommit(t, tmpDir, "Add API key")

	commits := gitLogHashes(t, tmpDir)
	secretCommit := commits[0]

	config := Config{Root: tmpDir}
	enumerator := NewGitEnumerator(config)
	enumerator.WalkAll = true

	var found bool
	err := enumerator.enumerateAllHistoryNative(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		if string(content) == secretContent {
			found = true
			gp := prov.(types.GitProvenance)
			if gp.Commit == nil {
				t.Fatal("expected non-nil commit for secret blob")
			}
			if gp.Commit.CommitID != secretCommit {
				t.Errorf("secret blob attributed to %s (%s), want %s",
					gp.Commit.CommitID, gp.Commit.Message, secretCommit)
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}
	if !found {
		t.Error("secret blob not found in enumeration")
	}
}

func gitLogHashes(t *testing.T, dir string) []string {
	t.Helper()
	cmd := exec.Command("git", "log", "--format=%H")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git log: %v", err)
	}
	var hashes []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			hashes = append(hashes, line)
		}
	}
	return hashes
}
