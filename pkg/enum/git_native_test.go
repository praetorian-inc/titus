package enum

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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
		// Native mode now collects commit metadata via git log.
		if gitProv.Commit == nil {
			t.Fatal("expected non-nil commit metadata")
		}
		if gitProv.Commit.CommitID == "" {
			t.Error("expected non-empty commit ID")
		}
		if gitProv.Commit.CommitterTimestamp.IsZero() {
			t.Error("expected non-zero committer timestamp")
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
	var locations []string
	err := enumerator.enumerateAllHistoryNative(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		callCount++
		for _, l := range prov.(types.GitProvenance).Locations {
			locations = append(locations, l.Path)
		}
		return nil
	})

	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}

	// One callback for the shared blob, carrying both of its paths.
	if callCount != 1 {
		t.Errorf("expected callback called 1 time (deduplication), got %d", callCount)
	}
	if want := []string{"file1.txt", "file2.txt"}; !slices.Equal(locations, want) {
		t.Errorf("locations = %v, want %v", locations, want)
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
	_ = os.Remove(filepath.Join(tmpDir, "file2.txt"))
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

func TestNativeGitEnumerator_DoesNotApplyIgnorePatterns(t *testing.T) {
	skipIfNoGit(t)

	// Ignore patterns are intentionally NOT applied to git history scanning.
	// git rev-list deduplicates by blob hash and picks one representative path —
	// if that path matched an ignore pattern, we'd lose the blob entirely even
	// if it also exists at a non-ignored path. Filesystem scanning handles ignore.
	tmpDir := t.TempDir()
	initGitRepo(t, tmpDir)

	writeFile(t, filepath.Join(tmpDir, "package-lock.json"), `{"lockfileVersion": 3}`)
	writeFile(t, filepath.Join(tmpDir, "app.js"), "const x = 1")
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

	// Both files should be found — git enumerator does not filter
	if len(foundFiles) != 2 {
		t.Errorf("expected 2 files (git does not apply ignore), got %d: %v", len(foundFiles), foundFiles)
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

// nativeRun collects every callback of a native history walk, keyed by blob.
type nativeRun struct {
	calls map[types.BlobID]int
	provs map[types.BlobID]types.GitProvenance
}

func runNative(t *testing.T, e *GitEnumerator) nativeRun {
	t.Helper()
	r := nativeRun{calls: map[types.BlobID]int{}, provs: map[types.BlobID]types.GitProvenance{}}
	err := e.enumerateAllHistoryNative(context.Background(), func(_ []byte, id types.BlobID, prov types.Provenance) error {
		r.calls[id]++
		r.provs[id] = prov.(types.GitProvenance)
		return nil
	})
	if err != nil {
		t.Fatalf("enumerateAllHistoryNative: %v", err)
	}
	return r
}

func nativeEnum(root string) *GitEnumerator {
	e := NewGitEnumerator(Config{Root: root})
	e.WalkAll = true
	return e
}

// C-ONECALLBACK-1 + C-HISTPATHS-1: one blob at two paths gives exactly one
// callback whose Locations hold both paths, each with its earliest commit.
func TestNativeGitEnumerator_OneCallbackEveryLocation(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	const secret = "TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	writeFile(t, filepath.Join(dir, "config.yml"), secret)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	if err := os.MkdirAll(filepath.Join(dir, "deploy"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "deploy", "config.yml"), secret)
	b := commitAt(t, dir, "B", "2026-02-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "unrelated.txt"), "x\n")
	commitAt(t, dir, "C", "2026-03-01T00:00:00Z")

	r := runNative(t, nativeEnum(dir))
	x := types.ComputeBlobID([]byte(secret))
	if got := r.calls[x]; got != 1 {
		t.Fatalf("callbacks_for_blob_X = %d, want 1", got)
	}
	p := r.provs[x]
	want := []locWant{{"config.yml", a}, {"deploy/config.yml", b}}
	if got := locsOf(p.Locations); !slices.Equal(got, want) {
		t.Fatalf("provenance_paths = %v, want %v", got, want)
	}
	if p.BlobPath != "config.yml" || p.Commit == nil || p.Commit.CommitID != a {
		t.Errorf("primary = (%q, %v), want (config.yml, %s)", p.BlobPath, p.Commit, a)
	}
	for id, n := range r.calls {
		if n != 1 {
			t.Errorf("blob %s got %d callbacks, want 1", id.Hex(), n)
		}
	}
}

// C-HISTPATHS-2: add, delete, re-add of the same path keeps the earliest commit.
func TestNativeGitEnumerator_ReAddKeepsEarliest(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	const body = "k: v\n"
	writeFile(t, filepath.Join(dir, "a.yml"), body)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	runGit(t, dir, "rm", "-q", "a.yml")
	commitAt(t, dir, "B", "2026-02-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "a.yml"), body)
	commitAt(t, dir, "C", "2026-03-01T00:00:00Z")

	r := runNative(t, nativeEnum(dir))
	p := r.provs[types.ComputeBlobID([]byte(body))]
	want := []locWant{{"a.yml", a}}
	if got := locsOf(p.Locations); !slices.Equal(got, want) {
		t.Fatalf("locations = %v, want %v", got, want)
	}
}

// C-MODCOMMIT-1: a secret added by a modify commit is attributed to it.
func TestNativeGitEnumerator_ModifyCommitAttribution(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "config.yml"), "name: app\n")
	commitAt(t, dir, "create", "2026-01-15T00:00:00Z")
	const withToken = "name: app\nTOKEN=ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
	writeFile(t, filepath.Join(dir, "config.yml"), withToken)
	mod := commitAt(t, dir, "modify", "2026-06-15T00:00:00Z")

	r := runNative(t, nativeEnum(dir))
	p := r.provs[types.ComputeBlobID([]byte(withToken))]
	if p.BlobPath != "config.yml" || p.Commit == nil || p.Commit.CommitID != mod {
		t.Fatalf("primary = (%q, %v), want (config.yml, %s)", p.BlobPath, p.Commit, mod)
	}
	wantDate := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	if !p.Commit.CommitterTimestamp.Equal(wantDate) {
		t.Errorf("commit_date = %v, want %v", p.Commit.CommitterTimestamp, wantDate)
	}
}

// A blob the index does not know falls back to its rev-list path, no commit.
func TestNativeGitEnumerator_NoIndexEntryFallsBackToRevListPath(t *testing.T) {
	skipIfNoGit(t)
	dir := setupTestGitRepo(t)
	e := nativeEnum(dir)
	e.buildIndex = func(context.Context, string) (*blobIndex, error) { return &blobIndex{}, nil }

	r := runNative(t, e)
	if len(r.provs) != 3 {
		t.Fatalf("blobs = %d, want 3", len(r.provs))
	}
	for _, p := range r.provs {
		if len(p.Locations) != 1 || p.Locations[0].Path != p.BlobPath || p.Locations[0].Commit != nil || p.Commit != nil {
			t.Errorf("fallback provenance = %+v", p)
		}
	}
}

// SEC-12: an index failure degrades attribution, never the scan set.
func TestNativeGitEnumerator_IndexFailureKeepsAllBlobs(t *testing.T) {
	skipIfNoGit(t)
	dir := setupTestGitRepo(t)
	var warn bytes.Buffer
	e := nativeEnum(dir)
	e.warn = &warn
	e.buildIndex = func(context.Context, string) (*blobIndex, error) { return nil, errors.New("boom") }

	r := runNative(t, e)
	if len(r.provs) != 3 {
		t.Fatalf("blobs = %d, want 3", len(r.provs))
	}
	if !strings.Contains(warn.String(), "titus: git history index unavailable") || !strings.Contains(warn.String(), "boom") {
		t.Errorf("warning = %q", warn.String())
	}
}

// SEC-10: a rev-list failure cancels the index build and returns promptly.
func TestNativeGitEnumerator_RevListFailureCancelsIndex(t *testing.T) {
	skipIfNoGit(t)
	e := nativeEnum(t.TempDir()) // not a repository: rev-list fails
	var warn bytes.Buffer
	e.warn = &warn
	e.buildIndex = func(ctx context.Context, _ string) (*blobIndex, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan error, 1)
	go func() {
		done <- e.enumerateAllHistoryNative(context.Background(), func([]byte, types.BlobID, types.Provenance) error { return nil })
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("want rev-list error, got nil")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("enumeration did not return after rev-list failed")
	}
	if strings.Contains(warn.String(), "index unavailable") {
		t.Errorf("cancelled index must not warn: %q", warn.String())
	}
}

// C-NOREMOTE-1: no remote keeps the typed root and repo-relative paths.
func TestNativeGitEnumerator_NoRemoteIdentity(t *testing.T) {
	skipIfNoGit(t)
	base := t.TempDir()
	repo := filepath.Join(base, "e", "f")
	if err := os.MkdirAll(filepath.Join(repo, "g", "h"), 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepo(t, repo)
	writeFile(t, filepath.Join(repo, "g", "h", "config.yml"), "TOKEN=x\n")
	commitAt(t, repo, "A", "2026-01-01T00:00:00Z")
	t.Chdir(base)

	r := runNative(t, nativeEnum("e/f"))
	if len(r.provs) != 1 {
		t.Fatalf("blobs = %d, want 1", len(r.provs))
	}
	wantRoot, err := filepath.Abs("e/f")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.provs {
		if p.RepoPath != "e/f" || p.BlobPath != "g/h/config.yml" || p.RemoteIdentity || p.RepoRoot != wantRoot {
			t.Errorf("provenance = %+v, want repository e/f path g/h/config.yml root %s", p, wantRoot)
		}
	}
}

// SEC-3: an origin remote is normalized and never leaks credentials.
func TestNativeGitEnumerator_RemoteIdentityStripsCredentials(t *testing.T) {
	skipIfNoGit(t)
	dir := setupTestGitRepo(t)
	runGit(t, dir, "remote", "add", "origin", "https://u:secret@github.com/acme/api.git")

	r := runNative(t, nativeEnum(dir))
	if len(r.provs) == 0 {
		t.Fatal("no blobs enumerated")
	}
	for _, p := range r.provs {
		if p.RepoPath != "github.com/acme/api" || !p.RemoteIdentity {
			t.Errorf("identity = (%q, %v), want (github.com/acme/api, true)", p.RepoPath, p.RemoteIdentity)
		}
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("secret")) {
			t.Errorf("provenance leaks credentials: %s", b)
		}
	}
}

func TestTypedRepoIdentity_RedactsAndSanitizes(t *testing.T) {
	cases := map[string]string{
		"e/f":                  "e/f",
		"https://u:p@host/x/y": "https://host/x/y",
		"repo\x1b[31m":         `repo\x1b[31m`,
		"/abs/path/with space": "/abs/path/with space",
	}
	for in, want := range cases {
		if got := typedRepoIdentity(in); got != want {
			t.Errorf("typedRepoIdentity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadRevList(t *testing.T) {
	h1 := strings.Repeat("a", 40)
	h2 := strings.Repeat("b", 40)
	h3 := strings.Repeat("c", 40)
	longPath := strings.Repeat("p", 70000)
	hugePath := strings.Repeat("q", 2<<20)
	in := strings.Join([]string{
		h1,                  // commit: no path field, skipped
		h1 + " ",            // root tree: empty path, kept
		h2 + " " + longPath, // long but under the cap: kept whole
		h2 + " other",       // duplicate hash: dropped
		h3 + " " + hugePath, // over the cap: hash recovered, path dropped
		"zz bad line",
	}, "\n") + "\n"

	rl, err := parseRevList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	got := rl.blobs
	if rl.overlong != 1 {
		t.Errorf("overlong = %d, want 1", rl.overlong)
	}
	type row struct {
		hash, path string
	}
	var rows []row
	for _, b := range got {
		rows = append(rows, row{hex.EncodeToString(b.hash[:]), b.path})
	}
	want := []row{{h1, ""}, {h2, longPath}, {h3, ""}}
	if len(rows) != len(want) {
		t.Fatalf("rows = %d, want %d", len(rows), len(want))
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d: hash %s pathlen %d, want hash %s pathlen %d", i, rows[i].hash, len(rows[i].path), want[i].hash, len(want[i].path))
		}
	}
}

func TestWriteEnumWarnings_SingleOverlongLine(t *testing.T) {
	var w bytes.Buffer
	idx := &blobIndex{}
	idx.stats.overlong = 2
	writeEnumWarnings(&w, idx, 3)
	if got := strings.Count(w.String(), "over-long"); got != 1 || !strings.Contains(w.String(), "skipped 5 over-long") {
		t.Errorf("warnings = %q", w.String())
	}

	w.Reset()
	writeEnumWarnings(&w, nil, 4)
	if !strings.Contains(w.String(), "skipped 4 over-long") {
		t.Errorf("nil-index warnings = %q", w.String())
	}

	w.Reset()
	writeEnumWarnings(&w, nil, 0)
	if w.Len() != 0 {
		t.Errorf("want no warnings, got %q", w.String())
	}
}
