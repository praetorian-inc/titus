package enum

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
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

func TestUnquoteGitPath(t *testing.T) {
	if got := unquoteGitPath(`"caf\303\251.txt"`); got != "café.txt" {
		t.Fatalf("octal path: got %q", got)
	}
	if got := unquoteGitPath(`"has\"quote.txt"`); got != "has\"quote.txt" {
		t.Fatalf("quoted path: got %q", got)
	}
	if got := unquoteGitPath("my file.txt"); got != "my file.txt" {
		t.Fatalf("plain path: got %q", got)
	}
}

func TestDisplayRef(t *testing.T) {
	cases := map[string]string{
		"refs/heads/main":             "main",
		"refs/remotes/origin/feature": "feature",
		"refs/remotes/upstream/a/b":   "a/b",
		"refs/tags/v1.2.3":            "v1.2.3",
		"HEAD":                        "",
	}
	for in, want := range cases {
		if got := displayRef(in); got != want {
			t.Errorf("displayRef(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollectBlobIntroductions(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	runGit(t, tmpDir, "init", "-b", "main")
	runGit(t, tmpDir, "config", "user.email", "test@example.com")
	runGit(t, tmpDir, "config", "user.name", "Test User")

	writeFile(t, filepath.Join(tmpDir, "qa.env"), "plain\n")
	gitAddCommit(t, tmpDir, "add qa.env")
	writeFile(t, filepath.Join(tmpDir, "notes.txt"), "unrelated\n")
	gitAddCommit(t, tmpDir, "unrelated")
	marker := "plain\ntitus-marker-not-a-secret\n"
	writeFile(t, filepath.Join(tmpDir, "qa.env"), marker)
	gitAddCommit(t, tmpDir, "add marker")
	writeFile(t, filepath.Join(tmpDir, "qa.env"), marker+"later\n")
	gitAddCommit(t, tmpDir, "later edit")

	writeFile(t, filepath.Join(tmpDir, "old.txt"), "stable-blob\n")
	gitAddCommit(t, tmpDir, "add old")
	runGit(t, tmpDir, "mv", "old.txt", "new.txt")
	gitAddCommit(t, tmpDir, "rename")
	writeFile(t, filepath.Join(tmpDir, "my file.txt"), "spaced\n")
	writeFile(t, filepath.Join(tmpDir, "has\"quote.txt"), "quoted\n")
	gitAddCommit(t, tmpDir, "odd names")

	runGit(t, tmpDir, "checkout", "-b", "feature")
	writeFile(t, filepath.Join(tmpDir, "feature.txt"), "feature-only\n")
	gitAddCommit(t, tmpDir, "on feature")
	runGit(t, tmpDir, "checkout", "main")

	intros, err := collectBlobIntroductions(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("collectBlobIntroductions: %v", err)
	}

	markerIntro := intros[gitHash(t, marker)]
	if markerIntro == nil || markerIntro.Commit == nil {
		t.Fatal("marker blob has no introduction")
	}
	if markerIntro.Commit.Message != "add marker" {
		t.Errorf("marker commit = %q, want add marker", markerIntro.Commit.Message)
	}
	if markerIntro.Path != "qa.env" {
		t.Errorf("marker path = %q", markerIntro.Path)
	}
	if markerIntro.Commit.Branch != "main" {
		t.Errorf("marker branch = %q", markerIntro.Commit.Branch)
	}
	if markerIntro.Commit.AuthorEmail != "test@example.com" {
		t.Errorf("marker author = %q", markerIntro.Commit.AuthorEmail)
	}
	if markerIntro.Commit.AuthorTimestamp.IsZero() {
		t.Error("marker author timestamp is zero")
	}

	stable := intros[gitHash(t, "stable-blob\n")]
	if stable == nil || stable.Commit == nil {
		t.Fatal("stable blob has no introduction")
	}
	if stable.Commit.Message != "add old" || stable.Path != "old.txt" {
		t.Errorf("rename kept %q at %q, want add old at old.txt", stable.Commit.Message, stable.Path)
	}

	spaced := intros[gitHash(t, "spaced\n")]
	if spaced == nil || spaced.Path != "my file.txt" {
		t.Fatalf("spaced path = %#v", spaced)
	}
	quoted := intros[gitHash(t, "quoted\n")]
	if quoted == nil || quoted.Path != "has\"quote.txt" {
		t.Fatalf("quoted path = %#v", quoted)
	}

	feature := intros[gitHash(t, "feature-only\n")]
	if feature == nil || feature.Commit == nil {
		t.Fatal("feature blob has no introduction")
	}
	if feature.Commit.Message != "on feature" || feature.Commit.Branch != "feature" || feature.Path != "feature.txt" {
		t.Errorf("feature intro = %q branch %q path %q", feature.Commit.Message, feature.Commit.Branch, feature.Path)
	}
}

func TestEnumeratorCitesIntroducingCommit(t *testing.T) {
	skipIfNoGit(t)

	tmpDir := t.TempDir()
	runGit(t, tmpDir, "init", "-b", "main")
	runGit(t, tmpDir, "config", "user.email", "test@example.com")
	runGit(t, tmpDir, "config", "user.name", "Test User")

	writeFile(t, filepath.Join(tmpDir, "qa.env"), "plain\n")
	gitAddCommit(t, tmpDir, "add qa.env")
	writeFile(t, filepath.Join(tmpDir, "notes.txt"), "unrelated\n")
	gitAddCommit(t, tmpDir, "unrelated")
	marker := "plain\ntitus-marker-not-a-secret\n"
	writeFile(t, filepath.Join(tmpDir, "qa.env"), marker)
	gitAddCommit(t, tmpDir, "add marker")
	writeFile(t, filepath.Join(tmpDir, "qa.env"), marker+"later\n")
	gitAddCommit(t, tmpDir, "later edit")

	enum := NewGitEnumerator(Config{Root: tmpDir})
	enum.WalkAll = true

	assertIntro := func(t *testing.T, prov types.Provenance, wantBranch bool) {
		t.Helper()
		gitProv, ok := prov.(types.GitProvenance)
		if !ok || gitProv.Commit == nil {
			t.Fatalf("provenance %#v", prov)
		}
		if commitSubject(gitProv.Commit.Message) != "add marker" || gitProv.BlobPath != "qa.env" {
			t.Errorf("got %q at %q", gitProv.Commit.Message, gitProv.BlobPath)
		}
		if wantBranch && gitProv.Commit.Branch != "main" {
			t.Errorf("branch = %q", gitProv.Commit.Branch)
		}
	}

	var native types.Provenance
	err := enum.enumerateAllHistoryNative(context.Background(), func(content []byte, _ types.BlobID, prov types.Provenance) error {
		if string(content) == marker {
			native = prov
		}
		return nil
	})
	if err != nil {
		t.Fatalf("native: %v", err)
	}
	assertIntro(t, native, true)

	var fallback types.Provenance
	err = enum.enumerateAllHistory(context.Background(), func(content []byte, _ types.BlobID, prov types.Provenance) error {
		if string(content) == marker {
			fallback = prov
		}
		return nil
	})
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	assertIntro(t, fallback, false)
}

func gitHash(t *testing.T, content string) string {
	t.Helper()
	cmd := exec.Command("git", "hash-object", "--stdin")
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git hash-object: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func commitSubject(message string) string {
	message = strings.TrimSpace(message)
	if i := strings.IndexByte(message, '\n'); i >= 0 {
		return message[:i]
	}
	return message
}

func keys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
