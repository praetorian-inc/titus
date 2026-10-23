package enum

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// --- fixture helpers -------------------------------------------------------

// commitAt stages everything and commits with fixed author and committer
// dates, returning the full commit id.
func commitAt(t *testing.T, dir, msg, date string, extra ...string) string {
	t.Helper()
	runGit(t, dir, "add", "-A")
	args := []string{"commit", "-q", "--allow-empty", "--no-gpg-sign"}
	if msg != "" {
		args = append(args, "-m", msg)
	}
	runGitEnv(t, dir, []string{"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_DATE=" + date}, append(args, extra...)...)
	return gitOutput(t, dir, "rev-parse", "HEAD")
}

func runGitEnv(t *testing.T, dir string, env []string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return gitInput(t, dir, nil, args...)
}

func gitInput(t *testing.T, dir string, stdin []byte, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

func hashObjectLiterally(t *testing.T, dir, kind, body string) string {
	t.Helper()
	return gitInput(t, dir, []byte(body), "hash-object", "-t", kind, "-w", "--literally", "--stdin")
}

func hashBlob(t *testing.T, dir, content string) string {
	t.Helper()
	return gitInput(t, dir, []byte(content), "hash-object", "-w", "--stdin")
}

func contentHash(content string) [20]byte {
	return [20]byte(types.ComputeBlobID([]byte(content)))
}

func mustHash(t *testing.T, s string) [20]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 20 {
		t.Fatalf("bad hash %q: %v", s, err)
	}
	return [20]byte(b)
}

type locWant struct {
	path   string
	commit string
}

func locsOf(locs []types.GitLocation) []locWant {
	out := make([]locWant, 0, len(locs))
	for _, l := range locs {
		w := locWant{path: l.Path}
		if l.Commit != nil {
			w.commit = l.Commit.CommitID
		}
		out = append(out, w)
	}
	return out
}

func mustBuild(t *testing.T, dir string) *blobIndex {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	idx, err := buildBlobIndex(ctx, dir)
	if err != nil {
		t.Fatalf("buildBlobIndex: %v", err)
	}
	return idx
}

// allPairs flattens the index into "hash path" strings for exact set checks.
func allPairs(idx *blobIndex) []string {
	var out []string
	for _, p := range idx.pairs {
		out = append(out, hex.EncodeToString(p.hash[:])+" "+idx.paths[p.path])
	}
	return out
}

// --- outcome-plan cases -----------------------------------------------------

// C-MODCOMMIT-1: a secret added by a later modify commit is attributed to the
// modify commit, not to the commit that created the file.
func TestBuildBlobIndex_ModifyCommitAttribution(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)

	writeFile(t, filepath.Join(dir, "config.yml"), "name: billing\n")
	created := commitAt(t, dir, "add config", "2026-01-15T12:00:00Z")
	writeFile(t, filepath.Join(dir, "config.yml"), "name: billing\ntoken: TOKEN\n")
	modified := commitAt(t, dir, "add token", "2026-06-15T12:00:00Z")

	got := mustBuild(t, dir).lookup(contentHash("name: billing\ntoken: TOKEN\n"))
	if len(got) != 1 {
		t.Fatalf("lookup = %+v, want exactly one location", got)
	}
	if got[0].Path != "config.yml" {
		t.Errorf("path = %q, want %q", got[0].Path, "config.yml")
	}
	if got[0].Commit == nil || got[0].Commit.CommitID != modified {
		t.Fatalf("commit = %+v, want modify commit %s (not create commit %s)", got[0].Commit, modified, created)
	}
	if d := got[0].Commit.CommitterTimestamp.UTC().Format("2006-01-02"); d != "2026-06-15" {
		t.Errorf("commit_date = %q, want %q", d, "2026-06-15")
	}
}

// C-HISTPATHS-1: the same blob at two paths yields both pairs, each with its
// own earliest commit.
func TestBuildBlobIndex_SameBlobTwoPaths(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)

	writeFile(t, filepath.Join(dir, "config.yml"), "TOKEN\n")
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	if err := os.MkdirAll(filepath.Join(dir, "deploy"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "deploy", "config.yml"), "TOKEN\n")
	b := commitAt(t, dir, "B", "2026-02-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "unrelated.txt"), "x\n")
	commitAt(t, dir, "C", "2026-03-01T00:00:00Z")

	got := locsOf(mustBuild(t, dir).lookup(contentHash("TOKEN\n")))
	want := []locWant{{"config.yml", a}, {"deploy/config.yml", b}}
	if !slices.Equal(got, want) {
		t.Fatalf("locations = %+v, want %+v", got, want)
	}
}

// C-HISTPATHS-2: a blob deleted and re-added at the same path keeps the
// earliest commit.
func TestBuildBlobIndex_ReAddKeepsEarliest(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)

	writeFile(t, filepath.Join(dir, "a.yml"), "TOKEN\n")
	writeFile(t, filepath.Join(dir, "keep.txt"), "keep\n")
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	if err := os.Remove(filepath.Join(dir, "a.yml")); err != nil {
		t.Fatal(err)
	}
	commitAt(t, dir, "B", "2026-02-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "a.yml"), "TOKEN\n")
	commitAt(t, dir, "C", "2026-03-01T00:00:00Z")

	got := locsOf(mustBuild(t, dir).lookup(contentHash("TOKEN\n")))
	want := []locWant{{"a.yml", a}}
	if !slices.Equal(got, want) {
		t.Fatalf("locations = %+v, want %+v", got, want)
	}
}

// --- fixture coverage ------------------------------------------------------

// A merged-in branch's blob is attributed to its own (earlier) branch commit,
// and a blob that exists only in the merge commit (an evil merge) is
// attributed to the merge through the first-parent diff.
func TestBuildBlobIndex_Merge(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)

	writeFile(t, filepath.Join(dir, "base.txt"), "base\n")
	commitAt(t, dir, "base", "2026-01-01T00:00:00Z")
	mainBranch := gitOutput(t, dir, "rev-parse", "--abbrev-ref", "HEAD")

	runGit(t, dir, "checkout", "-q", "-b", "feature")
	writeFile(t, filepath.Join(dir, "feature.txt"), "feature secret\n")
	featureCommit := commitAt(t, dir, "feature", "2026-02-01T00:00:00Z")

	runGit(t, dir, "checkout", "-q", mainBranch)
	writeFile(t, filepath.Join(dir, "main.txt"), "main\n")
	commitAt(t, dir, "main work", "2026-02-02T00:00:00Z")

	runGitEnv(t, dir, []string{"GIT_AUTHOR_DATE=2026-03-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-03-01T00:00:00Z"},
		"merge", "-q", "--no-ff", "--no-commit", "feature")
	writeFile(t, filepath.Join(dir, "evil.txt"), "only in merge\n")
	mergeCommit := commitAt(t, dir, "merge feature", "2026-03-01T00:00:00Z")

	idx := mustBuild(t, dir)
	if got, want := locsOf(idx.lookup(contentHash("feature secret\n"))), []locWant{{"feature.txt", featureCommit}}; !slices.Equal(got, want) {
		t.Errorf("feature blob = %+v, want %+v", got, want)
	}
	if got, want := locsOf(idx.lookup(contentHash("only in merge\n"))), []locWant{{"evil.txt", mergeCommit}}; !slices.Equal(got, want) {
		t.Errorf("merge-only blob = %+v, want %+v", got, want)
	}
}

// An empty commit between two real ones does not desynchronize the parser.
func TestBuildBlobIndex_EmptyCommit(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)

	writeFile(t, filepath.Join(dir, "one.txt"), "one\n")
	one := commitAt(t, dir, "one", "2026-01-01T00:00:00Z")
	commitAt(t, dir, "empty", "2026-01-02T00:00:00Z")
	writeFile(t, filepath.Join(dir, "two.txt"), "two\n")
	two := commitAt(t, dir, "two", "2026-01-03T00:00:00Z")

	idx := mustBuild(t, dir)
	if got, want := locsOf(idx.lookup(contentHash("one\n"))), []locWant{{"one.txt", one}}; !slices.Equal(got, want) {
		t.Errorf("one = %+v, want %+v", got, want)
	}
	if got, want := locsOf(idx.lookup(contentHash("two\n"))), []locWant{{"two.txt", two}}; !slices.Equal(got, want) {
		t.Errorf("two = %+v, want %+v", got, want)
	}
	if idx.stats.malformed != 0 {
		t.Errorf("malformed = %d, want 0", idx.stats.malformed)
	}
}

// A unicode, space-containing path matches rev-list's raw path byte for byte,
// even when the repository sets core.quotePath=false.
func TestBuildBlobIndex_UnicodePathMatchesRevList(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	runGit(t, dir, "config", "core.quotePath", "false")

	sub := filepath.Join(dir, "dir with space")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(sub, "café ü.txt"), "unicode secret\n")
	commitAt(t, dir, "unicode", "2026-01-01T00:00:00Z")

	h := contentHash("unicode secret\n")
	revListPath := ""
	for line := range strings.SplitSeq(gitOutput(t, dir, "rev-list", "--all", "--objects"), "\n") {
		if id, p, ok := strings.Cut(line, " "); ok && id == hex.EncodeToString(h[:]) {
			revListPath = p
		}
	}
	if revListPath != "dir with space/café ü.txt" {
		t.Fatalf("rev-list path = %q", revListPath)
	}

	got := mustBuild(t, dir).lookup(h)
	if len(got) != 1 || got[0].Path != revListPath {
		t.Fatalf("lookup = %+v, want path %q (rev-list, byte for byte)", got, revListPath)
	}
}

// A 100 KB subject line is handled: the commit keeps its full subject and its
// blobs keep their location.
func TestBuildBlobIndex_LongSubject(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)

	subject := strings.Repeat("s", 100*1024)
	msgFile := filepath.Join(t.TempDir(), "msg")
	if err := os.WriteFile(msgFile, []byte(subject+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "a.txt"), "after long subject\n")
	c := commitAt(t, dir, "", "2026-01-01T00:00:00Z", "-F", msgFile)

	got := mustBuild(t, dir).lookup(contentHash("after long subject\n"))
	if len(got) != 1 || got[0].Commit == nil || got[0].Commit.CommitID != c {
		t.Fatalf("lookup = %+v, want one location at %s", locsOf(got), c)
	}
	if got[0].Commit.Message != subject {
		t.Errorf("subject length = %d, want %d", len(got[0].Commit.Message), len(subject))
	}
}

// A submodule (gitlink, mode 160000) entry is skipped; a regular file in the
// same commit is kept.
func TestBuildBlobIndex_SkipsSubmodule(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)

	gitlink := "1234567890123456789012345678901234567890"
	runGit(t, dir, "update-index", "--add", "--cacheinfo", "160000,"+gitlink+",vendor/sub")
	writeFile(t, filepath.Join(dir, "a.txt"), "with submodule\n")
	commitAt(t, dir, "submodule", "2026-01-01T00:00:00Z")

	idx := mustBuild(t, dir)
	if got := idx.lookup(mustHash(t, gitlink)); len(got) != 0 {
		t.Errorf("submodule gitlink indexed: %+v", got)
	}
	if got := idx.lookup(contentHash("with submodule\n")); len(got) != 1 || got[0].Path != "a.txt" {
		t.Errorf("regular file = %+v, want a.txt", got)
	}
	if len(idx.pairs) != 1 {
		t.Errorf("pairs = %q, want only a.txt", allPairs(idx))
	}
}

// SEC-8: hostile path names are parsed by NUL, never C-unquoted, and a path
// crafted to look like a raw record produces no location of its own.
func TestBuildBlobIndex_HostilePaths(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	runGit(t, dir, "config", "core.quotePath", "false")

	zero := strings.Repeat("0", 40)
	names := []string{
		"a\nb.yml",
		`q"u\o.yml`,
		"x\x1b[31mRED.yml",
		"‮evil.yml",
		"café.yml",
		"fake\n:100644 100644 " + zero + " " + zero + " A\tforged.yml",
	}
	var tree bytes.Buffer
	var want []string
	for i, name := range names {
		blob := hashBlob(t, dir, fmt.Sprintf("hostile %d\n", i))
		fmt.Fprintf(&tree, "100644 blob %s\t%s\x00", blob, name)
		want = append(want, blob+" "+name)
	}
	treeID := gitInput(t, dir, tree.Bytes(), "mktree", "-z")
	commit := gitInput(t, dir, []byte("hostile\n"), "commit-tree", treeID)
	runGit(t, dir, "update-ref", "refs/heads/hostile", commit)

	idx := mustBuild(t, dir)
	got := allPairs(idx)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("pairs:\n got %q\nwant %q", got, want)
	}
	if slices.Contains(idx.paths, "forged.yml") {
		t.Error("forged record produced a path")
	}
	if idx.stats.malformed != 0 {
		t.Errorf("malformed = %d, want 0", idx.stats.malformed)
	}
}

// SEC-14: earliest is by committer timestamp (not log order); ties break on
// the smaller commit id; an unparseable or zero timestamp sorts last; the
// result is identical across runs.
func TestBuildBlobIndex_EarliestOrdering(t *testing.T) {
	skipIfNoGit(t)

	// rootCommits writes one parentless commit per committer line, each with
	// a tree holding the same blob at path, and returns their ids.
	rootCommits := func(t *testing.T, content, path string, committers map[string]string) (string, string, map[string]string) {
		dir := t.TempDir()
		initGitRepo(t, dir)
		blob := hashBlob(t, dir, content)
		tree := gitInput(t, dir, []byte("100644 blob "+blob+"\t"+path+"\n"), "mktree")
		ids := map[string]string{}
		for name, committer := range committers {
			body := "tree " + tree + "\nauthor A <a@x> 1767225600 +0000\n" + committer + "\n\n" + name + "\n"
			ids[name] = hashObjectLiterally(t, dir, "commit", body)
			runGit(t, dir, "update-ref", "refs/heads/"+name, ids[name])
		}
		return dir, blob, ids
	}

	t.Run("earliest committer date wins regardless of log order", func(t *testing.T) {
		dir, blob, ids := rootCommits(t, "ordered secret\n", "p.yml", map[string]string{
			"late":      "committer C <c@x> 1780000000 +0000",
			"early":     "committer C <c@x> 1770000000 +0000",
			"malformed": "committer C <c@x> notadate +0000",
			"zero":      "committer C <c@x> 0 +0000",
		})
		want := []locWant{{"p.yml", ids["early"]}}
		for i := range 5 {
			if got := locsOf(mustBuild(t, dir).lookup(mustHash(t, blob))); !slices.Equal(got, want) {
				t.Fatalf("run %d: %+v, want %+v", i, got, want)
			}
		}
	})

	t.Run("tie on timestamp breaks on smaller commit id", func(t *testing.T) {
		same := "committer C <c@x> 1770000000 +0000"
		dir, blob, ids := rootCommits(t, "tied\n", "t.yml", map[string]string{"x": same, "y": same, "z": same})
		want := []locWant{{"t.yml", min(ids["x"], ids["y"], ids["z"])}}
		for i := range 5 {
			if got := locsOf(mustBuild(t, dir).lookup(mustHash(t, blob))); !slices.Equal(got, want) {
				t.Fatalf("run %d: %+v, want %+v", i, got, want)
			}
		}
	})

	t.Run("unparseable and zero dates sort after valid ones and are flagged", func(t *testing.T) {
		dir, blob, ids := rootCommits(t, "bad dates\n", "b.yml", map[string]string{
			"malformed": "committer C <c@x> notadate +0000",
			"zero":      "committer C <c@x> 0 +0000",
		})
		idx := mustBuild(t, dir)
		want := []locWant{{"b.yml", min(ids["malformed"], ids["zero"])}}
		if got := locsOf(idx.lookup(mustHash(t, blob))); !slices.Equal(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
		for i, c := range idx.commits {
			if c.flags&commitTimeUnusable == 0 {
				t.Errorf("commit %d: committer time not flagged unusable", i)
			}
		}
	})
}

// Lookups are sorted by path; a blob with no entry returns nil, so the caller
// falls back to its rev-list path.
func TestBlobIndex_LookupSortedAndMissing(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	for _, p := range []string{"z.txt", "a.txt", "m/b.txt"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, p), "same\n")
	}
	commitAt(t, dir, "three paths", "2026-01-01T00:00:00Z")

	idx := mustBuild(t, dir)
	var paths []string
	for _, l := range idx.lookup(contentHash("same\n")) {
		paths = append(paths, l.Path)
	}
	if want := []string{"a.txt", "m/b.txt", "z.txt"}; !slices.Equal(paths, want) {
		t.Errorf("paths = %q, want %q", paths, want)
	}
	if got := idx.lookup(contentHash("absent\n")); got != nil {
		t.Errorf("missing blob lookup = %+v, want nil", got)
	}
	var nilIdx *blobIndex
	if got := nilIdx.lookup(contentHash("same\n")); got != nil {
		t.Errorf("nil index lookup = %+v, want nil", got)
	}
}

// Commit metadata pointers are shared: two blobs from one commit point at the
// same *CommitMetadata, and every field is populated.
func TestBlobIndex_CommitMetadataShared(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "a.txt"), "a\n")
	writeFile(t, filepath.Join(dir, "b.txt"), "b\n")
	c := commitAt(t, dir, "two files", "2026-04-05T06:07:08+02:00")

	idx := mustBuild(t, dir)
	a, b := idx.lookup(contentHash("a\n")), idx.lookup(contentHash("b\n"))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("a=%+v b=%+v", a, b)
	}
	if a[0].Commit != b[0].Commit {
		t.Error("commit metadata not shared between blobs of one commit")
	}
	m := a[0].Commit
	if m.CommitID != c || m.AuthorName != "Test User" || m.AuthorEmail != "test@example.com" ||
		m.CommitterName != "Test User" || m.CommitterEmail != "test@example.com" || m.Message != "two files" {
		t.Errorf("metadata = %+v", m)
	}
	want := time.Date(2026, 4, 5, 4, 7, 8, 0, time.UTC)
	if !m.AuthorTimestamp.Equal(want) || !m.CommitterTimestamp.Equal(want) {
		t.Errorf("timestamps = %v / %v, want %v", m.AuthorTimestamp, m.CommitterTimestamp, want)
	}
	if _, off := m.CommitterTimestamp.Zone(); off != 2*3600 {
		t.Errorf("committer zone offset = %d, want 7200", off)
	}
}

// A SHA-256 repository parses cleanly. Its 64-hex object ids are recognized
// (not counted as malformed) but not indexed, because types.BlobID and the
// rev-list scan path are SHA-1 only.
func TestBuildBlobIndex_SHA256Repo(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", "--object-format=sha256", dir).CombinedOutput(); err != nil {
		t.Skipf("git without sha256 support: %v %s", err, out)
	}
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test User")
	writeFile(t, filepath.Join(dir, "a.txt"), "sha256 content\n")
	commitAt(t, dir, "sha256", "2026-01-01T00:00:00Z")

	idx := mustBuild(t, dir)
	if idx.stats.malformed != 0 {
		t.Errorf("malformed = %d, want 0", idx.stats.malformed)
	}
	if idx.stats.unsupportedOID != 1 {
		t.Errorf("unsupportedOID = %d, want 1", idx.stats.unsupportedOID)
	}
	if len(idx.pairs) != 0 {
		t.Errorf("pairs = %d, want 0", len(idx.pairs))
	}
	if len(idx.commits) != 1 || idx.commits[0].idLen != 64 {
		t.Errorf("commits = %+v, want one 64-hex commit", idx.commits)
	}
}

// SEC-12: an index failure is an error to the caller (which degrades to "no
// locations"); it never hangs.
func TestBuildBlobIndex_Errors(t *testing.T) {
	skipIfNoGit(t)

	if _, err := buildBlobIndex(context.Background(), t.TempDir()); err == nil {
		t.Error("non-repository: want error")
	}

	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "a.txt"), "a\n")
	commitAt(t, dir, "a", "2026-01-01T00:00:00Z")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := buildBlobIndex(ctx, dir); err == nil {
		t.Error("cancelled context: want error")
	}

	empty := t.TempDir()
	initGitRepo(t, empty)
	idx, err := buildBlobIndex(context.Background(), empty)
	if err != nil {
		t.Fatalf("empty repo: %v", err)
	}
	if len(idx.pairs) != 0 {
		t.Errorf("empty repo pairs = %d", len(idx.pairs))
	}
}

// SEC-10 regression (E4): a 70,000-char subject followed by thousands of
// paths. The old reader stopped at the 64 KB line limit and then called Wait
// on an undrained pipe, which hung forever. Both readers must return within
// the bound, and the index must still record every path.
func TestCommitHistory_LongSubjectManyFilesNoHang(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)

	const nFiles = 5000
	for i := range nFiles {
		writeFile(t, filepath.Join(dir, fmt.Sprintf("file-with-a-longish-name-%05d.txt", i)), fmt.Sprintf("c%d\n", i))
	}
	msgFile := filepath.Join(t.TempDir(), "msg")
	if err := os.WriteFile(msgFile, []byte(strings.Repeat("x", 70000)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitAt(t, dir, "", "2026-01-01T00:00:00Z", "-F", msgFile)
	writeFile(t, filepath.Join(dir, "later.txt"), "later\n")
	commitAt(t, dir, "later", "2026-01-02T00:00:00Z")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	commitMap, err := collectCommitMetadataForRepo(ctx, dir, true)
	if ctx.Err() != nil {
		t.Fatal("collectCommitMetadataForRepo ran until the 30 s deadline (undrained pipe)")
	}
	if err != nil {
		t.Fatalf("collectCommitMetadataForRepo: %v", err)
	}
	if len(commitMap) != nFiles+1 {
		t.Errorf("commit map has %d paths, want %d", len(commitMap), nFiles+1)
	}

	idx, err := buildBlobIndex(ctx, dir)
	if err != nil {
		t.Fatalf("buildBlobIndex: %v", err)
	}
	for i := range nFiles {
		if got := idx.lookup(contentHash(fmt.Sprintf("c%d\n", i))); len(got) != 1 {
			t.Fatalf("file %d: %+v", i, got)
		}
	}
}

// --- parser-level tests (synthetic streams) ----------------------------------

func header(id, subject string) string {
	return id + "\x00A\x00a@x\x002026-01-01T00:00:00Z\x00C\x00c@x\x002026-01-01T00:00:00Z\x00" + subject + "\x00"
}

func raw(dstMode, dst, status, path string) string {
	return "\n:000000 " + dstMode + " " + strings.Repeat("0", 40) + " " + dst + " " + status + "\x00" + path + "\x00"
}

// SEC-9: a record over maxRecord is skipped and counted, never fatal, and the
// surrounding records are intact.
func TestParseBlobIndex_OverlongRecordsSkipped(t *testing.T) {
	c1 := strings.Repeat("1", 40)
	c2 := strings.Repeat("2", 40)
	b1 := strings.Repeat("a", 40)
	b2 := strings.Repeat("b", 40)
	b3 := strings.Repeat("c", 40)
	stream := header(c1, strings.Repeat("S", 2<<20)) +
		raw("100644", b1, "A", "ok.txt") +
		raw("100644", b2, "A", strings.Repeat("p", 2<<20)) +
		header(c2, "fine") +
		raw("100644", b3, "M", "after.txt")

	idx, err := parseBlobIndex(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if idx.stats.overlong != 2 {
		t.Errorf("overlong = %d, want 2", idx.stats.overlong)
	}
	if got := locsOf(idx.lookup(mustHash(t, b1))); !slices.Equal(got, []locWant{{"ok.txt", c1}}) {
		t.Errorf("b1 = %+v", got)
	}
	if got := idx.lookup(mustHash(t, b2)); got != nil {
		t.Errorf("over-long path indexed: %d locations", len(got))
	}
	if got := locsOf(idx.lookup(mustHash(t, b3))); !slices.Equal(got, []locWant{{"after.txt", c2}}) {
		t.Errorf("b3 = %+v", got)
	}
	if m := idx.lookup(mustHash(t, b1))[0].Commit.Message; m != "" {
		t.Errorf("over-long subject kept %d bytes, want empty", len(m))
	}

	var w bytes.Buffer
	idx.writeWarnings(&w)
	if got := w.String(); got != "titus: skipped 2 over-long git records\n" {
		t.Errorf("warnings = %q", got)
	}
}

// Statuses other than A/M/T, all-zero ids, gitlinks, malformed meta and
// records before any header produce no location.
func TestParseBlobIndex_Filtering(t *testing.T) {
	c := strings.Repeat("1", 40)
	keepA, keepM, keepT := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	del, link, early := strings.Repeat("d", 40), strings.Repeat("e", 40), strings.Repeat("f", 40)
	stream := raw("100644", early, "A", "before-header.txt") +
		header(c, "s") +
		raw("100644", keepA, "A", "a") +
		raw("100755", keepM, "M", "m") +
		raw("120000", keepT, "T", "t") +
		raw("000000", del, "D", "d") +
		raw("100644", strings.Repeat("0", 40), "A", "zero") +
		raw("160000", link, "A", "sub") +
		raw("100644", "nothex"+strings.Repeat("0", 34), "A", "badhex") +
		"\n:garbage\x00g\x00" +
		"stray-token\x00"

	idx, err := parseBlobIndex(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var got []string
	for _, p := range idx.pairs {
		got = append(got, idx.paths[p.path])
	}
	if want := []string{"a", "m", "t"}; !slices.Equal(got, want) {
		t.Errorf("indexed paths = %q, want %q", got, want)
	}
	// before-header, all-zero id, non-hex id, garbage meta, stray token.
	if idx.stats.malformed != 5 {
		t.Errorf("malformed = %d, want 5", idx.stats.malformed)
	}
	var w bytes.Buffer
	idx.writeWarnings(&w)
	if got := w.String(); got != "titus: skipped 5 malformed git records\n" {
		t.Errorf("warnings = %q", got)
	}
}

// A stream that ends without a final NUL still yields its last path.
func TestParseBlobIndex_UnterminatedFinalToken(t *testing.T) {
	c := strings.Repeat("1", 40)
	b := strings.Repeat("a", 40)
	stream := strings.TrimSuffix(header(c, "s")+raw("100644", b, "A", "last.txt"), "\x00")
	idx, err := parseBlobIndex(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := locsOf(idx.lookup(mustHash(t, b))); !slices.Equal(got, []locWant{{"last.txt", c}}) {
		t.Errorf("got %+v", got)
	}
}

// R1: the global pair cap stops inserting, marks the index truncated and
// warns once; existing entries stay usable.
func TestParseBlobIndex_GlobalCap(t *testing.T) {
	old := maxIndexPairs
	maxIndexPairs = 2
	t.Cleanup(func() { maxIndexPairs = old })

	c := strings.Repeat("1", 40)
	var stream strings.Builder
	stream.WriteString(header(c, "s"))
	for i := range 5 {
		stream.WriteString(raw("100644", fmt.Sprintf("%040x", i+1), "A", fmt.Sprintf("f%d", i)))
	}
	idx, err := parseBlobIndex(strings.NewReader(stream.String()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !idx.truncated() {
		t.Error("truncated() = false, want true")
	}
	if len(idx.pairs) != 2 || idx.stats.droppedPairs != 3 {
		t.Errorf("pairs = %d dropped = %d, want 2 and 3", len(idx.pairs), idx.stats.droppedPairs)
	}
	if got := idx.lookup(mustHash(t, fmt.Sprintf("%040x", 1))); len(got) != 1 {
		t.Errorf("kept pair lookup = %+v", got)
	}
	var w bytes.Buffer
	idx.writeWarnings(&w)
	if got, want := w.String(), "titus: git history index reached 2 locations; 3 more were not recorded, so location lists may be incomplete\n"; got != want {
		t.Errorf("warnings = %q, want %q", got, want)
	}

	var nilIdx *blobIndex
	if nilIdx.truncated() {
		t.Error("nil index reports truncated")
	}
}

// Duplicate (blob, path) records beyond the in-place compaction threshold are
// folded so the transient slice stays bounded, and the earliest commit wins.
func TestParseBlobIndex_CompactionKeepsEarliest(t *testing.T) {
	old := minCompactPairs
	minCompactPairs = 4
	t.Cleanup(func() { minCompactPairs = old })

	b := strings.Repeat("a", 40)
	var stream strings.Builder
	// Newest first, as git log emits them; each commit re-touches the blob.
	for i := range 50 {
		id := fmt.Sprintf("%040x", 100-i)
		date := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, 50-i).Format(time.RFC3339)
		stream.WriteString(id + "\x00A\x00a@x\x00" + date + "\x00C\x00c@x\x00" + date + "\x00s\x00")
		stream.WriteString(raw("100644", b, "M", "same.yml"))
		stream.WriteString(raw("100644", fmt.Sprintf("%040x", 1000+i), "A", "other.yml"))
	}
	idx, err := parseBlobIndex(strings.NewReader(stream.String()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []locWant{{"same.yml", fmt.Sprintf("%040x", 51)}}
	if got := locsOf(idx.lookup(mustHash(t, b))); !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if len(idx.pairs) != 51 {
		t.Errorf("pairs = %d, want 51", len(idx.pairs))
	}
}

// --- benchmark ---------------------------------------------------------------

// BenchmarkBuildBlobIndex indexes a generated repository end to end,
// including the git log process.
func BenchmarkBuildBlobIndex(b *testing.B) {
	dir := benchRepo(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := buildBlobIndex(context.Background(), dir); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseBlobIndex measures only parsing and index construction on the
// captured log stream of the same generated repository.
func BenchmarkParseBlobIndex(b *testing.B) {
	dir := benchRepo(b)
	out, err := hardenedGit(context.Background(), dir, blobIndexLogArgs()...).Output()
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(out)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseBlobIndex(bytes.NewReader(out)); err != nil {
			b.Fatal(err)
		}
	}
}

// benchRepo builds, with git fast-import, a linear history of 1,000 commits
// over 5,000 files: the root commit adds every file and each later commit
// modifies 50 of them (about 55,000 raw records).
func benchRepo(b *testing.B) string {
	b.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		b.Skip("git binary not available")
	}
	const files, commits, perCommit = 5000, 1000, 50
	dir := b.TempDir()
	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		b.Fatalf("git init: %v %s", err, out)
	}

	var s bytes.Buffer
	data := func(content string) { fmt.Fprintf(&s, "data %d\n%s\n", len(content), content) }
	for c := range commits {
		fmt.Fprintf(&s, "commit refs/heads/main\nmark :%d\ncommitter Bench <bench@example.com> %d +0000\n", c+1, 1767225600+c*60)
		data(fmt.Sprintf("commit %d", c))
		if c > 0 {
			fmt.Fprintf(&s, "from :%d\n", c)
		}
		for f := range files {
			if c > 0 && f%(files/perCommit) != c%(files/perCommit) {
				continue
			}
			fmt.Fprintf(&s, "M 100644 inline dir%02d/file-%05d.txt\n", f%25, f)
			data(fmt.Sprintf("v%d file %d\n", c, f))
		}
	}
	cmd := exec.Command("git", "fast-import", "--quiet")
	cmd.Dir = dir
	cmd.Stdin = &s
	if out, err := cmd.CombinedOutput(); err != nil {
		b.Fatalf("fast-import: %v %s", err, out)
	}
	return dir
}
