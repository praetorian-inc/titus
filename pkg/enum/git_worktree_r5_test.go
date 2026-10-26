package enum

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Contents unique to the round-5 fixtures, so each finding's blob is found
// by content alone.
const (
	r5MainDetachedSecret = "R5_MAIN_DETACHED_SECRET=ghp_example\n"
	r5TreeHeadSecret     = "R5_TREE_HEAD_SECRET=ghp_example\n"
	r5LostHeadSecret     = "R5_LOST_HEAD_SECRET=ghp_example\n"
	r5BlankLineSecret    = "R5_BLANK_LINE_SECRET=ghp_example\n"
)

// linkedGitDir returns the absolute administrative directory of the linked
// worktree at path (<commondir>/worktrees/<id>).
func linkedGitDir(t *testing.T, path string) string {
	t.Helper()
	dir := gitOutput(t, path, "rev-parse", "--absolute-git-dir")
	if filepath.Base(filepath.Dir(dir)) != "worktrees" {
		t.Fatalf("fixture: %s is not a linked worktree's git dir", dir)
	}
	return dir
}

// R5-1: the main checkout's detached HEAD holds a commit no ref reaches.
// Scanning from a linked worktree, both walks must still start from the
// main HEAD (rev-list --all does) and report the blob with its commit.
func TestGitHistory_MainDetachedHeadFromLinkedWorktree(t *testing.T) {
	skipIfNoGit(t)
	main, linked := t.TempDir(), filepath.Join(t.TempDir(), "wt")
	initGitRepo(t, main)
	writeFile(t, filepath.Join(main, "base.txt"), wtBaseContent)
	commitAt(t, main, "base", "2026-01-01T00:00:00Z")
	if out, err := addDetachedWorktree(main, linked); err != nil {
		t.Fatalf("git worktree add: %v\n%s", err, out)
	}
	runGit(t, main, "checkout", "-q", "--detach")
	writeFile(t, filepath.Join(main, "main-detached.txt"), r5MainDetachedSecret)
	mainCommit := commitAt(t, main, "main detached", "2026-01-02T00:00:00Z")

	// Fixture shape: only the main HEAD reaches the commit.
	if refs := gitOutput(t, main, "for-each-ref", "--contains", mainCommit); refs != "" {
		t.Fatalf("fixture: refs reach the main detached commit: %q", refs)
	}
	if gitOutput(t, linked, "rev-parse", "HEAD") == mainCommit {
		t.Fatal("fixture: the linked worktree HEAD is the main detached commit")
	}

	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			got, warn := walkAllProv(t, linked, walk)
			g, ok := got[r5MainDetachedSecret]
			if !ok {
				t.Fatalf("the blob reachable only from the main checkout's detached HEAD was not scanned (warnings %q)", warn)
			}
			want := blobProv{Paths: "main-detached.txt", Commits: mainCommit}
			if g != want {
				t.Errorf("provenance = %+v, want %+v (warnings %q)", g, want, warn)
			}
		})
	}
}

// R5-2: a linked worktree's HEAD file names a tree, which git accepts and
// rev-list --all walks. The blob sits at p1.txt and p2.txt in that tree
// and nowhere else. Each walk must either list both paths or mark the
// finding as possibly missing locations, and the two walks must agree.
func TestGitHistory_LinkedWorktreeHeadNamingTree(t *testing.T) {
	skipIfNoGit(t)
	main, linked := t.TempDir(), filepath.Join(t.TempDir(), "wt")
	initGitRepo(t, main)
	writeFile(t, filepath.Join(main, "base.txt"), wtBaseContent)
	commitAt(t, main, "base", "2026-01-01T00:00:00Z")
	if out, err := addDetachedWorktree(main, linked); err != nil {
		t.Fatalf("git worktree add: %v\n%s", err, out)
	}
	blob := hashBlob(t, main, r5TreeHeadSecret)
	tree := gitInput(t, main, []byte("100644 blob "+blob+"\tp1.txt\n100644 blob "+blob+"\tp2.txt\n"), "mktree")
	head := filepath.Join(linkedGitDir(t, linked), "HEAD")
	writeFile(t, head, tree+"\n")

	// Fixture shape: git itself walks the tree from the worktree HEAD.
	if objs := gitOutput(t, main, "rev-list", "--all", "--objects"); !strings.Contains(objs, blob) {
		t.Fatalf("fixture: rev-list --all does not reach the blob under the tree HEAD:\n%s", objs)
	}

	results := map[string]blobProv{}
	for _, name := range []string{"native", "go-git"} {
		walk := enumWalks[name]
		t.Run(name, func(t *testing.T) {
			got, warn := walkAllProv(t, main, walk)
			g, ok := got[r5TreeHeadSecret]
			if !ok {
				t.Fatalf("the blob under the worktree's tree HEAD was not scanned (warnings %q)", warn)
			}
			results[name] = g
			if g.Paths != "p1.txt,p2.txt" && !g.Truncated {
				t.Errorf("provenance = %+v: a path is lost and the finding is not marked as possibly missing locations (warnings %q)", g, warn)
			}
		})
	}
	if n, g := results["native"], results["go-git"]; len(results) == 2 && n != g {
		t.Errorf("walks disagree: native %+v, go-git %+v", n, g)
	}
}

// unreadableWorktreeHeadRepo commits content at main.txt on the main
// branch and at other-path.txt only on a linked worktree's detached HEAD,
// then makes that HEAD file unreadable. It skips where chmod 000 does not
// stop the owner from reading.
func unreadableWorktreeHeadRepo(t *testing.T, content string) string {
	t.Helper()
	skipIfNoGit(t)
	if runtime.GOOS == "windows" {
		t.Skip("chmod 000 does not make a file unreadable on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a chmod 000 file")
	}
	main, linked := t.TempDir(), filepath.Join(t.TempDir(), "wt")
	initGitRepo(t, main)
	writeFile(t, filepath.Join(main, "main.txt"), content)
	commitAt(t, main, "main", "2026-01-01T00:00:00Z")
	if out, err := addDetachedWorktree(main, linked); err != nil {
		t.Fatalf("git worktree add: %v\n%s", err, out)
	}
	writeFile(t, filepath.Join(linked, "other-path.txt"), content)
	commitAt(t, linked, "other path", "2026-01-02T00:00:00Z")

	head := filepath.Join(linkedGitDir(t, linked), "HEAD")
	if err := os.Chmod(head, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(head, 0o644) })
	if f, err := os.Open(head); err == nil {
		_ = f.Close()
		t.Skip("this filesystem still lets the owner read a chmod 000 file")
	}
	return main
}

// R5-3: go-git cannot read a linked worktree's HEAD, so other-path.txt is
// lost. It must say so on stderr AND mark the finding as possibly missing
// locations; the warning alone leaves the finding looking complete.
func TestGoGitHistory_UnreadableWorktreeHeadWarnsAndMarks(t *testing.T) {
	main := unreadableWorktreeHeadRepo(t, r5LostHeadSecret)
	got, warn := walkAllProv(t, main, enumWalks["go-git"])
	g, ok := got[r5LostHeadSecret]
	if !ok {
		t.Fatalf("the blob on the main branch was not scanned (warnings %q)", warn)
	}
	if !strings.Contains(warn, "could not read the HEAD") {
		t.Errorf("warnings = %q, want one about the unreadable worktree HEAD", warn)
	}
	if !strings.Contains(g.Paths, "main.txt") {
		t.Errorf("paths = %q, want main.txt", g.Paths)
	}
	if g.Paths != "main.txt,other-path.txt" && !g.Truncated {
		t.Errorf("provenance = %+v: other-path.txt is lost and the finding is not marked as possibly missing locations (warnings %q)", g, warn)
	}
}

// R5-3, native side: git worktree list reports the unreadable HEAD as the
// null id and rev-list --all skips it, so other-path.txt can be lost here
// too. The finding must then be marked as possibly missing locations.
func TestNativeGitHistory_UnreadableWorktreeHeadMarks(t *testing.T) {
	main := unreadableWorktreeHeadRepo(t, r5LostHeadSecret)
	got, warn := walkAllProv(t, main, enumWalks["native"])
	g, ok := got[r5LostHeadSecret]
	if !ok {
		t.Fatalf("the blob on the main branch was not scanned (warnings %q)", warn)
	}
	if g.Paths != "main.txt,other-path.txt" && !g.Truncated {
		t.Errorf("provenance = %+v: other-path.txt is lost and the finding is not marked as possibly missing locations (warnings %q)", g, warn)
	}
}

// oldGitShim puts a "git" first on PATH that behaves like git older than
// 2.36: worktree list with -z exits 129, and every other call runs the
// real git. It returns a log file that records each rejected -z call, so
// a test can prove the fallback ran.
func oldGitShim(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the git shim is a POSIX shell script")
	}
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git binary not available")
	}
	if real, err = filepath.Abs(real); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	log := filepath.Join(bin, "rejected.log")
	script := "#!/bin/sh\n" +
		"wt=0; z=0\n" +
		"for a in \"$@\"; do\n" +
		"  [ \"$a\" = worktree ] && wt=1\n" +
		"  [ \"$a\" = -z ] && z=1\n" +
		"done\n" +
		"if [ $wt = 1 ] && [ $z = 1 ]; then\n" +
		"  echo rejected >> '" + log + "'\n" +
		"  echo \"error: unknown switch \\`z'\" >&2\n" +
		"  exit 129\n" +
		"fi\n" +
		"exec '" + real + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// R5-4: on git older than 2.36 the plain porcelain output is parsed. A
// worktree path holding a blank line prints an empty line inside that
// worktree's block, before its real HEAD line. The real HEAD must stay a
// tip, so the blob committed only there keeps its commit and is not
// silently left without one.
func TestNativeGitHistory_OldGitBlankLinePathKeepsWorktreeHead(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "base.txt"), wtBaseContent)
	commitAt(t, dir, "base", "2026-01-01T00:00:00Z")

	linked := filepath.Join(t.TempDir(), "aw\n\nt")
	if out, err := addDetachedWorktree(dir, linked); err != nil {
		t.Skipf("cannot create a worktree path with a blank line here: %v\n%s", err, out)
	}
	writeFile(t, filepath.Join(linked, "wt-only.txt"), r5BlankLineSecret)
	wtCommit := commitAt(t, linked, "wt only", "2026-01-02T00:00:00Z")

	// Fixture shape: no ref reaches the commit, and the plain porcelain
	// output really carries the blank line ahead of the real HEAD line.
	if refs := gitOutput(t, dir, "for-each-ref", "--contains", wtCommit); refs != "" {
		t.Fatalf("fixture: refs reach the worktree commit: %q", refs)
	}
	porcelain := gitOutput(t, dir, "worktree", "list", "--porcelain")
	if !strings.Contains(porcelain, "aw\n\nt\nHEAD "+wtCommit) {
		t.Skipf("this git does not print the path unquoted, so the blank line cannot split the block:\n%q", porcelain)
	}

	log := oldGitShim(t)

	tips, err := resolveRefTips(context.Background(), dir)
	if err != nil {
		t.Fatalf("resolveRefTips: %v", err)
	}
	if b, err := os.ReadFile(log); err != nil || !strings.Contains(string(b), "rejected") {
		t.Fatalf("fixture: the shim never rejected worktree list -z, so the fallback did not run (%v)", err)
	}
	if !slices.Contains(tips.commits, wtCommit) {
		t.Errorf("tips = %q, want the worktree's real HEAD %s", tips.commits, wtCommit)
	}

	got, warn := walkAllProv(t, dir, enumWalks["native"])
	g, ok := got[r5BlankLineSecret]
	if !ok {
		t.Fatalf("the worktree-only blob was not scanned (warnings %q)", warn)
	}
	want := blobProv{Paths: "wt-only.txt", Commits: wtCommit}
	if g != want {
		t.Errorf("provenance = %+v, want %+v (warnings %q)", g, want, warn)
	}
}
