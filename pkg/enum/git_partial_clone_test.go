package enum

import (
	"bytes"
	"context"
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

// partialClone is a blob-less partial clone whose origin uploadpack is a
// script that leaves a marker when it runs: any lazy fetch from the scanned
// repository's remote runs that script (V1).
type partialClone struct {
	dir     string
	marker  string
	missing int    // objects rev-list reports as absent ("?<id>" lines)
	head    string // content checked out at clone time: present
	old     string // content only in older history: never fetched
}

func newPartialClone(t *testing.T) partialClone {
	t.Helper()
	skipIfNoGit(t)
	pc := partialClone{
		head: "HEAD_TOKEN=present-in-the-partial-clone\n",
		old:  "OLD_TOKEN=only-in-history-never-fetched\n",
	}

	src := t.TempDir()
	initGitRepo(t, src)
	writeFile(t, filepath.Join(src, "old.env"), pc.old)
	commitAt(t, src, "old", "2026-01-01T00:00:00Z")
	runGit(t, src, "rm", "-q", "old.env")
	writeFile(t, filepath.Join(src, "head.env"), pc.head)
	commitAt(t, src, "head", "2026-02-01T00:00:00Z")
	runGit(t, src, "config", "uploadpack.allowFilter", "true")

	pc.dir = filepath.Join(t.TempDir(), "clone")
	clone := exec.Command("git", "clone", "-q", "--filter=blob:none", "file://"+src, pc.dir)
	if out, err := clone.CombinedOutput(); err != nil {
		t.Skipf("git lacks partial-clone support: %v\n%s", err, out)
	}

	pc.marker = filepath.Join(t.TempDir(), "uploadpack-ran")
	script := filepath.Join(t.TempDir(), "evil-uploadpack.sh")
	body := "#!/bin/sh\ntouch '" + pc.marker + "'\nexec git-upload-pack \"$@\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, pc.dir, "config", "protocol.file.allow", "always")
	runGit(t, pc.dir, "config", "remote.origin.uploadpack", script)

	// Fixture shape: the clone really lacks objects, and listing them did
	// not fetch anything.
	for _, line := range strings.Split(gitOutput(t, pc.dir, "rev-list", "--all", "--objects", "--missing=print"), "\n") {
		if strings.HasPrefix(line, "?") {
			pc.missing++
		}
	}
	if pc.missing == 0 {
		t.Skip("partial clone has no missing objects; git did not honor --filter=blob:none")
	}
	pc.assertNoFetch(t)
	return pc
}

func (pc partialClone) assertNoFetch(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(pc.marker); err == nil {
		t.Fatal("the scanned repository's remote.origin.uploadpack ran: a lazy fetch happened")
	}
}

// collect runs one history walk and returns the scanned contents.
func (pc partialClone) collect(t *testing.T, walk func(*GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error) (map[string]bool, string) {
	t.Helper()
	e := nativeEnum(pc.dir)
	var warn bytes.Buffer
	e.warn = &warn
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seen := map[string]bool{}
	err := walk(e)(ctx, func(content []byte, _ types.BlobID, _ types.Provenance) error {
		seen[string(content)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("enumeration failed: %v (warnings %q)", err, warn.String())
	}
	return seen, warn.String()
}

// V1: scanning a partial clone never runs the repository's own remote
// configuration. Missing objects are counted and reported, the present ones
// are scanned, and enumeration succeeds.
func TestPartialClone_NoLazyFetch(t *testing.T) {
	pc := newPartialClone(t)
	wantWarn := fmt.Sprintf("titus: %d git objects are missing", pc.missing)

	walks := []struct {
		name string
		walk func(*GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error
	}{
		{"native", func(e *GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error {
			return e.enumerateAllHistoryNative
		}},
		{"go-git", func(e *GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error {
			return e.enumerateAllHistory
		}},
	}
	for _, w := range walks {
		t.Run(w.name, func(t *testing.T) {
			seen, warn := pc.collect(t, w.walk)
			pc.assertNoFetch(t)
			if !seen[pc.head] {
				t.Errorf("present blob head.env was not scanned; scanned %d blobs", len(seen))
			}
			if seen[pc.old] {
				t.Error("unfetched blob old.env was scanned: it was fetched")
			}
			if !strings.Contains(warn, wantWarn) {
				t.Errorf("warnings = %q, want %q", warn, wantWarn)
			}
		})
	}

	// Sanity: the fixture is live. Plain git, with lazy fetch allowed,
	// reading a missing blob runs the repository's uploadpack script.
	t.Run("fixture is live", func(t *testing.T) {
		missing := ""
		for _, line := range strings.Split(gitOutput(t, pc.dir, "rev-list", "--all", "--objects", "--missing=print"), "\n") {
			if id, ok := strings.CutPrefix(line, "?"); ok {
				missing = id
				break
			}
		}
		cmd := exec.Command("git", "cat-file", "-p", missing)
		cmd.Dir = pc.dir
		cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=0")
		_ = cmd.Run() // the fetch's outcome is irrelevant; the marker is the signal
		if _, err := os.Stat(pc.marker); err != nil {
			t.Fatalf("fixture is not live: plain git cat-file did not run remote.origin.uploadpack: %v", err)
		}
	})
}

// V2: an object rev-list lists but cat-file reports missing is counted, and
// the other blobs are still scanned.
func TestStreamBlobContents_CatFileMissingCounted(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "gone.env"), "GONE=deleted-after-rev-list\n")
	writeFile(t, filepath.Join(dir, "kept.env"), "KEPT=still-readable\n")
	commitAt(t, dir, "c", "2026-01-01T00:00:00Z")

	e := nativeEnum(dir)
	rl, err := e.collectBlobEntries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	gone := hashBlob(t, dir, "GONE=deleted-after-rev-list\n")
	if err := os.Remove(filepath.Join(dir, ".git", "objects", gone[:2], gone[2:])); err != nil {
		t.Fatalf("fixture: remove loose object: %v", err)
	}

	seen := map[string]bool{}
	err = e.streamBlobContents(context.Background(), &rl, &blobIndex{}, repoIdentity{}, func(content []byte, _ types.BlobID, _ types.Provenance) error {
		seen[string(content)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("streamBlobContents: %v", err)
	}
	if rl.missing != 1 {
		t.Errorf("missing = %d, want 1", rl.missing)
	}
	if !seen["KEPT=still-readable\n"] || seen["GONE=deleted-after-rev-list\n"] {
		t.Errorf("scanned = %v, want only kept.env", seen)
	}
}

// V2, go-git: a blob whose object is gone is counted and reported, not
// silently skipped.
func TestGoGitHistory_MissingBlobReported(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "gone.env"), "GONE=deleted\n")
	writeFile(t, filepath.Join(dir, "kept.env"), "KEPT=readable\n")
	commitAt(t, dir, "c", "2026-01-01T00:00:00Z")
	gone := hashBlob(t, dir, "GONE=deleted\n")
	if err := os.Remove(filepath.Join(dir, ".git", "objects", gone[:2], gone[2:])); err != nil {
		t.Fatalf("fixture: remove loose object: %v", err)
	}

	e := nativeEnum(dir)
	var warn bytes.Buffer
	e.warn = &warn
	seen := map[string]bool{}
	err := e.enumerateAllHistory(context.Background(), func(content []byte, _ types.BlobID, _ types.Provenance) error {
		seen[string(content)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("enumerateAllHistory: %v", err)
	}
	if !seen["KEPT=readable\n"] {
		t.Error("kept.env was not scanned")
	}
	if want := "titus: 1 git objects are missing"; !strings.Contains(warn.String(), want) {
		t.Errorf("warnings = %q, want %q", warn.String(), want)
	}
}

// firstMissing returns one object id the partial clone lacks.
func (pc partialClone) firstMissing(t *testing.T) string {
	t.Helper()
	for _, line := range strings.Split(gitOutput(t, pc.dir, "rev-list", "--all", "--objects", "--missing=print"), "\n") {
		if id, ok := strings.CutPrefix(line, "?"); ok {
			return id
		}
	}
	t.Fatal("fixture: no missing object")
	return ""
}

// R1: hardenedGit itself never lazily fetches. Reading a missing object
// directly, which rev-list's missing=print mode otherwise keeps away from
// cat-file, must not
// run the scanned repository's uploadpack. The control proves the fixture is
// live: the same command through plain git runs it.
func TestHardenedGit_CatFileMissingNoLazyFetch(t *testing.T) {
	pc := newPartialClone(t)
	missing := pc.firstMissing(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_ = hardenedGit(ctx, pc.dir, "cat-file", "-p", missing).Run() // fails: the object is absent
	pc.assertNoFetch(t)

	control := exec.CommandContext(ctx, "git", "cat-file", "-p", missing)
	control.Dir = pc.dir
	control.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=0")
	_ = control.Run() // the fetch's outcome is irrelevant; the marker is the signal
	if _, err := os.Stat(pc.marker); err != nil {
		t.Fatalf("fixture is not live: plain git cat-file did not run remote.origin.uploadpack: %v", err)
	}
}

// R1 / V1 on git older than 2.45: with GIT_NO_LAZY_FETCH unset and without
// -c protocol.allow=never (which the repository's own
// protocol.file.allow=always overrides), the GIT_ALLOW_PROTOCOL= entry of
// hardenedGitEnv alone stops the lazy fetch.
func TestHardenedGit_AllowProtocolAloneBlocksLazyFetch(t *testing.T) {
	pc := newPartialClone(t)
	missing := pc.firstMissing(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := hardenedGit(ctx, pc.dir, "cat-file", "-p", missing)
	cmd.Env = slices.DeleteFunc(cmd.Env, func(kv string) bool {
		return strings.HasPrefix(kv, "GIT_NO_LAZY_FETCH=")
	})
	cmd.Args = withoutConfig(cmd.Args, "protocol.allow=never")
	if slices.Contains(cmd.Args, "protocol.allow=never") || slices.ContainsFunc(cmd.Env, func(kv string) bool {
		return strings.HasPrefix(kv, "GIT_NO_LAZY_FETCH=")
	}) {
		t.Fatal("fixture: the other two layers are still present")
	}
	_ = cmd.Run() // fails: the object is absent
	pc.assertNoFetch(t)

	// Control: the same command without GIT_ALLOW_PROTOCOL= does fetch, so
	// the entry is what blocked it.
	cmd = hardenedGit(ctx, pc.dir, "cat-file", "-p", missing)
	cmd.Env = append(slices.DeleteFunc(cmd.Env, func(kv string) bool {
		return strings.HasPrefix(kv, "GIT_NO_LAZY_FETCH=") || strings.HasPrefix(kv, "GIT_ALLOW_PROTOCOL=")
	}), "GIT_NO_LAZY_FETCH=0")
	cmd.Args = withoutConfig(cmd.Args, "protocol.allow=never")
	_ = cmd.Run()
	if _, err := os.Stat(pc.marker); err != nil {
		t.Fatalf("fixture is not live: without GIT_ALLOW_PROTOCOL= the uploadpack did not run: %v", err)
	}
}

// withoutConfig returns args without the "-c kv" pair.
func withoutConfig(args []string, kv string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "-c" && i+1 < len(args) && args[i+1] == kv {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}
