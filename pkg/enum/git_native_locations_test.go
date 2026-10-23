package enum

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

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

	got, overlong, err := readRevList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if overlong != 1 {
		t.Errorf("overlong = %d, want 1", overlong)
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
