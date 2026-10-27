package enum

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockEnumerator is a simple Enumerator that yields a fixed set of blobs.
type mockEnumerator struct {
	blobs []mockBlob
}

type mockBlob struct {
	content []byte
	blobID  types.BlobID
	prov    types.Provenance
}

func (m *mockEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	for _, b := range m.blobs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := callback(b.content, b.blobID, b.prov); err != nil {
			return err
		}
	}
	return nil
}

// blobID creates a fixed BlobID from a byte value for test convenience.
func blobIDFrom(b byte) types.BlobID {
	var id types.BlobID
	id[0] = b
	return id
}

func TestCombinedEnumerator_Empty(t *testing.T) {
	combined := NewCombinedEnumerator()

	var yielded int
	err := combined.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		yielded++
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 0, yielded, "empty CombinedEnumerator should yield no blobs")
}

func TestCombinedEnumerator_SingleEnumerator(t *testing.T) {
	id1 := blobIDFrom(1)
	id2 := blobIDFrom(2)
	prov1 := types.FileProvenance{FilePath: "a.txt"}
	prov2 := types.FileProvenance{FilePath: "b.txt"}

	e1 := &mockEnumerator{blobs: []mockBlob{
		{content: []byte("hello"), blobID: id1, prov: prov1},
		{content: []byte("world"), blobID: id2, prov: prov2},
	}}
	combined := NewCombinedEnumerator(e1)

	type yielded struct {
		blobID types.BlobID
		prov   types.Provenance
	}
	var results []yielded
	err := combined.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		results = append(results, yielded{blobID: blobID, prov: prov})
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, id1, results[0].blobID)
	assert.Equal(t, id2, results[1].blobID)
}

func TestCombinedEnumerator_DeduplicatesByBlobID(t *testing.T) {
	sharedID := blobIDFrom(42)
	uniqueID := blobIDFrom(99)

	// Both enumerators yield the same blobID; only one should reach the callback.
	e1 := &mockEnumerator{blobs: []mockBlob{
		{content: []byte("dup"), blobID: sharedID, prov: types.FileProvenance{FilePath: "first.txt"}},
	}}
	e2 := &mockEnumerator{blobs: []mockBlob{
		{content: []byte("dup"), blobID: sharedID, prov: types.FileProvenance{FilePath: "second.txt"}},
		{content: []byte("unique"), blobID: uniqueID, prov: types.FileProvenance{FilePath: "unique.txt"}},
	}}
	combined := NewCombinedEnumerator(e1, e2)

	var blobIDs []types.BlobID
	err := combined.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobIDs = append(blobIDs, blobID)
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, blobIDs, 2, "shared blob should be deduplicated, only 2 unique blobs expected")
	assert.Contains(t, blobIDs, sharedID)
	assert.Contains(t, blobIDs, uniqueID)
}

func TestCombinedEnumerator_AllUniqueBlobs(t *testing.T) {
	e1 := &mockEnumerator{blobs: []mockBlob{
		{content: []byte("a"), blobID: blobIDFrom(1), prov: types.FileProvenance{FilePath: "a.txt"}},
		{content: []byte("b"), blobID: blobIDFrom(2), prov: types.FileProvenance{FilePath: "b.txt"}},
	}}
	e2 := &mockEnumerator{blobs: []mockBlob{
		{content: []byte("c"), blobID: blobIDFrom(3), prov: types.FileProvenance{FilePath: "c.txt"}},
	}}
	combined := NewCombinedEnumerator(e1, e2)

	var count int
	err := combined.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 3, count, "all unique blobs from both enumerators should be yielded")
}

func TestCombinedEnumerator_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var callCount int
	e1 := &mockEnumerator{blobs: []mockBlob{
		{content: []byte("a"), blobID: blobIDFrom(1), prov: types.FileProvenance{FilePath: "a.txt"}},
		{content: []byte("b"), blobID: blobIDFrom(2), prov: types.FileProvenance{FilePath: "b.txt"}},
	}}
	combined := NewCombinedEnumerator(e1)

	err := combined.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		callCount++
		cancel() // Cancel after first blob
		return nil
	})

	// The context cancellation should propagate as an error.
	assert.True(t, errors.Is(err, context.Canceled), "expected context.Canceled, got: %v", err)
	assert.Equal(t, 1, callCount, "should stop after cancellation")
}

// wtLoc is one location as the tests compare it: path, commit, working tree.
type wtLoc struct {
	path   string
	commit string
	wt     bool
}

func wtLocsOf(locs []types.GitLocation) []wtLoc {
	out := make([]wtLoc, 0, len(locs))
	for _, l := range locs {
		w := wtLoc{path: l.Path, wt: l.WorkingTree}
		if l.Commit != nil {
			w.commit = l.Commit.CommitID
		}
		out = append(out, w)
	}
	return out
}

// combinedRun collects every callback of a combined enumeration.
type combinedRun struct {
	mu    sync.Mutex
	calls map[types.BlobID]int
	provs map[types.BlobID]types.Provenance
}

func runCombined(t *testing.T, c *CombinedEnumerator) (*combinedRun, error) {
	t.Helper()
	r := &combinedRun{calls: map[types.BlobID]int{}, provs: map[types.BlobID]types.Provenance{}}
	err := c.Enumerate(context.Background(), func(_ []byte, id types.BlobID, prov types.Provenance) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls[id]++
		r.provs[id] = prov
		return nil
	})
	return r, err
}

func gitAndWorktree(root string, cfg Config) *CombinedEnumerator {
	cfg.Root = root
	g := NewGitEnumerator(cfg)
	g.WalkAll = true
	return NewCombinedEnumerator(g, NewFilesystemEnumerator(cfg))
}

// assertOneCallbackPerBlob checks INV-ONECALLBACK over every blob reported,
// not only the blob a test names.
func assertOneCallbackPerBlob(t *testing.T, r *combinedRun) {
	t.Helper()
	for id, n := range r.calls {
		if n != 1 {
			t.Errorf("callbacks for blob %s = %d, want 1", id.Hex(), n)
		}
	}
}

// assertNoFileProvenance checks that, under the --git shape, no blob inside
// the repository escapes as a bare FileProvenance: working-tree files are
// reported as GitProvenance (archive members keep ArchiveProvenance).
func assertNoFileProvenance(t *testing.T, r *combinedRun) {
	t.Helper()
	for id, p := range r.provs {
		if fp, ok := p.(types.FileProvenance); ok {
			t.Errorf("blob %s has stray FileProvenance %q, want GitProvenance", id.Hex(), fp.FilePath)
		}
	}
}

// assertGitShape runs the global checks every --git shape test needs.
func assertGitShape(t *testing.T, r *combinedRun) {
	t.Helper()
	assertOneCallbackPerBlob(t, r)
	assertNoFileProvenance(t, r)
}

func mustGitProv(t *testing.T, r *combinedRun, id types.BlobID) types.GitProvenance {
	t.Helper()
	if n := r.calls[id]; n != 1 {
		t.Fatalf("callbacks for blob %s = %d, want 1", id.Hex(), n)
	}
	p, ok := r.provs[id].(types.GitProvenance)
	if !ok {
		t.Fatalf("provenance for blob %s is %T, want types.GitProvenance", id.Hex(), r.provs[id])
	}
	return p
}

func absDir(t *testing.T, dir string) string {
	t.Helper()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// C-WORKTREE-1: an untracked copy of a committed file yields one callback
// whose locations are the committed path with its commit and the working-tree
// path with no commit.
func TestCombinedEnumerator_WorktreeCopyMergesIntoHistory(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	secret := fakeTokenLine('a')
	writeFile(t, filepath.Join(dir, "config.yml"), secret)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	if err := os.MkdirAll(filepath.Join(dir, "backup"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "backup", "config.yml"), secret)

	r, err := runCombined(t, gitAndWorktree(dir, Config{}))
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	assertGitShape(t, r)
	p := mustGitProv(t, r, types.ComputeBlobID([]byte(secret)))
	want := []wtLoc{{"config.yml", a, false}, {"backup/config.yml", "", true}}
	if got := wtLocsOf(p.Locations); !slices.Equal(got, want) {
		t.Fatalf("locations = %v, want %v", got, want)
	}
	if p.BlobPath != "config.yml" || p.Commit == nil || p.Commit.CommitID != a {
		t.Errorf("primary = (%q, %v), want (config.yml, %s)", p.BlobPath, p.Commit, a)
	}
	if p.RepoRoot != absDir(t, dir) {
		t.Errorf("RepoRoot = %q, want %q", p.RepoRoot, absDir(t, dir))
	}
}

// A tracked, unmodified file adds no working-tree location.
func TestCombinedEnumerator_TrackedUnmodifiedAddsNoWorktreeLocation(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	secret := fakeTokenLine('b')
	writeFile(t, filepath.Join(dir, "config.yml"), secret)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")

	r, err := runCombined(t, gitAndWorktree(dir, Config{}))
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	assertGitShape(t, r)
	p := mustGitProv(t, r, types.ComputeBlobID([]byte(secret)))
	want := []wtLoc{{"config.yml", a, false}}
	if got := wtLocsOf(p.Locations); !slices.Equal(got, want) {
		t.Fatalf("locations = %v, want %v", got, want)
	}
}

// Untracked-only content yields one callback per blob carrying every
// working-tree path as a GitProvenance location.
func TestCombinedEnumerator_UntrackedOnlyBlob(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "readme.txt"), "hello\n")
	commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	secret := fakeTokenLine('c')
	if err := os.MkdirAll(filepath.Join(dir, "only"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "only", "b.txt"), secret)
	writeFile(t, filepath.Join(dir, "only", "a.txt"), secret)

	r, err := runCombined(t, gitAndWorktree(dir, Config{}))
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	assertGitShape(t, r)
	p := mustGitProv(t, r, types.ComputeBlobID([]byte(secret)))
	want := []wtLoc{{"only/a.txt", "", true}, {"only/b.txt", "", true}}
	if got := wtLocsOf(p.Locations); !slices.Equal(got, want) {
		t.Fatalf("locations = %v, want %v", got, want)
	}
	if p.BlobPath != "only/a.txt" || p.Commit != nil {
		t.Errorf("primary = (%q, %v), want (only/a.txt, nil)", p.BlobPath, p.Commit)
	}
	if p.RepoRoot != absDir(t, dir) {
		t.Errorf("RepoRoot = %q, want %q", p.RepoRoot, absDir(t, dir))
	}
	if p.RepoPath == "" {
		t.Error("RepoPath is empty")
	}
}

// A modified tracked file: the new content is working-tree only at the same
// path; the committed content keeps its history location alone.
func TestCombinedEnumerator_ModifiedTrackedFile(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	v1 := fakeTokenLine('d')
	v2 := fakeTokenLine('e')
	writeFile(t, filepath.Join(dir, "config.yml"), v1)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "config.yml"), v2)

	r, err := runCombined(t, gitAndWorktree(dir, Config{}))
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	assertGitShape(t, r)
	p1 := mustGitProv(t, r, types.ComputeBlobID([]byte(v1)))
	if got, want := wtLocsOf(p1.Locations), []wtLoc{{"config.yml", a, false}}; !slices.Equal(got, want) {
		t.Errorf("v1 locations = %v, want %v", got, want)
	}
	p2 := mustGitProv(t, r, types.ComputeBlobID([]byte(v2)))
	if got, want := wtLocsOf(p2.Locations), []wtLoc{{"config.yml", "", true}}; !slices.Equal(got, want) {
		t.Errorf("v2 locations = %v, want %v", got, want)
	}
}

// SEC-12: a working-tree failure never drops history blobs. The error is still
// returned after history is reported.
func TestCombinedEnumerator_WorktreeFailureKeepsHistory(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	secret := fakeTokenLine('f')
	writeFile(t, filepath.Join(dir, "config.yml"), secret)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")

	cfg := Config{Root: dir}
	g := NewGitEnumerator(cfg)
	g.WalkAll = true
	bad := cfg
	bad.IgnoreFile = filepath.Join(t.TempDir(), "missing.ignore") // fs Enumerate fails at once
	c := NewCombinedEnumerator(g, NewFilesystemEnumerator(bad))

	r, err := runCombined(t, c)
	switch {
	case err == nil:
		t.Error("Enumerate error = nil, want the working-tree error")
	case !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), bad.IgnoreFile):
		t.Errorf("Enumerate error = %v, want the missing ignore file error (fs.ErrNotExist naming %s)", err, bad.IgnoreFile)
	}
	assertGitShape(t, r)
	p := mustGitProv(t, r, types.ComputeBlobID([]byte(secret)))
	if got, want := wtLocsOf(p.Locations), []wtLoc{{"config.yml", a, false}}; !slices.Equal(got, want) {
		t.Errorf("locations = %v, want %v", got, want)
	}
	for id, prov := range r.provs {
		gp, ok := prov.(types.GitProvenance)
		if !ok {
			continue
		}
		for _, l := range gp.Locations {
			if l.WorkingTree {
				t.Errorf("blob %s has WorkingTree location %q after a failed working-tree walk", id.Hex(), l.Path)
			}
		}
	}
}

// Any other shape keeps today's dedup: git and fs over different roots do not
// merge, and the fs blob keeps its file provenance.
func TestCombinedEnumerator_DifferentRootsKeepDedup(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "readme.txt"), "hello\n")
	commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	other := t.TempDir()
	secret := fakeTokenLine('g')
	writeFile(t, filepath.Join(other, "x.txt"), secret)

	g := NewGitEnumerator(Config{Root: dir})
	g.WalkAll = true
	c := NewCombinedEnumerator(g, NewFilesystemEnumerator(Config{Root: other}))
	r, err := runCombined(t, c)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	assertOneCallbackPerBlob(t, r) // not the --git shape: FileProvenance is expected here
	id := types.ComputeBlobID([]byte(secret))
	if r.calls[id] != 1 {
		t.Fatalf("callbacks = %d, want 1", r.calls[id])
	}
	if _, ok := r.provs[id].(types.FileProvenance); !ok {
		t.Errorf("provenance = %T, want types.FileProvenance", r.provs[id])
	}
}

// Archive members in the working tree are still reported, with their archive
// provenance, when the merge shape is active.
func TestCombinedEnumerator_WorktreeArchiveMembersStillReported(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "readme.txt"), "hello\n")
	commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	secret := fakeTokenLine('h')
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("inner/creds.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(secret)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.zip"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := runCombined(t, gitAndWorktree(dir, Config{ExtractArchives: "zip", ExtractLimits: DefaultExtractionLimits()}))
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	assertGitShape(t, r)
	id := types.ComputeBlobID([]byte(secret))
	if r.calls[id] != 1 {
		t.Fatalf("callbacks = %d, want 1", r.calls[id])
	}
	if _, ok := r.provs[id].(types.ArchiveProvenance); !ok {
		t.Errorf("provenance = %T, want types.ArchiveProvenance", r.provs[id])
	}
}

// A git failure is returned and the prewalk is stopped and joined.
func TestCombinedEnumerator_GitFailureReturnsError(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir() // not a repository
	// Enough files that the prewalk may still be walking when git fails.
	for i := range 500 {
		writeFile(t, filepath.Join(dir, "x"+strconv.Itoa(i)+".txt"), "hello "+strconv.Itoa(i)+"\n")
	}

	type result struct {
		r   *combinedRun
		err error
	}
	ch := make(chan result, 1)
	go func() {
		r, err := runCombined(t, gitAndWorktree(dir, Config{}))
		ch <- result{r, err}
	}()
	var res result
	select {
	case res = <-ch:
	case <-time.After(30 * time.Second):
		t.Fatal("Enumerate did not return within 30s after the git failure")
	}
	if res.err == nil {
		t.Fatal("Enumerate error = nil, want the git error")
	}
	if n := len(res.r.calls); n != 0 {
		t.Errorf("callbacks = %d, want 0 after a git failure", n)
	}

	// The prewalk is joined before Enumerate returns. The prewalk leaves the
	// filesystem walk (and joins its readers) before it signals done, so once
	// Enumerate has returned no goroutine may still be inside it. Checked once,
	// with no polling: a joined prewalk can never show these frames here.
	buf := make([]byte, 1<<20)
	stacks := string(buf[:runtime.Stack(buf, true)])
	for _, frame := range []string{"(*FilesystemEnumerator).Enumerate", "(*FilesystemEnumerator).processFile"} {
		if strings.Contains(stacks, frame) {
			t.Errorf("a goroutine is still in %s after Enumerate returned (prewalk not joined)\n%s", frame, stacks)
		}
	}
}

// F1 (ENG-9178): a secret committed in A, removed in B and restored locally
// (uncommitted) is one blob with two locations: the historical commit A and
// the working-tree copy at the same path. The working-tree copy is not
// dropped because its (blob, path) pair is already in history.
func TestCombinedEnumerator_RestoredBlobKeepsWorkingTreeLocation(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	secret := fakeTokenLine('f')
	writeFile(t, filepath.Join(dir, "config.yml"), secret)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "config.yml"), "TOKEN=redacted\n")
	commitAt(t, dir, "B", "2026-01-02T00:00:00Z")
	writeFile(t, filepath.Join(dir, "config.yml"), secret) // restored locally

	r, err := runCombined(t, gitAndWorktree(dir, Config{}))
	require.NoError(t, err)
	assertGitShape(t, r)
	p := mustGitProv(t, r, types.ComputeBlobID([]byte(secret)))
	want := []wtLoc{{"config.yml", a, false}, {"config.yml", "", true}}
	assert.Equal(t, want, wtLocsOf(p.Locations))
}

// F2 (ENG-9178): a committed path containing "\n" is reported under that
// path only; no location carries a truncated prefix of it ("a").
func TestCombinedEnumerator_NewlineInPathNoPhantomLocation(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	secret := fakeTokenLine('g')
	writeFile(t, filepath.Join(dir, "a\nb.yml"), secret)
	commitAt(t, dir, "A", "2026-01-01T00:00:00Z")

	g := NewGitEnumerator(Config{Root: dir})
	g.WalkAll = true
	r, err := runCombined(t, NewCombinedEnumerator(g))
	require.NoError(t, err)
	p := mustGitProv(t, r, types.ComputeBlobID([]byte(secret)))
	paths := make([]string, 0, len(p.Locations))
	for _, l := range p.Locations {
		paths = append(paths, l.Path)
	}
	assert.Equal(t, []string{"a\nb.yml"}, paths, "locations %v", wtLocsOf(p.Locations))
}

// utf16Fixture commits a UTF-16LE (BOM) file w.txt holding a fake token and
// returns the repository and the BlobID of its decoded UTF-8 text, which is
// what the filesystem enumerator reports for the same file.
func utf16Fixture(t *testing.T) (dir string, decoded types.BlobID) {
	t.Helper()
	skipIfNoGit(t)
	dir = t.TempDir()
	initGitRepo(t, dir)
	text := fakeTokenLine('h')
	require.NoError(t, os.WriteFile(filepath.Join(dir, "w.txt"), encodeUTF16(t, text, false, true), 0o644))
	commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	return dir, types.ComputeBlobID([]byte(text))
}

// F4 (ENG-9178): a tracked, unmodified UTF-16 file is one blob under --git:
// history and working tree name it by the same BlobID, so it is reported
// once, with its committed location and no working-tree location.
func TestCombinedEnumerator_UTF16TrackedUnmodifiedReportedOnce(t *testing.T) {
	dir, decoded := utf16Fixture(t)

	r, err := runCombined(t, gitAndWorktree(dir, Config{}))
	require.NoError(t, err)
	var ids []string
	for id, p := range r.provs {
		if gp, ok := p.(types.GitProvenance); ok && slices.ContainsFunc(gp.Locations, func(l types.GitLocation) bool { return l.Path == "w.txt" }) {
			ids = append(ids, id.Hex())
		}
	}
	assert.Equal(t, []string{decoded.Hex()}, ids, "blobs holding w.txt (want only the decoded-content BlobID)")
}

// F4, history side: the native and go-git history walks name a UTF-16 blob
// by the BlobID of the decoded text they hand to the matcher, as the
// filesystem enumerator and the single-commit walk do, not by the raw git
// object hash.
func TestGitHistory_UTF16BlobIDIsDecodedContent(t *testing.T) {
	dir, decoded := utf16Fixture(t)
	for name, run := range map[string]func(*testing.T, *GitEnumerator) nativeRun{
		"native": runNative,
		"go-git": runGoGit,
	} {
		t.Run(name, func(t *testing.T) {
			r := run(t, NewGitEnumerator(Config{Root: dir}))
			assert.Equal(t, []types.BlobID{decoded}, slices.Collect(maps.Keys(r.calls)))
		})
	}
	single := runSingleCommit(t, dir)
	assert.Equal(t, []types.BlobID{decoded}, slices.Collect(maps.Keys(single.calls)), "single-commit walk (control)")
}

// ENG-9178: headBlobs is empty whenever HEAD's tree cannot be listed, so
// every working-tree path is kept. An unborn HEAD (no commit yet) is
// expected and silent; a HEAD that resolves but whose tree object is gone is
// a real failure and is warned on, as the scan then reports tracked files
// as working-tree locations too.
func TestHeadBlobs_WarnsUnlessUnborn(t *testing.T) {
	skipIfNoGit(t)

	t.Run("unborn HEAD", func(t *testing.T) {
		dir := t.TempDir()
		initGitRepo(t, dir)
		writeFile(t, filepath.Join(dir, "c.yml"), fakeTokenLine('v'))

		var warn bytes.Buffer
		head := headBlobs(context.Background(), dir, &warn)
		assert.Empty(t, head)
		assert.NotContains(t, warn.String(), "warning:")
	})

	t.Run("HEAD tree object missing", func(t *testing.T) {
		dir := t.TempDir()
		initGitRepo(t, dir)
		writeFile(t, filepath.Join(dir, "c.yml"), fakeTokenLine('w'))
		commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
		out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD^{tree}").Output()
		require.NoError(t, err)
		tree := strings.TrimSpace(string(out))
		require.NoError(t, os.Remove(filepath.Join(dir, ".git", "objects", tree[:2], tree[2:])))

		var warn bytes.Buffer
		head := headBlobs(context.Background(), dir, &warn)
		assert.Empty(t, head)
		assert.Contains(t, warn.String(), "warning:")
	})
}

// ENG-9178: a scan rooted at a subdirectory of a repository names
// working-tree files relative to that root ("c.yml") while history names
// them relative to the repository ("sub/c.yml"). A tracked, unmodified
// sub/c.yml is therefore reported once, at its history location only, not
// again as a working-tree "c.yml". A file restored to a blob only an older
// commit held still keeps its working-tree location.
func TestCombinedEnumerator_SubdirRootTrackedUnmodified(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	tracked := fakeTokenLine('s')
	restored := fakeTokenLine('t')
	writeFile(t, filepath.Join(dir, "sub", "c.yml"), tracked)
	writeFile(t, filepath.Join(dir, "sub", "m.yml"), restored)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "sub", "m.yml"), "TOKEN=redacted\n")
	commitAt(t, dir, "B", "2026-01-02T00:00:00Z")
	writeFile(t, filepath.Join(dir, "sub", "m.yml"), restored) // restored locally

	r, err := runCombined(t, gitAndWorktree(filepath.Join(dir, "sub"), Config{}))
	require.NoError(t, err)
	assertGitShape(t, r)

	c := mustGitProv(t, r, types.ComputeBlobID([]byte(tracked)))
	assert.Equal(t, []wtLoc{{"sub/c.yml", a, false}}, wtLocsOf(c.Locations), "tracked, unmodified")

	m := mustGitProv(t, r, types.ComputeBlobID([]byte(restored)))
	assert.Equal(t, []wtLoc{{"sub/m.yml", a, false}, {"m.yml", "", true}}, wtLocsOf(m.Locations), "restored")
}

// ENG-9178: in a SHA-256 repository the working-tree BlobID (SHA-1 of the
// content) never equals HEAD's object id, so headHolds hashes the file as
// git does. A tracked, unmodified file adds no working-tree location; a
// file restored to a blob only an older commit held keeps it.
func TestCombinedEnumerator_SHA256TrackedAndRestored(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepoFormat(t, dir, "sha256")
	restored := fakeTokenLine('q')
	unmodified := fakeTokenLine('r')
	writeFile(t, filepath.Join(dir, "c.yml"), restored)
	writeFile(t, filepath.Join(dir, "k.yml"), unmodified)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "c.yml"), "x\n")
	commitAt(t, dir, "B", "2026-01-02T00:00:00Z")
	writeFile(t, filepath.Join(dir, "c.yml"), restored)

	r, err := runCombined(t, gitAndWorktree(dir, Config{}))
	require.NoError(t, err)
	assertGitShape(t, r)

	c := mustGitProv(t, r, types.ComputeBlobID([]byte(restored)))
	assert.Equal(t, []wtLoc{{"c.yml", a, false}, {"c.yml", "", true}}, wtLocsOf(c.Locations), "restored")
	k := mustGitProv(t, r, types.ComputeBlobID([]byte(unmodified)))
	assert.Equal(t, []wtLoc{{"k.yml", a, false}}, wtLocsOf(k.Locations), "unmodified")
}

// ENG-9178: on an orphan branch HEAD is unborn, so nothing in the working
// tree is tracked by HEAD. A file whose blob another branch committed keeps
// both its commit location and its working-tree location, and the unborn
// HEAD is not warned about.
func TestCombinedEnumerator_OrphanUnbornHeadKeepsWorkingTree(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	secret := fakeTokenLine('u')
	writeFile(t, filepath.Join(dir, "c.yml"), secret)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	runGit(t, dir, "checkout", "-q", "--orphan", "fresh")

	var warn bytes.Buffer
	cfg := Config{Root: dir}
	g := NewGitEnumerator(cfg)
	g.WalkAll = true
	g.warn = &warn
	r, err := runCombined(t, NewCombinedEnumerator(g, NewFilesystemEnumerator(cfg)))
	require.NoError(t, err)
	assertGitShape(t, r)

	p := mustGitProv(t, r, types.ComputeBlobID([]byte(secret)))
	assert.Equal(t, []wtLoc{{"c.yml", a, false}, {"c.yml", "", true}}, wtLocsOf(p.Locations))
	assert.NotContains(t, warn.String(), "warning:")
}

// When the history index is truncated, a blob's older path can be held by
// HEAD yet missing from the history locations. y.txt and x.txt hold the same
// content, committed in A and B. With room for one pair, the index keeps only
// x.txt@B, so y.txt is deferred until git has reported every blob. It must
// then be reported once, as a working-tree location; x.txt keeps its commit.
func TestCombinedEnumerator_HeadHeldPathNoHistoryRecordsIsReportedOnce(t *testing.T) {
	skipIfNoGit(t)
	lowerIndexCap(t, 1)
	dir := t.TempDir()
	initGitRepo(t, dir)
	text := fakeTokenLine('y')
	writeFile(t, filepath.Join(dir, "y.txt"), text)
	commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "x.txt"), text)
	b := commitAt(t, dir, "B", "2026-01-02T00:00:00Z")

	got := newAllLocs()
	require.NoError(t, gitAndWorktree(dir, Config{}).Enumerate(context.Background(), got.callback))

	id := types.ComputeBlobID([]byte(text))
	assert.Equal(t, []wtLoc{{"x.txt", b, false}, {"y.txt", "", true}}, got.of(id),
		"locations across all callbacks")
	ys := slices.DeleteFunc(slices.Clone(got.locs[id]), func(l wtLoc) bool { return l.path != "y.txt" })
	assert.Len(t, ys, 1, "y.txt is reported by exactly one callback")
}
