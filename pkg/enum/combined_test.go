package enum

import (
	"context"
	"errors"
	"os"
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
