package enum

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// These tests lower the package-global maxIndexPairs, so none of them (and no
// test in this package) may call t.Parallel.

// lowerIndexCap sets maxIndexPairs for one test and restores it afterwards.
func lowerIndexCap(t *testing.T, n int) {
	t.Helper()
	old := maxIndexPairs
	maxIndexPairs = n
	t.Cleanup(func() { maxIndexPairs = old })
}

func headerAt(id, date, subject string) string {
	return id + "\x00A\x00a@x\x00" + date + "\x00C\x00c@x\x00" + date + "\x00" + subject + "\x00"
}

func hexN(i int) string { return fmt.Sprintf("%040x", i) }

// R1: once the index is full, a blob is marked truncated exactly when a
// location of it was dropped: a new (blob, path) pair — including a new path
// for a blob the index kept — or an existing pair seen at an earlier commit
// than the one recorded. A dropped re-touch at the same or a later commit
// loses nothing and does not mark. Kept locations stay as recorded.
func TestParseBlobIndex_TruncatedBlobsMarked(t *testing.T) {
	lowerIndexCap(t, 3)
	mid, newer, older := strings.Repeat("2", 40), strings.Repeat("3", 40), strings.Repeat("1", 40)

	var s strings.Builder
	s.WriteString(headerAt(mid, "2026-02-01T00:00:00Z", "mid"))
	for i := 1; i <= 6; i++ { // 1..3 kept, 4..6 dropped
		s.WriteString(raw("100644", hexN(i), "A", fmt.Sprintf("f%d", i)))
	}
	s.WriteString(raw("100644", hexN(2), "M", "f2")) // same commit again: nothing lost
	s.WriteString(headerAt(newer, "2026-03-01T00:00:00Z", "newer"))
	s.WriteString(raw("100644", hexN(2), "M", "f2")) // later re-touch: nothing lost
	s.WriteString(raw("100644", hexN(3), "A", "g3")) // kept blob, new path: location lost
	s.WriteString(headerAt(older, "2026-01-01T00:00:00Z", "older"))
	s.WriteString(raw("100644", hexN(1), "A", "f1")) // earlier commit: attribution lost

	idx, err := parseBlobIndex(strings.NewReader(s.String()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[int]bool{1: true, 2: false, 3: true, 4: true, 5: true, 6: true, 7: false}
	for i, w := range want {
		if got := idx.locationsTruncated(mustHash(t, hexN(i))); got != w {
			t.Errorf("locationsTruncated(blob %d) = %v, want %v", i, got, w)
		}
	}
	if idx.stats.droppedPairs != 7 {
		t.Errorf("droppedPairs = %d, want 7", idx.stats.droppedPairs)
	}
	// Kept entries are untouched by the drops: the index still reports the
	// commit it held, which is why the blob must carry the marker.
	for i, w := range map[int][]locWant{
		1: {{"f1", mid}},
		2: {{"f2", mid}},
		3: {{"f3", mid}},
		4: {},
	} {
		if got := locsOf(idx.lookup(mustHash(t, hexN(i)))); !slices.Equal(got, w) {
			t.Errorf("lookup(blob %d) = %+v, want %+v", i, got, w)
		}
	}
	var nilIdx *blobIndex
	if nilIdx.locationsTruncated(mustHash(t, hexN(1))) {
		t.Error("nil index reports a truncated blob")
	}
}

// An index that never reached the cap marks nothing.
func TestParseBlobIndex_UntruncatedMarksNothing(t *testing.T) {
	c := strings.Repeat("1", 40)
	idx, err := parseBlobIndex(strings.NewReader(header(c, "s") + raw("100644", hexN(1), "A", "f")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if idx.truncated() || idx.locationsTruncated(mustHash(t, hexN(1))) {
		t.Error("untruncated index marks a blob")
	}
}

// threeCommitRepo commits a.txt, b.txt, c.txt in that order, oldest first,
// and returns their contents.
func threeCommitRepo(t *testing.T, dir string) (a, b, c string) {
	t.Helper()
	initGitRepo(t, dir)
	a, b, c = "alpha secret\n", "bravo secret\n", "charlie secret\n"
	writeFile(t, filepath.Join(dir, "a.txt"), a)
	commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "b.txt"), b)
	commitAt(t, dir, "B", "2026-02-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "c.txt"), c)
	commitAt(t, dir, "C", "2026-03-01T00:00:00Z")
	return a, b, c
}

// checkTruncationMarks asserts every blob was enumerated with its path
// (rev-list stays the authority) and only the blobs whose pairs were dropped
// carry the marker.
func checkTruncationMarks(t *testing.T, provs map[types.BlobID]types.GitProvenance, kept string, dropped ...string) {
	t.Helper()
	if len(provs) != 1+len(dropped) {
		t.Fatalf("blobs enumerated = %d, want %d", len(provs), 1+len(dropped))
	}
	k, ok := provs[types.ComputeBlobID([]byte(kept))]
	if !ok {
		t.Fatalf("kept blob %q not enumerated", kept)
	}
	if k.LocationsTruncated {
		t.Errorf("kept blob %q marked LocationsTruncated", kept)
	}
	if k.Commit == nil {
		t.Errorf("kept blob %q lost its commit", kept)
	}
	for _, d := range dropped {
		p, ok := provs[types.ComputeBlobID([]byte(d))]
		if !ok {
			t.Errorf("dropped blob %q not enumerated", d)
			continue
		}
		if !p.LocationsTruncated {
			t.Errorf("dropped blob %q: LocationsTruncated = false, want true", d)
		}
		if p.BlobPath == "" {
			t.Errorf("dropped blob %q enumerated without a path", d)
		}
	}
}

// Three blobs, room for one pair: two are dropped.
const truncWarning = "titus: git history index reached 1 locations; 2 more were not recorded, so location lists may be incomplete\n"

// Native pipeline: git log emits newest first, so with room for one pair
// c.txt is kept and a.txt and b.txt are dropped.
func TestNativeGitEnumerator_TruncatedIndexMarksAffectedBlobs(t *testing.T) {
	skipIfNoGit(t)
	lowerIndexCap(t, 1)
	dir := t.TempDir()
	a, b, c := threeCommitRepo(t, dir)
	var warn bytes.Buffer
	e := nativeEnum(dir)
	e.warn = &warn

	r := runNative(t, e)
	checkTruncationMarks(t, r.provs, c, a, b)
	for id, n := range r.calls {
		if n != 1 {
			t.Errorf("blob %s: %d callbacks, want 1", id.Hex(), n)
		}
	}
	if got := warn.String(); strings.Count(got, truncWarning) != 1 {
		t.Errorf("warning = %q, want exactly one %q", got, truncWarning)
	}
}

// go-git fallback: the walk starts at the tip, so c.txt is kept.
func TestGoGitEnumerator_TruncatedIndexMarksAffectedBlobs(t *testing.T) {
	skipIfNoGit(t)
	lowerIndexCap(t, 1)
	dir := t.TempDir()
	a, b, c := threeCommitRepo(t, dir)
	var warn bytes.Buffer
	e := nativeEnum(dir)
	e.warn = &warn

	provs := map[types.BlobID]types.GitProvenance{}
	err := e.enumerateAllHistory(context.Background(), func(_ []byte, id types.BlobID, prov types.Provenance) error {
		provs[id] = prov.(types.GitProvenance)
		return nil
	})
	if err != nil {
		t.Fatalf("enumerateAllHistory: %v", err)
	}
	checkTruncationMarks(t, provs, c, a, b)
	if got := warn.String(); strings.Count(got, truncWarning) != 1 {
		t.Errorf("warning = %q, want exactly one %q", got, truncWarning)
	}
}

// Clone, filesystem mode: the working-tree blob whose history pair was
// dropped is marked; the kept one is not.
func TestCloneEnumerator_TruncatedIndexMarksAffectedBlobs(t *testing.T) {
	skipIfNoGit(t)
	lowerIndexCap(t, 1)
	dir := t.TempDir()
	a, b, c := threeCommitRepo(t, dir)

	e := NewCloneEnumerator([]RepoInfo{{Name: "test/repo", CloneURL: "file://" + dir}}, Config{MaxFileSize: 1 << 20})
	var mu sync.Mutex
	provs := map[types.BlobID]types.GitProvenance{}
	err := e.Enumerate(context.Background(), func(_ []byte, id types.BlobID, prov types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
		// Filesystem mode also walks the clone's .git directory.
		if gp, ok := prov.(types.GitProvenance); ok && !strings.HasPrefix(gp.BlobPath, ".git/") {
			provs[id] = gp
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	checkTruncationMarks(t, provs, c, a, b)
}

// Combined (--git plus working tree): the marker survives the working-tree
// merge, and a working-tree-only blob is never marked.
func TestCombinedEnumerator_TruncatedIndexMarkSurvivesMerge(t *testing.T) {
	skipIfNoGit(t)
	lowerIndexCap(t, 1)
	dir := t.TempDir()
	a, _, c := threeCommitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "copy-of-a.txt"), a)
	const untracked = "untracked only\n"
	writeFile(t, filepath.Join(dir, "new.txt"), untracked)

	r, err := runCombined(t, gitAndWorktree(dir, Config{}))
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	pa := mustGitProv(t, r, types.ComputeBlobID([]byte(a)))
	if !pa.LocationsTruncated {
		t.Error("dropped blob lost LocationsTruncated through the working-tree merge")
	}
	if !slices.ContainsFunc(pa.Locations, func(l types.GitLocation) bool {
		return l.Path == "copy-of-a.txt" && l.WorkingTree
	}) {
		t.Errorf("working-tree location missing: %+v", wtLocsOf(pa.Locations))
	}
	if mustGitProv(t, r, types.ComputeBlobID([]byte(c))).LocationsTruncated {
		t.Error("kept blob marked")
	}
	if mustGitProv(t, r, types.ComputeBlobID([]byte(untracked))).LocationsTruncated {
		t.Error("working-tree-only blob marked")
	}
}

// The field is omitted from JSON unless set.
func TestGitProvenance_LocationsTruncatedJSON(t *testing.T) {
	off, err := json.Marshal(types.GitProvenance{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(off, []byte("LocationsTruncated")) {
		t.Errorf("unset field serialized: %s", off)
	}
	on, err := json.Marshal(types.GitProvenance{LocationsTruncated: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(on, []byte(`"LocationsTruncated":true`)) {
		t.Errorf("set field missing: %s", on)
	}
}
