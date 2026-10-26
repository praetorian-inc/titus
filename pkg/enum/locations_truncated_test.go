package enum

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
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
