package enum

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/go-git/go-git/v5"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Edge cases of the R1 locations-truncated marker: an index that could not be
// built, a decoded (UTF-16) working-tree file, and parsing after the cap.
// Like locations_truncated_test.go these lower the package-global
// maxIndexPairs or swap os.Stderr, so none may call t.Parallel.

// failingIndex is a history index builder that always fails.
func failingIndex(context.Context, string) (*blobIndex, error) {
	return nil, errors.New("boom")
}

// captureStderr redirects os.Stderr until the returned function is called,
// which restores it and returns what was written.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	var once sync.Once
	restore := func() {
		once.Do(func() {
			os.Stderr = old
			_ = w.Close()
			<-done
			_ = r.Close()
		})
	}
	t.Cleanup(restore)
	return func() string {
		restore()
		return buf.String()
	}
}

// cloneWorktreeProvs runs a clone enumeration and returns every working-tree
// file's provenance by path, and every provenance including the clone's .git
// files.
func cloneWorktreeProvs(t *testing.T, e *CloneEnumerator) (tree map[string]types.GitProvenance, all []types.GitProvenance) {
	t.Helper()
	var mu sync.Mutex
	tree = map[string]types.GitProvenance{}
	err := e.Enumerate(context.Background(), func(_ []byte, _ types.BlobID, prov types.Provenance) error {
		mu.Lock()
		defer mu.Unlock()
		gp, ok := prov.(types.GitProvenance)
		if !ok {
			t.Errorf("non-git provenance %T", prov)
			return nil
		}
		all = append(all, gp)
		if !strings.HasPrefix(gp.BlobPath, ".git/") {
			tree[gp.BlobPath] = gp
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	return tree, all
}

func cloneOf(dir string) *CloneEnumerator {
	return NewCloneEnumerator([]RepoInfo{{Name: "test/repo", CloneURL: "file://" + dir}}, Config{MaxFileSize: 1 << 20})
}

// --- F2: an index that could not be built marks every blob -----------------

// Native --git: every rev-list blob is still enumerated once, at its one
// rev-list path, without commit metadata, and marked. A built index on the
// same repository marks none.
func TestNativeGitEnumerator_IndexFailureMarksEveryBlob(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	a, b, c := threeCommitRepo(t, dir)
	wantPath := map[types.BlobID]string{
		types.ComputeBlobID([]byte(a)): "a.txt",
		types.ComputeBlobID([]byte(b)): "b.txt",
		types.ComputeBlobID([]byte(c)): "c.txt",
	}

	for _, tc := range []struct {
		name     string
		fail     bool
		wantWarn string
	}{
		{"index failed", true, "titus: git history index unavailable: boom; each blob falls back to one path and is marked as possibly missing locations\n"},
		{"index built", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var warn bytes.Buffer
			e := nativeEnum(dir)
			e.warn = &warn
			if tc.fail {
				e.buildIndex = failingIndex
			}
			r := runNative(t, e)
			if len(r.provs) != len(wantPath) {
				t.Fatalf("blobs enumerated = %d, want %d", len(r.provs), len(wantPath))
			}
			for id, path := range wantPath {
				p, ok := r.provs[id]
				if !ok {
					t.Errorf("blob at %s not enumerated", path)
					continue
				}
				if r.calls[id] != 1 {
					t.Errorf("%s: %d callbacks, want 1", path, r.calls[id])
				}
				if p.BlobPath != path {
					t.Errorf("BlobPath = %q, want %q", p.BlobPath, path)
				}
				if p.LocationsTruncated != tc.fail {
					t.Errorf("%s: LocationsTruncated = %v, want %v", path, p.LocationsTruncated, tc.fail)
				}
				if (p.Commit == nil) != tc.fail {
					t.Errorf("%s: Commit = %+v, want nil only when the index failed", path, p.Commit)
				}
			}
			if got := warn.String(); got != tc.wantWarn {
				t.Errorf("warnings = %q, want %q", got, tc.wantWarn)
			}
		})
	}
}

// Clone, filesystem mode: every file (the clone's .git files included) is
// still scanned and marked, without commit metadata; a built index marks
// none of the committed files.
func TestCloneEnumerator_IndexFailureMarksEveryFile(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	threeCommitRepo(t, dir)
	const wantWarn = "titus: git history index unavailable: boom; files are scanned without commit metadata and marked as possibly missing locations\n"

	for _, fail := range []bool{true, false} {
		t.Run(fmt.Sprintf("failed=%v", fail), func(t *testing.T) {
			e := cloneOf(dir)
			if fail {
				e.buildIndex = failingIndex
			}
			stderr := captureStderr(t)
			tree, all := cloneWorktreeProvs(t, e)
			gotErr := stderr()

			if got := slices.Sorted(func(yield func(string) bool) {
				for p := range tree {
					if !yield(p) {
						return
					}
				}
			}); !slices.Equal(got, []string{"a.txt", "b.txt", "c.txt"}) {
				t.Fatalf("working-tree files = %v", got)
			}
			for path, p := range tree {
				if p.LocationsTruncated != fail {
					t.Errorf("%s: LocationsTruncated = %v, want %v", path, p.LocationsTruncated, fail)
				}
				if (p.Commit == nil) != fail {
					t.Errorf("%s: Commit = %+v, want nil only when the index failed", path, p.Commit)
				}
			}
			if fail {
				for _, p := range all {
					if !p.LocationsTruncated {
						t.Errorf("%s: unmarked after index failure", p.BlobPath)
					}
				}
			}
			if n := strings.Count(gotErr, wantWarn); n != btoi(fail) {
				t.Errorf("stderr has %d index-unavailable warnings, want %d:\n%s", n, btoi(fail), gotErr)
			}
		})
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// A repository with no commits has an empty, valid history: the index is not
// a failure, and nothing in a clone of it is marked.
func TestBlobIndex_CommitlessRepoMarksNothing(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)

	idx, err := buildBlobIndex(context.Background(), dir)
	if err != nil {
		t.Fatalf("buildBlobIndex on a commitless repo: %v", err)
	}
	if idx.marksAny() || idx.locationsTruncated(contentHash("anything\n")) {
		t.Error("commitless index marks a blob")
	}

	stderr := captureStderr(t)
	_, all := cloneWorktreeProvs(t, cloneOf(dir))
	gotErr := stderr()
	// The clone holds only .git files; under an index failure every one of
	// them would be marked, so they are what this checks.
	if len(all) == 0 {
		t.Fatal("commitless clone enumerated nothing; the check proved nothing")
	}
	for _, p := range all {
		if p.LocationsTruncated {
			t.Errorf("%s marked in a commitless clone", p.BlobPath)
		}
	}
	if strings.Contains(gotErr, "index unavailable") {
		t.Errorf("commitless clone warned of an index failure:\n%s", gotErr)
	}
}

// --- F3: a decoded file is marked when its raw blob is ---------------------

// committedAt over a UTF-16 file whose scanned content is the decoded text.
// The decoded text is committed at other.txt; the raw UTF-16 blob at w.txt.
func TestCommittedAt_DecodedFileUsesRawBlobMark(t *testing.T) {
	const text = "password = hunter2 hunter2 hunter2 hunter2\n"
	rawBytes := encodeUTF16(t, text, false, true)
	if dec, ok := decodeUTF16(rawBytes); !ok || string(dec) != text {
		t.Fatalf("fixture does not decode: %q %v", dec, ok)
	}
	decodedID := types.ComputeBlobID([]byte(text))
	rawID := types.ComputeBlobID(rawBytes)
	file := filepath.Join(t.TempDir(), "w.txt")
	if err := os.WriteFile(file, rawBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "gone.txt")

	newer, older := strings.Repeat("2", 40), strings.Repeat("1", 40)
	parse := func(t *testing.T, cap int, log string) *blobIndex {
		t.Helper()
		if cap > 0 {
			lowerIndexCap(t, cap)
		}
		idx, err := parseBlobIndex(strings.NewReader(log))
		if err != nil {
			t.Fatal(err)
		}
		return idx
	}
	// Newest first: the decoded text at other.txt is kept, the raw blob at
	// w.txt is dropped once the index holds one pair.
	decodedThenRaw := headerAt(newer, "2026-02-01T00:00:00Z", "n") + raw("100644", decodedID.Hex(), "A", "other.txt") +
		headerAt(older, "2026-01-01T00:00:00Z", "o") + raw("100644", rawID.Hex(), "A", "w.txt")
	// The raw blob alone, at w.txt.
	rawOnly := headerAt(newer, "2026-02-01T00:00:00Z", "n") + raw("100644", rawID.Hex(), "A", "w.txt")
	// The decoded text kept at w.txt, an unrelated blob dropped.
	decodedPlusOther := headerAt(newer, "2026-02-01T00:00:00Z", "n") + raw("100644", decodedID.Hex(), "A", "w.txt") +
		raw("100644", hexN(9), "A", "z.txt")

	for _, tc := range []struct {
		name       string
		idx        func(t *testing.T) *blobIndex
		file       string
		wantMarked bool
		wantCommit string // "" means nil
	}{
		{"raw blob dropped, decoded kept elsewhere", func(t *testing.T) *blobIndex { return parse(t, 1, decodedThenRaw) }, file, true, ""},
		{"nothing dropped", func(t *testing.T) *blobIndex { return parse(t, 0, decodedThenRaw) }, file, false, ""},
		{"commit from the raw id", func(t *testing.T) *blobIndex { return parse(t, 0, rawOnly) }, file, false, newer},
		{"unreadable file, index marks another blob", func(t *testing.T) *blobIndex { return parse(t, 1, decodedPlusOther) }, missing, true, newer},
		{"unreadable file, index marks nothing", func(t *testing.T) *blobIndex { return parse(t, 0, decodedPlusOther) }, missing, false, newer},
		{"index unavailable", func(*testing.T) *blobIndex { return unavailableIndex() }, file, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commit, marked := committedAt(tc.idx(t), decodedID, tc.file, "w.txt")
			if marked != tc.wantMarked {
				t.Errorf("marked = %v, want %v", marked, tc.wantMarked)
			}
			switch {
			case tc.wantCommit == "" && commit != nil:
				t.Errorf("commit = %s, want nil", commit.CommitID)
			case tc.wantCommit != "" && (commit == nil || commit.CommitID != tc.wantCommit):
				t.Errorf("commit = %+v, want %s", commit, tc.wantCommit)
			}
		})
	}
}

// End to end: a cloned UTF-16 file whose raw blob lost its location to the
// cap is marked, though its decoded text is a kept, unmarked blob; the file
// holding that text is not marked.
func TestCloneEnumerator_TruncatedRawUTF16BlobMarksDecodedFile(t *testing.T) {
	skipIfNoGit(t)
	lowerIndexCap(t, 1)
	const text = "password = hunter2 hunter2 hunter2 hunter2\n"
	dir := t.TempDir()
	initGitRepo(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "w.txt"), encodeUTF16(t, text, false, true), 0o644); err != nil {
		t.Fatal(err)
	}
	commitAt(t, dir, "utf16", "2026-01-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "other.txt"), text)
	tip := commitAt(t, dir, "utf8", "2026-02-01T00:00:00Z")

	tree, _ := cloneWorktreeProvs(t, cloneOf(dir))
	w, o := tree["w.txt"], tree["other.txt"]
	if w.BlobPath == "" || o.BlobPath == "" {
		t.Fatalf("files missing: %v", tree)
	}
	if !w.LocationsTruncated {
		t.Error("w.txt: raw UTF-16 blob lost its location but the file is not marked")
	}
	if o.LocationsTruncated {
		t.Error("other.txt: kept blob marked")
	}
	if o.Commit == nil || o.Commit.CommitID != tip {
		t.Errorf("other.txt commit = %+v, want %s", o.Commit, tip)
	}
}

// --- F4: after the cap the parser stores nothing new -----------------------

func headerNamed(id, name, date, subject string) string {
	return id + "\x00" + name + "\x00" + name + "@x\x00" + date + "\x00" + name + "c\x00" + name + "c@x\x00" + date + "\x00" + subject + "\x00"
}

// A long history after the cap adds no path, name, arena byte, commit or
// pair: the parser only looks up and marks.
func TestParseBlobIndex_PostCapStoresNothing(t *testing.T) {
	lowerIndexCap(t, 1)
	first := hexN(1)
	prefix := headerNamed(first, "first", "2026-01-01T00:00:00Z", "first") +
		raw("100644", hexN(1), "A", "p1") + // kept
		raw("100644", hexN(2), "A", "p2") // fills the index: dropped
	base, err := parseBlobIndex(strings.NewReader(prefix))
	if err != nil {
		t.Fatal(err)
	}

	const n = 2000
	var more strings.Builder
	for i := range n {
		k := 1000 + i
		more.WriteString(headerNamed(hexN(k), fmt.Sprintf("author%d", k), "2026-06-01T00:00:00Z", strings.Repeat("subject ", 20)))
		more.WriteString(raw("100644", hexN(k), "A", fmt.Sprintf("dir/new-path-%d", k)))
		more.WriteString(raw("100644", hexN(1), "M", "p1")) // later re-touch: nothing lost
	}
	full, err := parseBlobIndex(strings.NewReader(prefix + more.String()))
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name      string
		base, got int
	}{
		{"paths", len(base.paths), len(full.paths)},
		{"commits", len(base.commits), len(full.commits)},
		{"arena", len(base.arena), len(full.arena)},
		{"names", len(base.names), len(full.names)},
		{"pairs", len(base.pairs), len(full.pairs)},
	} {
		if c.got != c.base {
			t.Errorf("len(%s) grew after the cap: %d -> %d", c.name, c.base, c.got)
		}
	}
	if got := locsOf(full.lookup(mustHash(t, hexN(1)))); !slices.Equal(got, []locWant{{"p1", first}}) {
		t.Errorf("kept blob lookup = %+v", got)
	}
	if full.locationsTruncated(mustHash(t, hexN(1))) {
		t.Error("kept blob re-touched later is marked")
	}
	for _, k := range []int{2, 1000, 1000 + n - 1} {
		if !full.locationsTruncated(mustHash(t, hexN(k))) {
			t.Errorf("dropped blob %d not marked", k)
		}
	}
	if want := 1 + 2*n; full.stats.droppedPairs != want {
		t.Errorf("droppedPairs = %d, want %d", full.stats.droppedPairs, want)
	}
}

// After the cap a re-touch of a kept (blob, path) is ordered against the
// commit being parsed, with the index's order (usable time, then id; an
// unusable time sorts last), whatever order the commits arrive in.
func TestParseBlobIndex_PostCapDropUsesCurrentCommitOrder(t *testing.T) {
	lowerIndexCap(t, 6)
	const feb = "2026-02-01T00:00:00Z"
	mid, unusable := strings.Repeat("5", 40), strings.Repeat("9", 40)

	var s strings.Builder
	s.WriteString(headerAt(mid, feb, "mid"))
	for i := 1; i <= 5; i++ { // blobs 1..5 kept at mid
		s.WriteString(raw("100644", hexN(i), "A", fmt.Sprintf("f%d", i)))
	}
	s.WriteString(headerAt(unusable, "not-a-date", "unusable"))
	s.WriteString(raw("100644", hexN(6), "A", "f6"))   // blob 6 kept at the unusable-time commit
	s.WriteString(raw("100644", hexN(99), "A", "f99")) // fills the index

	retouch := func(id, date string, blob int) {
		s.WriteString(headerAt(id, date, "post-cap"))
		s.WriteString(raw("100644", hexN(blob), "M", fmt.Sprintf("f%d", blob)))
	}
	retouch(strings.Repeat("a", 40), "2026-03-01T00:00:00Z", 1) // later: nothing lost
	retouch(strings.Repeat("b", 40), "2026-01-01T00:00:00Z", 2) // earlier: earliest commit lost
	retouch(strings.Repeat("c", 40), "not-a-date", 3)           // unusable time sorts after mid
	retouch(strings.Repeat("1", 40), feb, 4)                    // same time, smaller id: earlier
	retouch(strings.Repeat("7", 40), feb, 5)                    // same time, larger id: later
	retouch(strings.Repeat("d", 40), "2030-01-01T00:00:00Z", 6) // any usable time precedes unusable

	idx, err := parseBlobIndex(strings.NewReader(s.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.commits) != 2 {
		t.Errorf("commits stored = %d, want 2 (none after the cap)", len(idx.commits))
	}
	want := map[int]bool{1: false, 2: true, 3: false, 4: true, 5: false, 6: true, 99: true}
	for blob, w := range want {
		if got := idx.locationsTruncated(mustHash(t, hexN(blob))); got != w {
			t.Errorf("blob %d: marked = %v, want %v", blob, got, w)
		}
	}
}

// commitAs commits everything with one identity as both author and
// committer, at date.
func commitAs(t *testing.T, dir, name, date string) string {
	t.Helper()
	runGit(t, dir, "add", "-A")
	runGitEnv(t, dir, []string{
		"GIT_AUTHOR_NAME=" + name, "GIT_AUTHOR_EMAIL=" + name + "@x", "GIT_AUTHOR_DATE=" + date,
		"GIT_COMMITTER_NAME=" + name, "GIT_COMMITTER_EMAIL=" + name + "@x", "GIT_COMMITTER_DATE=" + date,
	}, "commit", "-q", "--no-gpg-sign", "-m", name)
	return gitOutput(t, dir, "rev-parse", "HEAD")
}

// Both index builders, on a real history walked newest first: once the tip
// commit fills the index, older commits store nothing, and an older commit
// holding the tip's kept (blob, path) marks it, since the tip is not that
// location's earliest commit. Without that older commit the kept blob is
// unmarked.
func TestHistoryIndex_PostCapEarlierRetouchMarksKeptBlob(t *testing.T) {
	skipIfNoGit(t)
	const x, y, z = "x secret\n", "y secret\n", "z secret\n"
	build := func(t *testing.T, earlier bool) (dir, tip string) {
		dir = t.TempDir()
		initGitRepo(t, dir)
		for i := range 3 {
			writeFile(t, filepath.Join(dir, fmt.Sprintf("extra%d.txt", i)), fmt.Sprintf("extra %d\n", i))
			commitAs(t, dir, fmt.Sprintf("extra%d", i), fmt.Sprintf("2025-0%d-01T00:00:00Z", i+1))
		}
		if earlier {
			writeFile(t, filepath.Join(dir, "a.txt"), x)
			commitAs(t, dir, "old", "2026-01-01T00:00:00Z")
		}
		writeFile(t, filepath.Join(dir, "a.txt"), y)
		commitAs(t, dir, "mid", "2026-02-01T00:00:00Z")
		writeFile(t, filepath.Join(dir, "a.txt"), x)
		writeFile(t, filepath.Join(dir, "b.txt"), z)
		return dir, commitAs(t, dir, "tip", "2026-03-01T00:00:00Z")
	}
	builders := map[string]func(t *testing.T, dir string) *blobIndex{
		"native": func(t *testing.T, dir string) *blobIndex {
			idx, err := buildBlobIndex(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			return idx
		},
		"go-git": func(t *testing.T, dir string) *blobIndex {
			repo, err := git.PlainOpen(dir)
			if err != nil {
				t.Fatal(err)
			}
			_, idx, err := goGitHistoryIndex(context.Background(), repo)
			if err != nil {
				t.Fatal(err)
			}
			return idx
		},
	}
	for name, buildIdx := range builders {
		for _, earlier := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/earlier=%v", name, earlier), func(t *testing.T) {
				lowerIndexCap(t, 1)
				dir, tip := build(t, earlier)
				idx := buildIdx(t, dir)

				// Bounds: only the tip is stored, with its two paths and one name.
				if len(idx.commits) != 1 || idx.commitID(&idx.commits[0]) == nil || string(idx.commitID(&idx.commits[0])) != tip {
					t.Errorf("commits stored = %d, want only the tip", len(idx.commits))
				}
				if !slices.Equal(idx.paths, []string{"a.txt", "b.txt"}) {
					t.Errorf("paths = %q, want [a.txt b.txt]", idx.paths)
				}
				if got := slices.Sorted(slices.Values(idx.names)); !slices.Equal(slices.Compact(got), []string{"tip", "tip@x"}) {
					t.Errorf("names = %q, want only the tip's", idx.names)
				}
				if want := len(tip) + len("tip"); len(idx.arena) != want {
					t.Errorf("arena = %d bytes, want %d (tip id and subject)", len(idx.arena), want)
				}

				if got := locsOf(idx.lookup(contentHash(x))); !slices.Equal(got, []locWant{{"a.txt", tip}}) {
					t.Errorf("kept blob lookup = %+v", got)
				}
				if got := idx.locationsTruncated(contentHash(x)); got != earlier {
					t.Errorf("kept blob marked = %v, want %v", got, earlier)
				}
				for _, c := range []string{y, z, "extra 0\n", "extra 2\n"} {
					if !idx.locationsTruncated(contentHash(c)) {
						t.Errorf("dropped blob %q not marked", c)
					}
				}
			})
		}
	}
}
