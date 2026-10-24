package enum

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// checkedRun is a native history walk that also keeps each blob's content.
type checkedRun struct {
	nativeRun
	content map[types.BlobID]string
}

// runNativeChecked walks history and fails if any callback's BlobID is not
// the content's BlobID: the ID must describe the bytes that were scanned.
func runNativeChecked(t *testing.T, e *GitEnumerator) checkedRun {
	t.Helper()
	r := checkedRun{
		nativeRun: nativeRun{calls: map[types.BlobID]int{}, provs: map[types.BlobID]types.GitProvenance{}},
		content:   map[types.BlobID]string{},
	}
	err := e.enumerateAllHistoryNative(context.Background(), func(content []byte, id types.BlobID, prov types.Provenance) error {
		if want := types.ComputeBlobID(content); id != want {
			t.Errorf("blob id %s does not match its content %q (content id %s)", id.Hex(), content, want.Hex())
		}
		r.calls[id]++
		r.provs[id] = prov.(types.GitProvenance)
		r.content[id] = string(content)
		return nil
	})
	if err != nil {
		t.Fatalf("enumerateAllHistoryNative: %v", err)
	}
	return r
}

// initGitRepoFormat initializes dir with the given object format, skipping
// the test when git cannot create it.
func initGitRepoFormat(t *testing.T, dir, format string) {
	t.Helper()
	if out, err := exec.Command("git", "init", "-q", "--object-format="+format, dir).CombinedOutput(); err != nil {
		t.Skipf("git cannot create a %s repository: %v %s", format, err, out)
	}
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test User")
}

func isHexOfLen(s string, n int) bool {
	_, err := hex.DecodeString(s)
	return len(s) == n && err == nil
}

// SEC-8: a SHA-256 repository is enumerated exactly like a SHA-1 one. The
// secret blob is yielded once under the content's BlobID, with the
// repository, every nested path and the full commit id of each location.
func TestNativeGitEnumerator_ObjectFormats(t *testing.T) {
	skipIfNoGit(t)
	for _, tc := range []struct {
		format string
		hexLen int
	}{
		{"sha1", 40},
		{"sha256", 64},
	} {
		t.Run(tc.format, func(t *testing.T) {
			dir := t.TempDir()
			initGitRepoFormat(t, dir, tc.format)
			const secret = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
			if err := os.MkdirAll(filepath.Join(dir, "deploy", "prod"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(dir, "deploy", "prod", "app.env"), secret)
			a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
			if err := os.MkdirAll(filepath.Join(dir, "other"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(dir, "other", "copy.env"), secret)
			b := commitAt(t, dir, "B", "2026-02-01T00:00:00Z")
			if !isHexOfLen(a, tc.hexLen) || !isHexOfLen(b, tc.hexLen) {
				t.Fatalf("fixture commits %q, %q are not %d-hex", a, b, tc.hexLen)
			}

			r := runNativeChecked(t, nativeEnum(dir))
			x := types.ComputeBlobID([]byte(secret))
			if got := r.calls[x]; got != 1 {
				t.Fatalf("callbacks for secret blob = %d, want 1 (blobs seen: %d)", got, len(r.calls))
			}
			if r.content[x] != secret {
				t.Errorf("scanned content = %q, want %q", r.content[x], secret)
			}
			p := r.provs[x]
			if p.RepoPath != dir {
				t.Errorf("repository = %q, want %q", p.RepoPath, dir)
			}
			want := []locWant{{"deploy/prod/app.env", a}, {"other/copy.env", b}}
			if got := locsOf(p.Locations); !slices.Equal(got, want) {
				t.Fatalf("locations = %v, want %v", got, want)
			}
			if p.BlobPath != "deploy/prod/app.env" || p.Commit == nil || p.Commit.CommitID != a {
				t.Errorf("primary = (%q, %v), want (deploy/prod/app.env, %s)", p.BlobPath, p.Commit, a)
			}
		})
	}
}

// SEC-8: in a SHA-256 repository rev-list object lines carry a 64-hex id.
// A line whose id is not exactly 64 lowercase hex characters followed by a
// space is not an object line and yields no blob.
func TestReadRevList_SHA256IDs(t *testing.T) {
	hugePath := strings.Repeat("q", 2<<20)
	in := strings.Join([]string{
		strings.Repeat("c", 64),                       // commit: no path, skipped
		strings.Repeat("d", 64) + " deploy/app.env",   // kept
		strings.Repeat("a", 41) + " forty-one.yml",    // skipped
		strings.Repeat("a", 63) + " sixty-three.yml",  // skipped
		strings.Repeat("a", 65) + " sixty-five.yml",   // skipped
		strings.Repeat("g", 64) + " not-hex.yml",      // skipped
		strings.Repeat("e", 64) + " nested/dir/b.yml", // kept
		strings.Repeat("f", 64) + " " + hugePath,      // over the cap: id kept, path dropped
	}, "\n") + "\n"

	rl, err := parseRevList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	got := rl.blobs
	if rl.overlong != 1 {
		t.Errorf("overlong = %d, want 1", rl.overlong)
	}
	var paths []string
	for _, b := range got {
		paths = append(paths, b.path)
	}
	if want := []string{"deploy/app.env", "nested/dir/b.yml", ""}; !slices.Equal(paths, want) {
		t.Errorf("paths = %q, want %q", paths, want)
	}
}

// SEC-13: replace refs are not followed. The blob at a.txt is scanned with
// its own bytes and attributed to a.txt; the replacement object never takes
// over that location.
func TestNativeGitEnumerator_IgnoresReplaceRefs(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	const original = "TOKEN=ghp_cccccccccccccccccccccccccccccccccccc\n"
	const replacement = "nothing to see here\n"
	writeFile(t, filepath.Join(dir, "a.txt"), original)
	c := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	orig := gitOutput(t, dir, "rev-parse", "HEAD:a.txt")
	repl := hashBlob(t, dir, replacement)
	runGit(t, dir, "replace", orig, repl)

	// Sanity: the fixture is live; an unhardened cat-file follows the ref.
	if got := gitOutput(t, dir, "cat-file", "-p", orig); got != strings.TrimSpace(replacement) {
		t.Fatalf("fixture is not live: cat-file %s = %q", orig, got)
	}

	r := runNativeChecked(t, nativeEnum(dir))
	x := types.ComputeBlobID([]byte(original))
	if r.calls[x] != 1 {
		t.Fatalf("original blob callbacks = %d, want 1", r.calls[x])
	}
	if r.content[x] != original {
		t.Errorf("original blob content = %q, want %q", r.content[x], original)
	}
	if got, want := locsOf(r.provs[x].Locations), []locWant{{"a.txt", c}}; !slices.Equal(got, want) {
		t.Errorf("original blob locations = %v, want %v", got, want)
	}
	y := types.ComputeBlobID([]byte(replacement))
	for _, l := range r.provs[y].Locations {
		if l.Path == "a.txt" {
			t.Errorf("replacement blob claims a.txt: %+v", r.provs[y])
		}
	}
}

// parseRevListIDs parses in and returns each blob's full hex id and path.
func parseRevListIDs(t *testing.T, in string) (revList, []string, []string) {
	t.Helper()
	rl, err := parseRevList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if rl.sha256() && len(rl.tails) != len(rl.blobs) {
		t.Fatalf("tails = %d, blobs = %d: not parallel", len(rl.tails), len(rl.blobs))
	}
	var ids, paths []string
	for i, b := range rl.blobs {
		ids = append(ids, string(rl.objectHex(nil, i)))
		paths = append(paths, b.path)
	}
	return rl, ids, paths
}

// SEC-8: two SHA-256 blobs that share the 20-byte index key are distinct
// objects. Both are emitted, each with its own full id, and only a repeat of
// the same full id is deduplicated.
func TestParseRevList_SHA256SharedPrefixBothKept(t *testing.T) {
	prefix := strings.Repeat("a", 40)
	id1 := prefix + strings.Repeat("1", 24)
	id2 := prefix + strings.Repeat("2", 24)
	in := strings.Join([]string{
		strings.Repeat("c", 64), // commit
		id1 + " first.env",
		id2 + " second.env",
		id1 + " again.env", // same full id: duplicate
	}, "\n") + "\n"

	rl, ids, paths := parseRevListIDs(t, in)
	if !rl.sha256() {
		t.Fatal("sha256() = false for a 64-hex stream")
	}
	if want := []string{id1, id2}; !slices.Equal(ids, want) {
		t.Errorf("ids = %q, want %q", ids, want)
	}
	if want := []string{"first.env", "second.env"}; !slices.Equal(paths, want) {
		t.Errorf("paths = %q, want %q", paths, want)
	}
	if rl.malformed != 0 || rl.overlong != 0 {
		t.Errorf("malformed, overlong = %d, %d, want 0, 0", rl.malformed, rl.overlong)
	}
}

// SEC-8: the first valid line fixes the id width. A line of the other width
// is malformed: it is counted and yields no blob.
func TestParseRevList_MixedWidthsMalformed(t *testing.T) {
	s1 := func(c string) string { return strings.Repeat(c, 40) }
	s256 := func(c string) string { return strings.Repeat(c, 64) }
	for _, tc := range []struct {
		name          string
		lines         []string
		wantIDs       []string
		wantSHA256    bool
		wantMalformed int
	}{
		{
			name:          "sha256 first",
			lines:         []string{s256("c"), s256("d") + " keep.env", s1("b") + " drop.env", s1("e"), s256("f") + " keep2.env"},
			wantIDs:       []string{s256("d"), s256("f")},
			wantSHA256:    true,
			wantMalformed: 2,
		},
		{
			name:          "sha1 first",
			lines:         []string{s1("c"), s1("d") + " keep.env", s256("b") + " drop.env", s256("e"), s1("f") + " keep2.env"},
			wantIDs:       []string{s1("d"), s1("f")},
			wantMalformed: 2,
		},
		{
			name:          "invalid lines do not fix the width",
			lines:         []string{"garbage", strings.Repeat("A", 64) + " upper.env", s1("d") + " keep.env", s256("e") + " drop.env"},
			wantIDs:       []string{s1("d")},
			wantMalformed: 3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rl, ids, _ := parseRevListIDs(t, strings.Join(tc.lines, "\n")+"\n")
			if !slices.Equal(ids, tc.wantIDs) {
				t.Errorf("ids = %q, want %q", ids, tc.wantIDs)
			}
			if rl.sha256() != tc.wantSHA256 {
				t.Errorf("sha256() = %v, want %v", rl.sha256(), tc.wantSHA256)
			}
			if rl.malformed != tc.wantMalformed {
				t.Errorf("malformed = %d, want %d", rl.malformed, tc.wantMalformed)
			}
		})
	}
}

// SEC-9: an over-long SHA-256 line keeps its full 64-hex id, tail included,
// so the blob is still fetched and scanned; only its path is dropped.
func TestParseRevList_SHA256OverlongKeepsFullID(t *testing.T) {
	id := strings.Repeat("a", 40) + strings.Repeat("9", 24)
	in := strings.Repeat("c", 64) + "\n" + id + " " + strings.Repeat("q", 2<<20) + "\n" +
		strings.Repeat("b", 64) + " after.env\n"

	rl, ids, paths := parseRevListIDs(t, in)
	if want := []string{id, strings.Repeat("b", 64)}; !slices.Equal(ids, want) {
		t.Errorf("ids = %q, want %q", ids, want)
	}
	if want := []string{"", "after.env"}; !slices.Equal(paths, want) {
		t.Errorf("paths = %q, want %q", paths, want)
	}
	if rl.overlong != 1 || rl.malformed != 0 {
		t.Errorf("overlong, malformed = %d, %d, want 1, 0", rl.overlong, rl.malformed)
	}
}

// A cat-file header is trusted only if it answers the request: another id,
// a negative size or a missing size means the stream cannot be framed.
func TestParseCatFileHeader(t *testing.T) {
	want := strings.Repeat("d", 64)
	other := strings.Repeat("e", 64)
	for _, tc := range []struct {
		name        string
		line        string
		wantType    string
		wantSize    int64
		wantMissing bool
		wantErr     bool
	}{
		{name: "blob", line: want + " blob 12\n", wantType: "blob", wantSize: 12},
		{name: "zero size", line: want + " blob 0\n", wantType: "blob"},
		{name: "missing", line: want + " missing\n", wantMissing: true},
		{name: "echoed id mismatch", line: other + " blob 12\n", wantErr: true},
		{name: "mismatched id reported missing", line: other + " missing\n", wantErr: true},
		{name: "id prefix only", line: want[:40] + " blob 12\n", wantErr: true},
		{name: "negative size", line: want + " blob -1\n", wantErr: true},
		{name: "missing size", line: want + " blob\n", wantErr: true},
		{name: "non-numeric size", line: want + " blob 1x\n", wantErr: true},
		{name: "empty", line: "\n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			typ, size, missing, err := parseCatFileHeader(tc.line, []byte(want))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if typ != tc.wantType || size != tc.wantSize || missing != tc.wantMissing {
				t.Errorf("= (%q, %d, %v), want (%q, %d, %v)", typ, size, missing, tc.wantType, tc.wantSize, tc.wantMissing)
			}
		})
	}
}
