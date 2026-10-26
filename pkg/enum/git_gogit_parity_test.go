package enum

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// runGoGit collects every callback of the go-git history walk, keyed by blob.
func runGoGit(t *testing.T, e *GitEnumerator) nativeRun {
	t.Helper()
	r := nativeRun{calls: map[types.BlobID]int{}, provs: map[types.BlobID]types.GitProvenance{}}
	err := e.enumerateAllHistory(context.Background(), func(_ []byte, id types.BlobID, prov types.Provenance) error {
		r.calls[id]++
		r.provs[id] = prov.(types.GitProvenance)
		return nil
	})
	if err != nil {
		t.Fatalf("enumerateAllHistory: %v", err)
	}
	return r
}

// describeCommit renders every CommitMetadata field, with timestamps as
// instant plus zone offset so that two equal times in different Location
// values still compare equal.
func describeCommit(c *types.CommitMetadata) string {
	if c == nil {
		return "<nil>"
	}
	ts := func(t time.Time) string {
		_, off := t.Zone()
		return fmt.Sprintf("%d%+d", t.Unix(), off)
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%q", c.CommitID, c.AuthorName, c.AuthorEmail,
		ts(c.AuthorTimestamp), c.CommitterName, c.CommitterEmail, ts(c.CommitterTimestamp), c.Message)
}

func describeProv(p types.GitProvenance) string {
	var b strings.Builder
	fmt.Fprintf(&b, "repo=%q root=%q remote=%v truncated=%v primary=(%q, %s)\n", p.RepoPath, p.RepoRoot, p.RemoteIdentity, p.LocationsTruncated, p.BlobPath, describeCommit(p.Commit))
	for _, l := range p.Locations {
		fmt.Fprintf(&b, "  loc %q wt=%v %s\n", l.Path, l.WorkingTree, describeCommit(l.Commit))
	}
	return b.String()
}

func describeRun(r nativeRun) map[types.BlobID]string {
	out := make(map[types.BlobID]string, len(r.provs))
	for id, p := range r.provs {
		out[id] = fmt.Sprintf("calls=%d %s", r.calls[id], describeProv(p))
	}
	return out
}

// Contents unique to one branch of parityFixture, so a walk that misses a
// ref is detectable.
const (
	fixtureFeatureOnly  = "feature only\n"
	fixtureMainOnly     = "main only\n"
	fixtureUnmergedOnly = "side branch\n"
	fixtureRenamedBody  = "renamed body\n"
	fixtureReadded      = "k: v\n"
)

// parityFixture builds a history with adds, a rename, a delete and re-add, a
// modify, duplicate content at two paths, a second branch merged back with
// a merge commit, a multi-line commit message and a non-UTC committer zone.
func parityFixture(t *testing.T) (dir string, secret string, a, b string) {
	t.Helper()
	dir = t.TempDir()
	initGitRepo(t, dir)
	secret = fakeTokenLine('a')

	writeFile(t, filepath.Join(dir, "config.yml"), secret)
	writeFile(t, filepath.Join(dir, "old.txt"), fixtureRenamedBody)
	writeFile(t, filepath.Join(dir, "gone.yml"), fixtureReadded)
	a = commitAt(t, dir, "A", "2026-01-01T00:00:00Z")

	if err := os.MkdirAll(filepath.Join(dir, "deploy"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "deploy", "config.yml"), secret)
	runGit(t, dir, "mv", "old.txt", "new.txt")
	b = commitAt(t, dir, "B subject\nwrapped line\n\nbody text", "2026-02-01T00:00:00+05:30")

	runGit(t, dir, "rm", "-q", "gone.yml")
	writeFile(t, filepath.Join(dir, "app.yml"), "name: app\n")
	commitAt(t, dir, "C", "2026-03-01T00:00:00Z")

	writeFile(t, filepath.Join(dir, "gone.yml"), fixtureReadded)
	writeFile(t, filepath.Join(dir, "app.yml"), "name: app\n"+fakeTokenLine('b'))
	commitAt(t, dir, "D re-add and modify", "2026-04-01T00:00:00Z")

	base := gitOutput(t, dir, "rev-parse", "--abbrev-ref", "HEAD")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	writeFile(t, filepath.Join(dir, "feature.txt"), fixtureFeatureOnly)
	writeFile(t, filepath.Join(dir, "copy-of-secret.env"), secret)
	commitAt(t, dir, "E on feature", "2026-05-01T00:00:00-07:00")
	runGit(t, dir, "checkout", "-q", base)
	writeFile(t, filepath.Join(dir, "main-only.txt"), fixtureMainOnly)
	commitAt(t, dir, "F on main", "2026-05-02T00:00:00Z")
	runGitEnv(t, dir, []string{"GIT_AUTHOR_DATE=2026-06-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-06-01T00:00:00Z"},
		"merge", "-q", "--no-ff", "--no-gpg-sign", "-m", "G merge", "feature")

	runGit(t, dir, "checkout", "-q", "-b", "unmerged")
	writeFile(t, filepath.Join(dir, "unmerged.txt"), fixtureUnmergedOnly)
	commitAt(t, dir, "H unmerged", "2026-07-01T00:00:00Z")
	runGit(t, dir, "checkout", "-q", base)
	return dir, secret, a, b
}

// C-HISTPATHS-1, C-MODCOMMIT-1, C-ONECALLBACK-1: the go-git fallback yields
// exactly what the native path yields, blob by blob.
func TestGoGitHistory_ParityWithNative(t *testing.T) {
	skipIfNoGit(t)
	dir, _, _, _ := parityFixture(t)
	runGit(t, dir, "remote", "add", "origin", fakeCredURL("https", "github.com/acme/api.git"))

	native := describeRun(runNative(t, nativeEnum(dir)))
	gogit := describeRun(runGoGit(t, nativeEnum(dir)))

	// Parity alone passes when both walks miss the same ref, so pin that the
	// baseline reaches the merged side branch, the merge's other parent, and
	// the unmerged branch.
	for name, content := range map[string]string{
		"feature.txt":   fixtureFeatureOnly,
		"main-only.txt": fixtureMainOnly,
		"unmerged.txt":  fixtureUnmergedOnly,
	} {
		if _, ok := native[types.ComputeBlobID([]byte(content))]; !ok {
			t.Errorf("native walk missed the %s blob", name)
		}
	}
	if len(gogit) != len(native) {
		t.Errorf("go-git enumerated %d blobs, native %d", len(gogit), len(native))
	}
	ids := map[string]types.BlobID{}
	for id := range native {
		ids[id.Hex()] = id
	}
	for id := range gogit {
		ids[id.Hex()] = id
	}
	for _, h := range slices.Sorted(maps.Keys(ids)) {
		id := ids[h]
		if native[id] != gogit[id] {
			t.Errorf("blob %s differs\nnative: %s\ngo-git: %s", id.Hex(), native[id], gogit[id])
		}
	}
}
