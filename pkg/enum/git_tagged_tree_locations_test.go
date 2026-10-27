package enum

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// taggedTreeWarning is part of the stderr line both walks print when a ref
// points directly at a tree.
const taggedTreeWarning = "git refs point directly at a tree"

// walkProv runs one walk over dir and returns the provenance of the blob with
// content, and the warnings. It fails when the blob was not scanned.
func walkProv(t *testing.T, dir string, walk func(*GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error, content string) (types.GitProvenance, string) {
	t.Helper()
	e := nativeEnum(dir)
	var warn bytes.Buffer
	e.warn = &warn
	var (
		prov  types.GitProvenance
		found bool
	)
	err := walk(e)(context.Background(), func(c []byte, _ types.BlobID, p types.Provenance) error {
		if string(c) == content {
			prov, found = p.(types.GitProvenance), true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v (warnings %q)", err, warn.String())
	}
	if !found {
		t.Fatalf("the blob was not scanned (warnings %q)", warn.String())
	}
	return prov, warn.String()
}

func locPaths(locs []types.GitLocation) []string {
	out := make([]string, len(locs))
	for i, l := range locs {
		out[i] = l.Path
	}
	return out
}

// F1 (a): a blob in a commit at a.txt and in a tagged tree at b-tagged.txt is
// reported at both paths on both walks. a.txt keeps its commit; b-tagged.txt
// has none. The blob is marked as possibly missing locations, and a warning
// says why.
func TestGitHistory_TaggedTreePathOfCommittedBlob(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	const secret = "TAGGED_AND_COMMITTED=ghp_example\n"
	writeFile(t, filepath.Join(dir, "a.txt"), secret)
	commit := commitAt(t, dir, "add a", "2026-01-01T00:00:00Z")
	tree := gitInput(t, dir, []byte("100644 blob "+hashBlob(t, dir, secret)+"\tb-tagged.txt\n"), "mktree")
	runGit(t, dir, "tag", "zz", tree)

	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			prov, warn := walkProv(t, dir, walk, secret)
			if got := locPaths(prov.Locations); strings.Join(got, ",") != "a.txt,b-tagged.txt" {
				t.Fatalf("locations = %q, want [a.txt b-tagged.txt]", got)
			}
			if c := prov.Locations[0].Commit; c == nil || c.CommitID != commit {
				t.Errorf("a.txt commit = %v, want %s", c, commit)
			}
			if c := prov.Locations[1].Commit; c != nil {
				t.Errorf("b-tagged.txt commit = %s, want none", c.CommitID)
			}
			if prov.BlobPath != "a.txt" {
				t.Errorf("primary path = %q, want a.txt", prov.BlobPath)
			}
			if !prov.LocationsTruncated {
				t.Error("blob under a tagged tree is not marked as possibly missing locations")
			}
			if want := "titus: 1 " + taggedTreeWarning; !strings.Contains(warn, want) {
				t.Errorf("warnings = %q, want %q", warn, want)
			}
		})
	}
}
