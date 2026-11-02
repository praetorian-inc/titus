package enum

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

const (
	brokenRefSecret   = "BROKEN_REF_SECRET=ghp_example\n"
	brokenRefSideBlob = "BROKEN_REF_SIDE=second-tip\n"

	indexUnavailableWarning = "history index unavailable"
	missingObjectsWarning   = "git objects are missing"
)

// Broken-ref cases. Each breaks one ref of a repo that has a good commit.
const (
	caseCorruptRef     = "corrupt ref file"
	caseDanglingRef    = "ref to missing commit"
	caseTwoDangling    = "two refs to the same missing commit"
	caseTagMissingObj  = "tag to missing object"
	missingCommitID    = "1111111111111111111111111111111111111111"
	missingTreeID      = "2222222222222222222222222222222222222222"
	brokenRefCommitMsg = "add a"
)

// writeRef writes id as the loose ref name (for example refs/heads/x).
func writeRef(t *testing.T, dir, name, id string) {
	t.Helper()
	path := filepath.Join(dir, ".git", filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, id+"\n")
}

// brokenRefRepo builds a repo with a.txt committed on the default branch,
// optionally a second branch tip, then breaks a ref as the case says. It
// returns the repo dir and the a.txt commit id.
func brokenRefRepo(t *testing.T, kase string, secondTip bool) (string, string) {
	t.Helper()
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "a.txt"), brokenRefSecret)
	commit := commitAt(t, dir, brokenRefCommitMsg, "2026-01-01T00:00:00Z")
	if secondTip {
		// A second branch with its own commit, built with plumbing so the
		// checkout never moves.
		tree := gitInput(t, dir, []byte("100644 blob "+hashBlob(t, dir, brokenRefSideBlob)+"\tside.txt\n"), "mktree")
		side := gitInput(t, dir, []byte("side\n"), "commit-tree", tree, "-p", commit)
		runGit(t, dir, "update-ref", "refs/heads/side", side)
	}
	switch kase {
	case caseCorruptRef:
		writeRef(t, dir, "refs/heads/corrupt", "garbage-not-a-sha")
	case caseDanglingRef:
		writeRef(t, dir, "refs/heads/dangling", missingCommitID)
	case caseTwoDangling:
		writeRef(t, dir, "refs/heads/d1", missingCommitID)
		writeRef(t, dir, "refs/heads/d2", missingCommitID)
	case caseTagMissingObj:
		tag := hashObjectLiterally(t, dir, "tag",
			"object "+missingTreeID+"\ntype tree\ntag gone\ntagger a <a@a> 0 +0000\n\nm\n")
		writeRef(t, dir, "refs/tags/gone", tag)
	default:
		t.Fatalf("unknown case %q", kase)
	}
	return dir, commit
}

var brokenRefCases = []string{caseCorruptRef, caseDanglingRef, caseTagMissingObj}

// A broken ref must not cost the good history its commit metadata: native
// must match go-git, which skips the broken ref.
func TestGitHistory_BrokenRefKeepsCommitMetadata(t *testing.T) {
	skipIfNoGit(t)
	for _, kase := range brokenRefCases {
		t.Run(kase, func(t *testing.T) {
			dir, commit := brokenRefRepo(t, kase, false)
			for name, walk := range enumWalks {
				t.Run(name, func(t *testing.T) {
					prov, warn := walkProv(t, dir, walk, brokenRefSecret)
					if got := locPaths(prov.Locations); strings.Join(got, ",") != "a.txt" {
						t.Fatalf("locations = %q, want [a.txt]", got)
					}
					if c := prov.Locations[0].Commit; c == nil || c.CommitID != commit {
						t.Errorf("a.txt commit = %v, want %s", c, commit)
					}
					if prov.LocationsTruncated {
						t.Error("a.txt is marked as possibly missing locations")
					}
					if strings.Contains(warn, indexUnavailableWarning) {
						t.Errorf("warnings = %q, want no %q", warn, indexUnavailableWarning)
					}
				})
			}
		})
	}
}

// blobProv is the comparable provenance of one scanned blob.
type blobProv struct {
	Paths     string
	Commits   string
	Truncated bool
}

// walkAllProv runs one walk and returns every scanned blob's provenance by
// content, and the warnings.
func walkAllProv(t *testing.T, dir string, walk func(*GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error) (map[string]blobProv, string) {
	t.Helper()
	e := nativeEnum(dir)
	var warn bytes.Buffer
	e.warn = &warn
	out := map[string]blobProv{}
	err := walk(e)(context.Background(), func(c []byte, _ types.BlobID, p types.Provenance) error {
		g := p.(types.GitProvenance)
		var commits []string
		for _, l := range g.Locations {
			if l.Commit != nil {
				commits = append(commits, l.Commit.CommitID)
			} else {
				commits = append(commits, "-")
			}
		}
		paths := locPaths(g.Locations)
		sort.Strings(paths)
		out[string(c)] = blobProv{Paths: strings.Join(paths, ","), Commits: strings.Join(commits, ","), Truncated: g.LocationsTruncated}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v (warnings %q)", err, warn.String())
	}
	return out, warn.String()
}

// With a broken ref and two good tips, both walks give the same provenance
// for every blob and print the same warnings.
func TestGitHistory_BrokenRefParity(t *testing.T) {
	skipIfNoGit(t)
	for _, kase := range brokenRefCases {
		t.Run(kase, func(t *testing.T) {
			dir, _ := brokenRefRepo(t, kase, true)
			native, nativeWarn := walkAllProv(t, dir, enumWalks["native"])
			gogit, gogitWarn := walkAllProv(t, dir, enumWalks["go-git"])
			if _, ok := gogit[brokenRefSideBlob]; !ok {
				t.Fatalf("fixture: go-git did not scan side.txt")
			}
			if !reflect.DeepEqual(native, gogit) {
				t.Errorf("provenance differs\nnative: %+v\ngo-git: %+v", native, gogit)
			}
			if nativeWarn != gogitWarn {
				t.Errorf("warnings differ\nnative: %q\ngo-git: %q", nativeWarn, gogitWarn)
			}
		})
	}
}

// A corrupt ref file names no object, so it is not a missing object. A ref
// or tag naming an absent object id is one missing object per distinct id.
func TestGitHistory_MissingObjectWarningForBrokenRefs(t *testing.T) {
	skipIfNoGit(t)
	cases := []struct {
		kase string
		want string // "" means no missing-object warning
	}{
		{caseCorruptRef, ""},
		{caseDanglingRef, "titus: 1 " + missingObjectsWarning},
		{caseTwoDangling, "titus: 1 " + missingObjectsWarning},
		{caseTagMissingObj, "titus: 1 " + missingObjectsWarning},
	}
	for _, tc := range cases {
		t.Run(tc.kase, func(t *testing.T) {
			dir, _ := brokenRefRepo(t, tc.kase, false)
			for name, walk := range enumWalks {
				t.Run(name, func(t *testing.T) {
					_, warn := runWalkWarn(t, dir, walk)
					if tc.want == "" {
						if strings.Contains(warn, missingObjectsWarning) {
							t.Errorf("warnings = %q, want no %q", warn, missingObjectsWarning)
						}
						return
					}
					if !strings.Contains(warn, tc.want) {
						t.Errorf("warnings = %q, want %q", warn, tc.want)
					}
				})
			}
		})
	}
}

// O2: HEAD as a symref to a branch that points at a tree is the branch, not
// a second ref; the tagged-tree count is of distinct refs.
func TestGitHistory_TaggedTreeCountsDistinctRefs(t *testing.T) {
	skipIfNoGit(t)
	cases := []struct {
		name       string
		headAtTree bool
		want       string
	}{
		{"HEAD symref to tree branch", true, "titus: 2 " + taggedTreeWarning},
		{"HEAD symref to commit branch", false, "titus: 1 " + taggedTreeWarning},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			initGitRepo(t, dir)
			writeFile(t, filepath.Join(dir, "base.txt"), "base\n")
			commitAt(t, dir, "base", "2026-01-01T00:00:00Z")
			branch := gitOutput(t, dir, "symbolic-ref", "HEAD")
			const secret = "TREE_BRANCH=ghp_example\n"
			tree := gitInput(t, dir, []byte("100644 blob "+hashBlob(t, dir, secret)+"\tt.txt\n"), "mktree")
			runGit(t, dir, "update-ref", "refs/tags/tt", tree)
			if tc.headAtTree {
				// git refuses a non-commit under refs/heads/, so write it.
				writeRef(t, dir, "refs/heads/treebr", tree)
				runGit(t, dir, "symbolic-ref", "HEAD", "refs/heads/treebr")
			} else if got := gitOutput(t, dir, "symbolic-ref", "HEAD"); got != branch {
				t.Fatalf("fixture: HEAD = %q, want %q", got, branch)
			}
			for name, walk := range enumWalks {
				t.Run(name, func(t *testing.T) {
					_, warn := runWalkWarn(t, dir, walk)
					if !strings.Contains(warn, tc.want) {
						t.Errorf("warnings = %q, want %q", warn, tc.want)
					}
				})
			}
		})
	}
}

// Regression guard: a commit reachable only from a linked worktree's HEAD
// keeps its commit metadata on the native walk of the main repo.
func TestGitHistoryNative_LinkedWorktreeHeadKeepsCommitMetadata(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "base.txt"), "base\n")
	commitAt(t, dir, "base", "2026-01-01T00:00:00Z")
	linked := filepath.Join(t.TempDir(), "wt")
	cmd := exec.Command("git", "worktree", "add", "--detach", linked)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PALATINE_TREE_ADD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git worktree add: %v\n%s", err, out)
	}
	const secret = "LINKED_WORKTREE=ghp_example\n"
	writeFile(t, filepath.Join(linked, "wt.txt"), secret)
	commit := commitAt(t, linked, "wt", "2026-01-02T00:00:00Z")

	prov, warn := walkProv(t, dir, enumWalks["native"], secret)
	if got := locPaths(prov.Locations); strings.Join(got, ",") != "wt.txt" {
		t.Fatalf("locations = %q, want [wt.txt]", got)
	}
	if c := prov.Locations[0].Commit; c == nil || c.CommitID != commit {
		t.Errorf("wt.txt commit = %v, want %s (warnings %q)", c, commit, warn)
	}
	if prov.LocationsTruncated {
		t.Errorf("wt.txt is marked as possibly missing locations (warnings %q)", warn)
	}
}

// Guard: with an unborn HEAD and only a tag at a tree, there are no commit
// tips, so the walk must not fall back to an index run that fails on HEAD.
func TestGitHistoryNative_OnlyTreeTagUnbornHead(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	const secret = "UNBORN_TREE_TAG=ghp_example\n"
	tree := gitInput(t, dir, []byte("100644 blob "+hashBlob(t, dir, secret)+"\tu.txt\n"), "mktree")
	runGit(t, dir, "update-ref", "refs/tags/t", tree)
	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			prov, warn := walkProv(t, dir, walk, secret)
			if !prov.LocationsTruncated {
				t.Error("blob under a tagged tree is not marked as possibly missing locations")
			}
			if strings.Contains(warn, indexUnavailableWarning) {
				t.Errorf("warnings = %q, want no %q", warn, indexUnavailableWarning)
			}
		})
	}
}
