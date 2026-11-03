package enum

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Test names carry the outcome-plan case ids (CASE-*) so they are greppable.
// Every fixture is a real git repository built with the git binary; none
// models an input git cannot produce.

// --- fixture helpers -------------------------------------------------------

func brInit(t *testing.T) string {
	t.Helper()
	skipIfNoGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init", "-q", "-b", "main")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test User")
	return dir
}

// brCommit commits one new file whose content is unique to name, so the commit
// is the earliest (and only) location of that blob, and returns the commit id.
func brCommit(t *testing.T, dir, name string) string {
	t.Helper()
	writeFile(t, filepath.Join(dir, name+".txt"), "secret-"+name+"\n")
	return commitAt(t, dir, name, "2026-01-01T00:00:00Z")
}

// topo is one repository topology: the directory to scan and the branch each
// commit must resolve to, keyed by commit id.
type topo struct {
	dir  string
	want map[string]string
}

type topoCase struct {
	name  string
	build func(t *testing.T) topo
}

// resolversFor builds the native and the go-git resolver for dir.
func resolversFor(t *testing.T, dir string) map[string]*branchResolver {
	t.Helper()
	repo, err := openGoGitRepo(dir)
	require.NoError(t, err)
	ctx := context.Background()
	return map[string]*branchResolver{
		"native": resolveBranchesNative(ctx, dir),
		"go-git": resolveBranchesGoGit(ctx, repo),
	}
}

// walkBranches runs one whole-history walk and returns commit id -> Branch for
// every commit any location or primary provenance names. It fails when one
// commit is given two different branches.
func walkBranches(t *testing.T, dir, walk string) (map[string]string, string) {
	t.Helper()
	e := nativeEnum(dir)
	var warn bytes.Buffer
	e.warn = &warn
	got := map[string]string{}
	note := func(c *types.CommitMetadata) {
		if c == nil {
			return
		}
		if prev, ok := got[c.CommitID]; ok {
			require.Equal(t, prev, c.Branch, "commit %s carries two different branches", c.CommitID)
		}
		got[c.CommitID] = c.Branch
	}
	err := enumWalks[walk](e)(context.Background(), func(_ []byte, _ types.BlobID, p types.Provenance) error {
		g := p.(types.GitProvenance)
		note(g.Commit)
		for _, l := range g.Locations {
			note(l.Commit)
		}
		return nil
	})
	require.NoError(t, err, "warnings %q", warn.String())
	return got, warn.String()
}

// --- topologies ------------------------------------------------------------

func topoCases() []topoCase {
	return []topoCase{
		{"CASE-PROV-1 commit only on checked-out main", func(t *testing.T) topo {
			dir := brInit(t)
			c1, c2 := brCommit(t, dir, "c1"), brCommit(t, dir, "c2")
			return topo{dir, map[string]string{c1: "main", c2: "main"}}
		}},
		{"CASE-GUARD-1 CASE-CHECKED-2 CASE-REPORT-1 commit on main and feature/login, feature/login checked out", func(t *testing.T) topo {
			dir := brInit(t)
			c1 := brCommit(t, dir, "c1")
			runGit(t, dir, "branch", "feature/login")
			mainOnly := brCommit(t, dir, "mainonly")
			runGit(t, dir, "checkout", "-q", "feature/login")
			featOnly := brCommit(t, dir, "featonly")
			return topo{dir, map[string]string{c1: "feature/login", mainOnly: "main", featOnly: "feature/login"}}
		}},
		{"CASE-CHECKED-1 aaa-other sorts before checked-out main", func(t *testing.T) topo {
			dir := brInit(t)
			c1 := brCommit(t, dir, "c1")
			runGit(t, dir, "branch", "aaa-other")
			return topo{dir, map[string]string{c1: "main"}}
		}},
		{"CASE-COMMIT-1 CASE-CHECKED-1 branch tip is later than the recorded commit", func(t *testing.T) topo {
			dir := brInit(t)
			c1 := brCommit(t, dir, "c1")
			runGit(t, dir, "branch", "aaa-other")
			c2 := brCommit(t, dir, "c2")
			return topo{dir, map[string]string{c1: "main", c2: "main"}}
		}},
		{"CASE-GUARD-ONLY-OTHER commit only on release/1.0 while main is checked out", func(t *testing.T) topo {
			dir := brInit(t)
			c0 := brCommit(t, dir, "c0")
			runGit(t, dir, "checkout", "-q", "-b", "release/1.0")
			c1 := brCommit(t, dir, "c1")
			runGit(t, dir, "checkout", "-q", "main")
			return topo{dir, map[string]string{c0: "main", c1: "release/1.0"}}
		}},
		{"commit on two non-checked-out branches resolves to nothing", func(t *testing.T) topo {
			dir := brInit(t)
			c0 := brCommit(t, dir, "c0")
			runGit(t, dir, "checkout", "-q", "-b", "a")
			x := brCommit(t, dir, "x")
			runGit(t, dir, "branch", "b", "a")
			runGit(t, dir, "checkout", "-q", "main")
			return topo{dir, map[string]string{c0: "main", x: ""}}
		}},
		{"CASE-OMIT-PROV-1 detached HEAD at a commit no branch contains", func(t *testing.T) topo {
			dir := brInit(t)
			base := brCommit(t, dir, "base")
			runGit(t, dir, "checkout", "-q", "--detach")
			c1 := brCommit(t, dir, "c1")
			return topo{dir, map[string]string{base: "main", c1: ""}}
		}},
		{"detached HEAD: commit in one branch resolves to it, in several to nothing", func(t *testing.T) topo {
			dir := brInit(t)
			c1 := brCommit(t, dir, "c1")
			runGit(t, dir, "checkout", "-q", "-b", "feature")
			f1 := brCommit(t, dir, "f1")
			runGit(t, dir, "checkout", "-q", "--detach")
			return topo{dir, map[string]string{c1: "", f1: "feature"}}
		}},
		{"detached HEAD at a commit only main contains", func(t *testing.T) topo {
			dir := brInit(t)
			c1 := brCommit(t, dir, "c1")
			runGit(t, dir, "checkout", "-q", "--detach")
			return topo{dir, map[string]string{c1: "main"}}
		}},
		{"bare clone resolves the default branch from HEAD", func(t *testing.T) topo {
			src := brInit(t)
			c1, c2 := brCommit(t, src, "c1"), brCommit(t, src, "c2")
			runGit(t, src, "checkout", "-q", "-b", "feature", c1)
			f1 := brCommit(t, src, "f1")
			runGit(t, src, "checkout", "-q", "main")
			dst := filepath.Join(t.TempDir(), "bare.git")
			runGit(t, src, "clone", "-q", "--bare", src, dst)
			return topo{dst, map[string]string{c1: "main", c2: "main", f1: "feature"}}
		}},
		{"shallow clone labels the tip and does not fail", func(t *testing.T) topo {
			src := brInit(t)
			brCommit(t, src, "c1")
			brCommit(t, src, "c2")
			c3 := brCommit(t, src, "c3")
			dst := filepath.Join(t.TempDir(), "shallow")
			runGit(t, src, "clone", "-q", "--depth", "1", "file://"+src, dst)
			return topo{dst, map[string]string{c3: "main"}}
		}},
		{"linked worktree on another branch resolves its own checked-out branch", func(t *testing.T) topo {
			main := brInit(t)
			c1 := brCommit(t, main, "c1")
			wt := filepath.Join(t.TempDir(), "wt")
			runGit(t, main, "worktree", "add", "-q", "-b", "other", wt)
			c2 := brCommit(t, main, "c2") // main only
			c3 := brCommit(t, wt, "c3")   // other only
			return topo{wt, map[string]string{c1: "other", c2: "main", c3: "other"}}
		}},
		{"remote-tracking ref only holds the commit", func(t *testing.T) topo {
			src := brInit(t)
			c1, c2 := brCommit(t, src, "c1"), brCommit(t, src, "c2")
			runGit(t, src, "checkout", "-q", "-b", "feature", c1)
			f1 := brCommit(t, src, "f1")
			runGit(t, src, "checkout", "-q", "main")
			dst := filepath.Join(t.TempDir(), "clone")
			runGit(t, src, "clone", "-q", "file://"+src, dst)
			return topo{dst, map[string]string{c1: "main", c2: "main", f1: "feature"}}
		}},
		{"local and remote-tracking ref with one short name are one branch, origin/HEAD is not a branch", func(t *testing.T) topo {
			src := brInit(t)
			c1, c2 := brCommit(t, src, "c1"), brCommit(t, src, "c2")
			runGit(t, src, "checkout", "-q", "-b", "feature", c1)
			f1 := brCommit(t, src, "f1")
			runGit(t, src, "checkout", "-q", "main")
			dst := filepath.Join(t.TempDir(), "clone")
			runGit(t, src, "clone", "-q", "file://"+src, dst)
			runGit(t, dst, "checkout", "-q", "-b", "feature", "origin/feature")
			// c2 is held by main, origin/main and origin/HEAD, none checked
			// out: three refs, one branch.
			return topo{dst, map[string]string{c1: "feature", c2: "main", f1: "feature"}}
		}},
		{"a second remote with the same branch name is still one branch", func(t *testing.T) topo {
			src := brInit(t)
			c1 := brCommit(t, src, "c1")
			runGit(t, src, "checkout", "-q", "-b", "feature", c1)
			f1 := brCommit(t, src, "f1")
			runGit(t, src, "checkout", "-q", "main")
			dst := filepath.Join(t.TempDir(), "clone")
			runGit(t, src, "clone", "-q", "file://"+src, dst)
			runGit(t, dst, "remote", "add", "up", "file://"+src)
			runGit(t, dst, "fetch", "-q", "up")
			return topo{dst, map[string]string{c1: "main", f1: "feature"}}
		}},
		{"odd but legal branch names are kept verbatim", func(t *testing.T) topo {
			dir := brInit(t)
			c0 := brCommit(t, dir, "c0")
			want := map[string]string{c0: "main"}
			for i, name := range []string{"feat/ünï-日本", "a.b+c@d", "release/1.0", "x=y#z", "bidi\U0000202eevil"} {
				runGit(t, dir, "checkout", "-q", "-b", name, c0)
				want[brCommit(t, dir, fmt.Sprintf("odd%d", i))] = name
			}
			runGit(t, dir, "checkout", "-q", "main")
			return topo{dir, want}
		}},
		{"merge commit and merged side branch", func(t *testing.T) topo {
			dir := brInit(t)
			c1 := brCommit(t, dir, "c1")
			runGit(t, dir, "checkout", "-q", "-b", "side")
			s1 := brCommit(t, dir, "s1")
			runGit(t, dir, "checkout", "-q", "main")
			m1 := brCommit(t, dir, "m1")
			runGitEnv(t, dir, []string{"GIT_AUTHOR_DATE=2026-02-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-02-01T00:00:00Z"},
				"merge", "-q", "--no-ff", "--no-gpg-sign", "-m", "merge", "side")
			// After the merge main holds s1; side holds it too. Checked-out main wins.
			return topo{dir, map[string]string{c1: "main", s1: "main", m1: "main"}}
		}},
	}
}

// Resolver table, run against the native and the go-git resolver.
func TestBranchResolver_Topologies(t *testing.T) {
	for _, tc := range topoCases() {
		t.Run(tc.name, func(t *testing.T) {
			tp := tc.build(t)
			for backend, r := range resolversFor(t, tp.dir) {
				t.Run(backend, func(t *testing.T) {
					for commit, want := range tp.want {
						assert.Equal(t, want, r.of(commit), "branch of %s", commit)
					}
					assert.Empty(t, r.notes, "no bound is reached on a small repository")
				})
			}
		})
	}
}

// The same table end to end: the Branch the whole-history walks put on the
// provenance of every blob, native and go-git, with no resolver warning.
func TestBranchEnumeration_Topologies(t *testing.T) {
	for _, tc := range topoCases() {
		t.Run(tc.name, func(t *testing.T) {
			tp := tc.build(t)
			for walk := range enumWalks {
				t.Run(walk, func(t *testing.T) {
					got, warn := walkBranches(t, tp.dir, walk)
					assert.Equal(t, tp.want, got)
					assert.NotContains(t, warn, "branch not recorded")
				})
			}
		})
	}
}

// Native and go-git must agree on every commit of the large mixed fixture the
// existing parity test uses (merges, a side branch, an unmerged branch).
func TestBranchResolver_ParityOnMixedHistory(t *testing.T) {
	dir, _, _, _ := parityFixture(t)
	rs := resolversFor(t, dir)
	revs := strings.Fields(gitOutput(t, dir, "rev-list", "--all"))
	require.NotEmpty(t, revs)
	seen := map[string]int{}
	for _, c := range revs {
		n, g := rs["native"].of(c), rs["go-git"].of(c)
		assert.Equal(t, n, g, "commit %s", c)
		seen[n]++
	}
	// The baseline must reach each resolution outcome, or parity is vacuous.
	assert.Positive(t, seen["main"]+seen["master"], "some commit resolves to the checked-out branch")
	assert.Positive(t, seen["unmerged"], "the unmerged branch's commit resolves to it")
}

func TestBranchResolver_Unborn(t *testing.T) {
	dir := brInit(t)
	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			assert.Equal(t, "", r.of("0123456789012345678901234567890123456789"))
			assert.Empty(t, r.notes)
		})
	}
	for walk := range enumWalks {
		t.Run("walk "+walk, func(t *testing.T) {
			got, _ := walkBranches(t, dir, walk)
			assert.Empty(t, got)
		})
	}
}

func TestBranchResolver_NilAndMalformedIdsResolveNothing(t *testing.T) {
	var nilR *branchResolver
	assert.Equal(t, "", nilR.of("0123456789012345678901234567890123456789"))
	nilR.writeWarnings(&bytes.Buffer{}) // must not panic
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			assert.Equal(t, "main", r.of(c1))
			for _, bad := range []string{"", "main", "xyz", c1[:10], strings.ToUpper(c1), c1 + "0"} {
				assert.Equal(t, "", r.of(bad), "id %q", bad)
			}
		})
	}
}

func TestBranchResolver_SHA256Repository(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	if out, err := runGitProbe(dir, "init", "-q", "-b", "main", "--object-format=sha256"); err != nil {
		t.Skipf("git cannot make a sha256 repository: %v %s", err, out)
	}
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test User")
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "branch", "side")
	runGit(t, dir, "checkout", "-q", "side")
	c2 := brCommit(t, dir, "c2")
	runGit(t, dir, "checkout", "-q", "main")
	require.Len(t, c1, 64)
	r := resolveBranchesNative(context.Background(), dir)
	assert.Equal(t, "main", r.of(c1))
	assert.Equal(t, "side", r.of(c2))
}

func runGitProbe(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// --- commit selection unchanged (CASE-COMMIT-1) -----------------------------

// The recorded commit is the earliest commit of the blob's path, as before the
// branch field: it is not replaced by the tip of the resolved branch.
func TestBranchEnumeration_CASE_COMMIT_1_RecordedCommitUnchanged(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "branch", "aaa-other")
	c2 := brCommit(t, dir, "c2")
	tip := gitOutput(t, dir, "rev-parse", "main")
	require.Equal(t, c2, tip)
	require.NotEqual(t, c1, tip)

	for walk := range enumWalks {
		t.Run(walk, func(t *testing.T) {
			e := nativeEnum(dir)
			e.warn = &bytes.Buffer{}
			var prov types.GitProvenance
			err := enumWalks[walk](e)(context.Background(), func(c []byte, _ types.BlobID, p types.Provenance) error {
				if string(c) == "secret-c1\n" {
					prov = p.(types.GitProvenance)
				}
				return nil
			})
			require.NoError(t, err)
			require.NotNil(t, prov.Commit)
			assert.Equal(t, c1, prov.Commit.CommitID, "primary commit is the introducing commit, not the branch tip")
			require.Len(t, prov.Locations, 1)
			assert.Equal(t, c1, prov.Locations[0].Commit.CommitID)
			assert.Equal(t, "main", prov.Locations[0].Commit.Branch, "CASE-CHECKED-1: main, not aaa-other")
		})
	}
}

// --- host independence (CASE-HOST-*) ----------------------------------------

func TestBranchEnumeration_CASE_HOST_OneFieldForEveryHost(t *testing.T) {
	hosts := map[string]string{
		"azure-devops": "https://dev.azure.com/org/project/_git/repo",
		"gitlab":       "https://gitlab.com/group/repo.git",
		"github":       "https://github.com/org/repo.git",
		"bitbucket":    "https://bitbucket.org/org/repo.git",
	}
	for host, url := range hosts {
		t.Run("CASE-HOST-"+host, func(t *testing.T) {
			dir := brInit(t)
			c1 := brCommit(t, dir, "c1")
			runGit(t, dir, "remote", "add", "origin", url)
			for walk := range enumWalks {
				t.Run(walk, func(t *testing.T) {
					got, _ := walkBranches(t, dir, walk)
					assert.Equal(t, map[string]string{c1: "main"}, got)
				})
			}
			// The recorded provenance names the host the URL resolved to, and
			// the branch is still the bare short name.
			e := nativeEnum(dir)
			e.warn = &bytes.Buffer{}
			require.NoError(t, e.enumerateAllHistoryNative(context.Background(), func(_ []byte, _ types.BlobID, p types.Provenance) error {
				g := p.(types.GitProvenance)
				assert.True(t, g.RemoteIdentity, "origin was recognised")
				assert.NotEmpty(t, g.Host)
				assert.Equal(t, "main", g.Commit.Branch)
				assert.NotContains(t, g.Commit.Branch, "refs/")
				return nil
			}))
		})
	}
}

// --- single-commit mode (plan item 9, addendum rules) -----------------------

type singleTopo struct {
	dir           string
	c1, c2, f1, x string // c1 ancestor on main; c2 main tip; f1 only on feature; x on both1 and both2
}

func buildSingleTopo(t *testing.T) singleTopo {
	t.Helper()
	dir := brInit(t)
	s := singleTopo{dir: dir}
	s.c1 = brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	s.f1 = brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "-b", "both1", s.c1)
	s.x = brCommit(t, dir, "x")
	runGit(t, dir, "branch", "both2", "both1")
	runGit(t, dir, "checkout", "-q", "main")
	s.c2 = brCommit(t, dir, "c2")
	return s
}

// singleCommitBranchOf enumerates one commit and returns the commit ids and
// branches its provenance names.
func singleCommitBranchOf(t *testing.T, dir, ref string) (commitIDs, branches map[string]bool) {
	t.Helper()
	e := NewGitEnumerator(Config{Root: dir})
	e.CommitRef = ref
	e.warn = &bytes.Buffer{}
	commitIDs, branches = map[string]bool{}, map[string]bool{}
	err := e.Enumerate(context.Background(), func(_ []byte, _ types.BlobID, p types.Provenance) error {
		g := p.(types.GitProvenance)
		require.NotNil(t, g.Commit)
		commitIDs[g.Commit.CommitID] = true
		branches[g.Commit.Branch] = true
		for _, l := range g.Locations {
			commitIDs[l.Commit.CommitID] = true
			branches[l.Commit.Branch] = true
		}
		return nil
	})
	require.NoError(t, err)
	return commitIDs, branches
}

func TestBranchEnumeration_SingleCommitMode(t *testing.T) {
	s := buildSingleTopo(t)
	cases := []struct {
		name, ref, commit, want string
	}{
		{"HEAD is on the checked-out branch", "HEAD", s.c2, "main"},
		{"ancestor of HEAD is on the checked-out branch", s.c1, s.c1, "main"},
		{"off-HEAD commit held by exactly one other branch", s.f1, s.f1, "feature"},
		{"off-HEAD commit held by two other branches", s.x, s.x, ""},
		{"branch name as the ref", "feature", s.f1, "feature"},
	}
	// Both resolver backends: with git on PATH the native resolver answers,
	// with no git binary the go-git resolver does.
	for _, backend := range []string{"native", "go-git"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "go-git" {
				t.Setenv("PATH", t.TempDir())
				require.False(t, gitBinaryAvailable())
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					ids, branches := singleCommitBranchOf(t, s.dir, c.ref)
					assert.Equal(t, map[string]bool{c.commit: true}, ids, "CASE-COMMIT-1: the recorded commit is the one asked for")
					assert.Equal(t, map[string]bool{c.want: true}, branches)
				})
			}
		})
	}
}

func TestBranchEnumeration_SingleCommitMode_DetachedHead(t *testing.T) {
	s := buildSingleTopo(t)
	runGit(t, s.dir, "checkout", "-q", "--detach", s.f1)
	cases := []struct{ name, ref, want string }{
		{"HEAD detached at a commit only feature holds", "HEAD", "feature"},
		{"detached ancestor held by main and others", s.c1, ""},
		{"detached: x on two branches", s.x, ""},
	}
	for _, backend := range []string{"native", "go-git"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "go-git" {
				t.Setenv("PATH", t.TempDir())
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					_, branches := singleCommitBranchOf(t, s.dir, c.ref)
					assert.Equal(t, map[string]bool{c.want: true}, branches)
				})
			}
		})
	}
}

func TestBranchEnumeration_SingleCommitMode_CASE_OMIT_PROV_1_DetachedOrphan(t *testing.T) {
	dir := brInit(t)
	brCommit(t, dir, "base")
	runGit(t, dir, "checkout", "-q", "--detach")
	c1 := brCommit(t, dir, "c1")
	for _, backend := range []string{"native", "go-git"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "go-git" {
				t.Setenv("PATH", t.TempDir())
			}
			ids, branches := singleCommitBranchOf(t, dir, "HEAD")
			assert.Equal(t, map[string]bool{c1: true}, ids)
			assert.Equal(t, map[string]bool{"": true}, branches, "no branch is invented, not HEAD and not main")
		})
	}
}

// --- caps -------------------------------------------------------------------

func setCaps(t *testing.T, head, branches, off int) {
	t.Helper()
	h, b, o := maxHeadCommits, maxBranches, maxOffHeadCommits
	maxHeadCommits, maxBranches, maxOffHeadCommits = head, branches, off
	t.Cleanup(func() { maxHeadCommits, maxBranches, maxOffHeadCommits = h, b, o })
}

func branchWarnings(r *branchResolver) string {
	var b bytes.Buffer
	r.writeWarnings(&b)
	return b.String()
}

func TestBranchResolver_CapMaxBranches_OmitsOffHeadKeepsHeadSet(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "a")
	ca := brCommit(t, dir, "ca")
	runGit(t, dir, "checkout", "-q", "-b", "b", c1)
	cb := brCommit(t, dir, "cb")
	runGit(t, dir, "checkout", "-q", "main")
	setCaps(t, defaultMaxHeadCommits, 1, defaultMaxOffHeadCommits)

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			assert.Equal(t, "", r.of(ca), "past the bound a branch is omitted, never guessed")
			assert.Equal(t, "", r.of(cb))
			assert.Equal(t, "main", r.of(c1), "the HEAD set does not depend on the branch bound")
			assert.Contains(t, branchWarnings(r), "titus: branch not recorded for commits outside the checked-out branch: more than 1 branches")
		})
	}
	// End to end: the scan still finishes, blobs are all reported, the
	// warning reaches the enumeration warnings.
	for walk := range enumWalks {
		t.Run("walk "+walk, func(t *testing.T) {
			got, warn := walkBranches(t, dir, walk)
			assert.Equal(t, map[string]string{c1: "main", ca: "", cb: ""}, got)
			assert.Contains(t, warn, "more than 1 branches")
		})
	}
}

func TestBranchResolver_CapMaxOffHeadCommits_OmitsOffHeadKeepsHeadSet(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	f2 := brCommit(t, dir, "f2")
	runGit(t, dir, "checkout", "-q", "main")
	setCaps(t, defaultMaxHeadCommits, defaultMaxBranches, 1)

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			assert.Equal(t, "", r.of(f1))
			assert.Equal(t, "", r.of(f2))
			assert.Equal(t, "main", r.of(c1))
			assert.Contains(t, branchWarnings(r), "more than 1 such commits")
		})
	}
	for walk := range enumWalks {
		t.Run("walk "+walk, func(t *testing.T) {
			got, warn := walkBranches(t, dir, walk)
			assert.Equal(t, map[string]string{c1: "main", f1: "", f2: ""}, got)
			assert.Contains(t, warn, "more than 1 such commits")
		})
	}
}

func TestBranchResolver_CapAtExactBoundResolves(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")
	// One off-HEAD commit, two branch names (main, feature), a HEAD set of one.
	setCaps(t, 1, 2, 1)
	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			assert.Equal(t, "main", r.of(c1))
			assert.Equal(t, "feature", r.of(f1))
			assert.Empty(t, r.notes)
		})
	}
}

func TestBranchResolver_CapMaxHeadCommits_OmitsEverything(t *testing.T) {
	dir := brInit(t)
	c1, c2 := brCommit(t, dir, "c1"), brCommit(t, dir, "c2")
	runGit(t, dir, "checkout", "-q", "-b", "feature")
	f1 := brCommit(t, dir, "f1")
	runGit(t, dir, "checkout", "-q", "main")
	setCaps(t, 1, defaultMaxBranches, defaultMaxOffHeadCommits)

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			for _, c := range []string{c1, c2, f1} {
				assert.Equal(t, "", r.of(c), "with an unknown HEAD set, contains and checked-out cannot be told apart")
			}
			assert.Contains(t, branchWarnings(r), "titus: branch not recorded: history exceeds 1 commits")
		})
	}
	for walk := range enumWalks {
		t.Run("walk "+walk, func(t *testing.T) {
			got, warn := walkBranches(t, dir, walk)
			assert.Equal(t, map[string]string{c1: "", c2: "", f1: ""}, got)
			assert.Contains(t, warn, "history exceeds 1 commits")
		})
	}
}

// --- concurrency (run under -race) -----------------------------------------

func TestBranchResolver_ConcurrentLookupsAreRaceFree(t *testing.T) {
	tp := topoCases()[1].build(t)
	for backend, r := range resolversFor(t, tp.dir) {
		t.Run(backend, func(t *testing.T) {
			var wg sync.WaitGroup
			errs := make(chan string, 64*len(tp.want))
			for range 64 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for c, want := range tp.want {
						if got := r.of(c); got != want {
							errs <- fmt.Sprintf("%s: got %q want %q", c, got, want)
						}
					}
				}()
			}
			wg.Wait()
			close(errs)
			for e := range errs {
				t.Error(e)
			}
		})
	}
}

// Many goroutines materialize commit metadata of one shared index at once, as
// the clone and combined paths do from parallel readers.
func TestBlobIndex_ConcurrentLookupCarriesBranch(t *testing.T) {
	tp := topoCases()[1].build(t)
	idx := mustBuild(t, tp.dir)
	type blob struct {
		hash   [20]byte
		commit string
	}
	var blobs []blob
	for commit := range tp.want {
		blobs = append(blobs, blob{mustHash(t, gitOutput(t, tp.dir, "rev-parse", commit+":"+nameOfCommit(t, tp.dir, commit)+".txt")), commit})
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var bad []string
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, b := range blobs {
				locs := idx.lookup(b.hash)
				if len(locs) != 1 || locs[0].Commit == nil || locs[0].Commit.CommitID != b.commit || locs[0].Commit.Branch != tp.want[b.commit] {
					mu.Lock()
					bad = append(bad, fmt.Sprintf("%s: %+v", b.commit, locs))
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	assert.Empty(t, bad)
}

// nameOfCommit returns the commit subject, which brCommit sets to the file stem.
func nameOfCommit(t *testing.T, dir, commit string) string {
	t.Helper()
	return gitOutput(t, dir, "log", "-1", "--format=%s", commit)
}

// --- clone, combined --------------------------------------------------------

func TestCloneEnumerator_FilesystemMode_BranchOnFileLocation(t *testing.T) {
	root := t.TempDir()
	head := makeRemoteFixture(t, root, "acme", "api", map[string]string{"cfg/app.yml": "token-BBBB"})
	redirectHTTPSToLocal(t, root)

	e := NewCloneEnumerator([]RepoInfo{{Name: "acme/api", CloneURL: fakeCredURL("https", "github.com/acme/api.git")}}, Config{})
	calls := withoutDotGit(collectBlobs(t, func(cb blobCallback) error { return e.Enumerate(context.Background(), cb) }))
	require.Len(t, calls, 1)
	gp := gitProv(t, calls[0].prov)
	require.Len(t, gp.Locations, 1)
	require.NotNil(t, gp.Locations[0].Commit)
	assert.Equal(t, head, gp.Locations[0].Commit.CommitID)
	assert.Equal(t, "main", gp.Locations[0].Commit.Branch)
	require.NotNil(t, gp.Commit)
	assert.Equal(t, "main", gp.Commit.Branch)
}

func TestCloneEnumerator_GitMode_BranchOnLocation(t *testing.T) {
	root := t.TempDir()
	makeRemoteFixture(t, root, "acme", "api", map[string]string{"a.txt": "token-AAAA"})
	redirectHTTPSToLocal(t, root)
	e := NewCloneEnumerator([]RepoInfo{{Name: "acme/api", CloneURL: fakeCredURL("https", "github.com/acme/api.git")}}, Config{})
	e.Git = true
	calls := collectBlobs(t, func(cb blobCallback) error { return e.Enumerate(context.Background(), cb) })
	require.NotEmpty(t, calls)
	for _, c := range calls {
		gp := gitProv(t, c.prov)
		for _, l := range gp.Locations {
			if l.Commit != nil {
				assert.Equal(t, "main", l.Commit.Branch)
			}
		}
	}
}

// When the history index cannot be built the file still scans, with no commit
// and so no branch.
func TestCloneEnumerator_FilesystemMode_UnavailableIndexGivesNoBranch(t *testing.T) {
	root := t.TempDir()
	makeRemoteFixture(t, root, "acme", "api", map[string]string{"cfg/app.yml": "token-BBBB"})
	redirectHTTPSToLocal(t, root)

	e := NewCloneEnumerator([]RepoInfo{{Name: "acme/api", CloneURL: fakeCredURL("https", "github.com/acme/api.git")}}, Config{})
	e.buildIndex = func(context.Context, string) (*blobIndex, error) { return nil, fmt.Errorf("boom") }
	calls := withoutDotGit(collectBlobs(t, func(cb blobCallback) error { return e.Enumerate(context.Background(), cb) }))
	require.Len(t, calls, 1)
	gp := gitProv(t, calls[0].prov)
	assert.Nil(t, gp.Commit)
	for _, l := range gp.Locations {
		assert.Nil(t, l.Commit, "no commit, so no branch")
	}
	assert.True(t, gp.LocationsTruncated)
}

func TestCombinedEnumerator_BranchOnCommittedLocationOnly(t *testing.T) {
	dir := brInit(t)
	secret := fakeTokenLine('a')
	writeFile(t, filepath.Join(dir, "config.yml"), secret)
	a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "backup"), 0o755))
	writeFile(t, filepath.Join(dir, "backup", "config.yml"), secret)
	untracked := fakeTokenLine('b')
	writeFile(t, filepath.Join(dir, "only-untracked.env"), untracked)

	r, err := runCombined(t, gitAndWorktree(dir, Config{}))
	require.NoError(t, err)
	assertGitShape(t, r)

	p := mustGitProv(t, r, types.ComputeBlobID([]byte(secret)))
	require.Len(t, p.Locations, 2)
	for _, l := range p.Locations {
		if l.WorkingTree {
			assert.Nil(t, l.Commit, "working-tree location %q has no commit and no branch", l.Path)
			continue
		}
		require.NotNil(t, l.Commit)
		assert.Equal(t, a, l.Commit.CommitID)
		assert.Equal(t, "main", l.Commit.Branch)
	}
	require.NotNil(t, p.Commit)
	assert.Equal(t, "main", p.Commit.Branch)

	u := mustGitProv(t, r, types.ComputeBlobID([]byte(untracked)))
	assert.Nil(t, u.Commit)
	for _, l := range u.Locations {
		assert.True(t, l.WorkingTree)
		assert.Nil(t, l.Commit)
	}
}

// Occurrence flattening carries the branch to the stored rows and leaves a
// working-tree row without one.
func TestBranchProvenance_OccurrencesCarryBranch(t *testing.T) {
	dir := brInit(t)
	secret := fakeTokenLine('a')
	writeFile(t, filepath.Join(dir, "config.yml"), secret)
	commitAt(t, dir, "A", "2026-01-01T00:00:00Z")
	writeFile(t, filepath.Join(dir, "copy.yml"), secret)
	r, err := runCombined(t, gitAndWorktree(dir, Config{}))
	require.NoError(t, err)
	p := mustGitProv(t, r, types.ComputeBlobID([]byte(secret)))

	occs := types.OccurrencesOf(p)
	require.Len(t, occs, 2)
	byPath := map[string]types.Occurrence{}
	for _, o := range occs {
		byPath[o.Path] = o
	}
	assert.Equal(t, "main", byPath["config.yml"].Branch)
	assert.Equal(t, "", byPath["copy.yml"].Branch)
	assert.True(t, byPath["copy.yml"].WorkingTree)
}

// --- revision/path ambiguity -------------------------------------------------

// Tracked files named like revisions must not make rev-list reject an argument
// as ambiguous: the native resolver ends its revisions with "--", and the
// go-git resolver never shells out. A rev-list failure would leave the
// off-HEAD part unresolved, so the feature commit would lose its branch.
func TestBranchResolver_TrackedFilesNamedLikeRevisions(t *testing.T) {
	dir := brInit(t)
	writeFile(t, filepath.Join(dir, "HEAD"), "not a ref\n")
	writeFile(t, filepath.Join(dir, "main"), "not a ref either\n")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "refs", "heads"), 0o755))
	writeFile(t, filepath.Join(dir, "refs", "heads", "x"), "not a ref\n")
	writeFile(t, filepath.Join(dir, "^HEAD"), "not an exclusion\n")
	c1 := commitAt(t, dir, "c1", "2026-01-01T00:00:00Z")
	runGit(t, dir, "checkout", "-q", "-b", "x")
	x1 := brCommit(t, dir, "x1") // only branch x holds it
	runGit(t, dir, "checkout", "-q", "main")
	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			assert.Equal(t, "main", r.of(c1))
			assert.Equal(t, "x", r.of(x1), "the off-HEAD branch resolves despite files named HEAD, main and refs/heads/x")
			assert.Empty(t, r.notes)
		})
	}
	for walk := range enumWalks {
		t.Run("walk "+walk, func(t *testing.T) {
			got, warn := walkBranches(t, dir, walk)
			assert.Equal(t, map[string]string{c1: "main", x1: "x"}, got)
			assert.Empty(t, warn)
		})
	}
}

// --- total walk-lines cap ----------------------------------------------------

func setWalkLines(t *testing.T, n int) {
	t.Helper()
	old := maxOffHeadWalkLines
	maxOffHeadWalkLines = n
	t.Cleanup(func() { maxOffHeadWalkLines = old })
}

// Several off-HEAD branches that each stay under every per-branch bound but
// together stream more lines than maxOffHeadWalkLines: nothing off HEAD is
// resolved, no branch is invented, and the warning is written once.
func TestBranchResolver_CapMaxOffHeadWalkLines_OmitsOffHeadWarnsOnce(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	var offs []string
	for _, name := range []string{"a", "b", "c"} {
		runGit(t, dir, "checkout", "-q", "-b", name, c1)
		offs = append(offs, brCommit(t, dir, name+"1"), brCommit(t, dir, name+"2"))
	}
	runGit(t, dir, "checkout", "-q", "main")
	setWalkLines(t, 3) // six off-HEAD lines are streamed in total

	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			for _, c := range offs {
				assert.Equal(t, "", r.of(c), "no branch is invented past the cap")
			}
			assert.Equal(t, "main", r.of(c1), "the HEAD set does not depend on the walk-lines cap")
			require.Len(t, r.notes, 1)
			assert.Equal(t, 1, strings.Count(branchWarnings(r), "\n"), "one warning line")
			assert.Contains(t, branchWarnings(r), "titus: branch not recorded for commits outside the checked-out branch")
		})
	}
	for walk := range enumWalks {
		t.Run("walk "+walk, func(t *testing.T) {
			got, warn := walkBranches(t, dir, walk)
			assert.Equal(t, "", got[offs[0]])
			assert.Equal(t, "main", got[c1])
			assert.Equal(t, 1, strings.Count(warn, "titus: branch not recorded for commits outside"), "warned once per walk")
		})
	}
}

// At exactly the bound the walks complete and everything resolves.
func TestBranchResolver_CapMaxOffHeadWalkLines_ExactBoundResolves(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "checkout", "-q", "-b", "a", c1)
	a1 := brCommit(t, dir, "a1")
	runGit(t, dir, "checkout", "-q", "-b", "b", c1)
	b1 := brCommit(t, dir, "b1")
	runGit(t, dir, "checkout", "-q", "main")
	setWalkLines(t, 2)
	for backend, r := range resolversFor(t, dir) {
		t.Run(backend, func(t *testing.T) {
			assert.Equal(t, "a", r.of(a1))
			assert.Equal(t, "b", r.of(b1))
			assert.Empty(t, r.notes)
		})
	}
}

// --- branch-count cap at the listing functions -------------------------------

func TestBranchListing_CapMaxBranches_StopsWithErrBranchCap(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	runGit(t, dir, "branch", "a", c1)
	runGit(t, dir, "branch", "b", c1)
	repo, err := openGoGitRepo(dir)
	require.NoError(t, err)
	ctx := context.Background()

	t.Run("under the bound lists every branch", func(t *testing.T) {
		setCaps(t, defaultMaxHeadCommits, 3, defaultMaxOffHeadCommits) // main, a, b
		_, refs, err := nativeBranchRefs(ctx, dir, nil)
		require.NoError(t, err)
		assert.Len(t, refs, 3)
		tips, err := goGitBranchTips(repo)
		require.NoError(t, err)
		assert.Len(t, tips, 3)
	})
	t.Run("over the bound both listings stop", func(t *testing.T) {
		setCaps(t, defaultMaxHeadCommits, 2, defaultMaxOffHeadCommits)
		ids, refs, err := nativeBranchRefs(ctx, dir, nil)
		assert.ErrorIs(t, err, errBranchCap)
		assert.Empty(t, ids)
		assert.Empty(t, refs)
		_, err = goGitBranchTips(repo) // the partial map is not used on error
		assert.ErrorIs(t, err, errBranchCap)
		_, err = nativeBranchTips(ctx, dir)
		assert.ErrorIs(t, err, errBranchCap)
	})
}

// Refs that share a short name are one branch against the bound, and the note
// reaches the resolver; the checked-out branch's own commits keep resolving.
func TestBranchResolver_CapMaxBranches_NoteAndHeadSet(t *testing.T) {
	src := brInit(t)
	c1 := brCommit(t, src, "c1")
	runGit(t, src, "checkout", "-q", "-b", "feature", c1)
	f1 := brCommit(t, src, "f1")
	runGit(t, src, "checkout", "-q", "main")
	dst := filepath.Join(t.TempDir(), "clone")
	runGit(t, src, "clone", "-q", "file://"+src, dst) // refs: main, origin/main, origin/feature (HEAD excluded)

	setCaps(t, defaultMaxHeadCommits, 2, defaultMaxOffHeadCommits) // exactly main + feature
	for backend, r := range resolversFor(t, dst) {
		t.Run(backend+"/at the bound with duplicate refs", func(t *testing.T) {
			assert.Equal(t, "feature", r.of(f1))
			assert.Empty(t, r.notes)
		})
	}
	setCaps(t, defaultMaxHeadCommits, 1, defaultMaxOffHeadCommits)
	for backend, r := range resolversFor(t, dst) {
		t.Run(backend+"/over the bound", func(t *testing.T) {
			assert.Equal(t, "", r.of(f1), "never guessed")
			assert.Equal(t, "main", r.of(c1), "the checked-out branch keeps its commits")
			assert.Contains(t, branchWarnings(r), "more than 1 branches")
		})
	}
}
