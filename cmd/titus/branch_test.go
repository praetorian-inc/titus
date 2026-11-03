package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

// End to end through `titus scan --git` and the report renderers, on real git
// repositories. Fixtures use the synthetic scan rule of scan_test.go.

// branchScanReport scans target (a directory under the cwd) with --git and
// returns the report's human location lines and its JSON locations.
func branchScanReport(t *testing.T, root, target string) (human []string, locs []jsonLocation) {
	t.Helper()
	t.Chdir(root)
	ds := tempDatastore(t)
	jsonOut := scanJSONMatches(t, scanForTest(t, target, ds, "json", true))
	require.Len(t, jsonOut, 1)

	s, err := store.New(store.Config{Path: filepath.Join(ds, "datastore.db")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	findings, err := s.GetFindings()
	require.NoError(t, err)
	matches, err := s.GetAllMatches()
	require.NoError(t, err)
	builtins, err := rule.NewLoader().LoadBuiltinRules()
	require.NoError(t, err)
	ruleMap := map[string]*types.Rule{}
	for _, r := range builtins {
		ruleMap[r.ID] = r
	}
	return humanLocationLines(renderHuman(t, s, findings, matches, ruleMap)), jsonOut[0].Locations
}

func commitShort(t *testing.T, repo string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repo, "rev-parse", "--short=7", "HEAD").Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(out))
}

// CASE-REPORT-1 and CASE-PROV-1: c1 is on main and feature/login with
// feature/login checked out; the report line and the JSON name feature/login.
func TestScanReportE2E_CASE_REPORT_1_CheckedOutBranchShown(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "acme-api")
	gitRepoForTest(t, repo, "", map[string]string{"config.yml": locTestSecret})
	gitForTest(t, repo, "checkout", "-q", "-b", "feature/login")
	c1 := commitShort(t, repo)

	human, locs := branchScanReport(t, root, "acme-api")

	assert.Equal(t, []string{"    acme-api  config.yml:1  " + c1 + "  2024-01-02  branch feature/login"}, human)
	require.Len(t, locs, 1)
	require.NotNil(t, locs[0].Branch)
	assert.Equal(t, "feature/login", *locs[0].Branch)
}

// CASE-CHECKED-1: aaa-other sorts first but main is checked out.
func TestScanReportE2E_CASE_CHECKED_1_NotFirstSortedBranch(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "acme-api")
	gitRepoForTest(t, repo, "", map[string]string{"config.yml": locTestSecret})
	gitForTest(t, repo, "branch", "aaa-other")
	c1 := commitShort(t, repo)

	human, locs := branchScanReport(t, root, "acme-api")

	assert.Equal(t, []string{"    acme-api  config.yml:1  " + c1 + "  2024-01-02  branch main"}, human)
	require.NotNil(t, locs[0].Branch)
	assert.Equal(t, "main", *locs[0].Branch)
}

// CASE-HOST-*: the same repository with each host's origin URL reports the
// same branch.
func TestScanReportE2E_CASE_HOST_SameBranchForEveryHost(t *testing.T) {
	hosts := map[string]string{
		"azure-devops": "https://dev.azure.com/org/project/_git/repo",
		"gitlab":       "https://gitlab.com/group/repo.git",
		"github":       "https://github.com/org/repo.git",
		"bitbucket":    "https://bitbucket.org/org/repo.git",
	}
	for host, url := range hosts {
		t.Run("CASE-HOST-"+host, func(t *testing.T) {
			root := t.TempDir()
			repo := filepath.Join(root, "work")
			gitRepoForTest(t, repo, url, map[string]string{"config.yml": locTestSecret})

			human, locs := branchScanReport(t, root, "work")

			require.Len(t, human, 1)
			assert.True(t, strings.HasSuffix(human[0], "  2024-01-02  branch main"), human[0])
			require.Len(t, locs, 1)
			require.NotNil(t, locs[0].Branch)
			assert.Equal(t, "main", *locs[0].Branch)
		})
	}
}

// CASE-OMIT-REPORT-1: C1 is on no branch and HEAD is detached at it: the
// line has no branch segment at all and the JSON branch is null.
func TestScanReportE2E_CASE_OMIT_REPORT_1_DetachedOrphanOmitsBranch(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "acme-api")
	gitRepoForTest(t, repo, "", map[string]string{"base.txt": "base\n"})
	gitForTest(t, repo, "checkout", "-q", "--detach")
	writeFileForTest(t, filepath.Join(repo, "config.yml"), locTestSecret)
	gitForTest(t, repo, "add", "-A")
	gitForTest(t, repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "c1")
	c1 := commitShort(t, repo)

	human, locs := branchScanReport(t, root, "acme-api")

	assert.Equal(t, []string{"    acme-api  config.yml:1  " + c1 + "  2024-01-02"}, human)
	require.Len(t, locs, 1)
	assert.Nil(t, locs[0].Branch, "CASE-OMIT-PROV-1: no branch is null, not HEAD and not main")
	require.NotNil(t, locs[0].Commit)
	assert.Equal(t, c1, (*locs[0].Commit)[:7])
}

// CASE-COMMIT-1: the commit the report records is the introducing commit, not
// the tip of the branch the resolver picked.
func TestScanReportE2E_CASE_COMMIT_1_RecordedCommitUnchanged(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "acme-api")
	gitRepoForTest(t, repo, "", map[string]string{"config.yml": locTestSecret})
	c1 := commitShort(t, repo)
	gitForTest(t, repo, "branch", "aaa-other")
	writeFileForTest(t, filepath.Join(repo, "later.txt"), "later\n")
	gitForTest(t, repo, "add", "-A")
	gitForTest(t, repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "tip")
	require.NotEqual(t, c1, commitShort(t, repo))

	human, locs := branchScanReport(t, root, "acme-api")

	assert.Equal(t, []string{"    acme-api  config.yml:1  " + c1 + "  2024-01-02  branch main"}, human)
	require.NotNil(t, locs[0].Commit)
	assert.Equal(t, c1, (*locs[0].Commit)[:7])
}
