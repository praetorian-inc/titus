package enum

import (
	"path/filepath"
	"testing"
)

// s2Repos returns a target repository with a commit of target.txt and a
// decoy repository with a commit of decoy.txt and a remote, built before any
// decoy variable is set (the fixture helpers inherit the environment).
func s2Repos(t *testing.T) (target, decoy string) {
	t.Helper()
	skipIfNoGit(t)
	target, decoy = t.TempDir(), t.TempDir()
	for dir, content := range map[string]string{target: s2TargetSecret, decoy: s2DecoySecret} {
		initGitRepo(t, dir)
		writeFile(t, filepath.Join(dir, "secret.txt"), content)
		commitAt(t, dir, "c", "2026-01-01T00:00:00Z")
	}
	runGit(t, decoy, "remote", "add", "origin", "https://github.com/decoy/other.git")
	return target, decoy
}

const (
	s2TargetSecret = "S2_TARGET_SECRET=ghp_example\n"
	s2DecoySecret  = "S2_DECOY_SECRET=ghp_example\n"
)

// S2: a GIT_DIR in the scanner's environment must not redirect the native
// walk to another repository. Before the filter, git ran in the target
// directory but read the decoy's objects, so the scan reported the other
// repository's secret and missed the target's.
func TestHardenedGit_DecoyGitDirDoesNotRedirectScan(t *testing.T) {
	target, decoy := s2Repos(t)
	t.Setenv("GIT_DIR", filepath.Join(decoy, ".git"))

	seen, warn := runWalkWarn(t, target, enumWalks["native"])
	if seen[s2DecoySecret] {
		t.Errorf("scan of %s read the decoy repository named by GIT_DIR (warnings %q)", target, warn)
	}
	if !seen[s2TargetSecret] {
		t.Errorf("scan of %s missed the target's own secret (warnings %q)", target, warn)
	}
}
