package enum

import (
	"os/exec"
	"testing"
)

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
