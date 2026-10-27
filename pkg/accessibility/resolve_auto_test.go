package accessibility

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// S3: Resolve "auto" reads the remote through enum.RemoteURL and falls back
// to Private whenever there is no remote to check. These cases make no
// network call: there is no URL for a platform API to match.

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
}

func gitRun(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("git", args...).CombinedOutput()
	require.NoError(t, err, string(out))
}

// A repository with no origin is Private, also when GIT_DIR names another
// repository whose origin is on GitHub.
func TestResolve_AutoNoRemoteIsPrivate(t *testing.T) {
	requireGit(t)
	dir, decoy := t.TempDir(), t.TempDir()
	gitRun(t, "init", "-q", dir)
	gitRun(t, "init", "-q", decoy)
	gitRun(t, "-C", decoy, "remote", "add", "origin", "https://git.example.invalid/decoy/other.git")

	assert.Equal(t, Private, Resolve("auto", dir, ""))
	t.Setenv("GIT_DIR", filepath.Join(decoy, ".git"))
	assert.Equal(t, Private, Resolve("auto", dir, ""))
}

// A directory that is not a git repository is Private.
func TestResolve_AutoNotARepoIsPrivate(t *testing.T) {
	requireGit(t)
	assert.Equal(t, Private, Resolve("auto", t.TempDir(), ""))
}

// An origin on a host with no platform API is Private.
func TestResolve_AutoUnknownHostIsPrivate(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitRun(t, "init", "-q", dir)
	gitRun(t, "-C", dir, "remote", "add", "origin", "https://git.example.invalid/acme/app.git")
	assert.Equal(t, Private, Resolve("auto", dir, ""))
}
