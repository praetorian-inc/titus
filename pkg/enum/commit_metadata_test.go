package enum

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// --- fixture helpers -------------------------------------------------------

// commitAt stages everything and commits with fixed author and committer
// dates, returning the full commit id.
func commitAt(t *testing.T, dir, msg, date string, extra ...string) string {
	t.Helper()
	runGit(t, dir, "add", "-A")
	args := []string{"commit", "-q", "--allow-empty", "--no-gpg-sign"}
	if msg != "" {
		args = append(args, "-m", msg)
	}
	runGitEnv(t, dir, []string{"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_DATE=" + date}, append(args, extra...)...)
	return gitOutput(t, dir, "rev-parse", "HEAD")
}

func runGitEnv(t *testing.T, dir string, env []string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return gitInput(t, dir, nil, args...)
}

func gitInput(t *testing.T, dir string, stdin []byte, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

func hashBlob(t *testing.T, dir, content string) string {
	t.Helper()
	return gitInput(t, dir, []byte(content), "hash-object", "-w", "--stdin")
}

type locWant struct {
	path   string
	commit string
}

func locsOf(locs []types.GitLocation) []locWant {
	out := make([]locWant, 0, len(locs))
	for _, l := range locs {
		w := locWant{path: l.Path}
		if l.Commit != nil {
			w.commit = l.Commit.CommitID
		}
		out = append(out, w)
	}
	return out
}
