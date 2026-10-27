package enum

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

const b1Secret = "B1_FORMAT_SECRET=ghp_example\n"

// b1Repo returns a repository with one commit of b1Secret at s.txt.
func b1Repo(t *testing.T) string {
	t.Helper()
	skipIfNoGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "s.txt"), b1Secret)
	commitAt(t, dir, "c", "2026-01-01T00:00:00Z")
	return dir
}

// goGitWalkErr runs the go-git walk over dir and returns its error and
// whether it reported b1Secret.
func goGitWalkErr(dir string) (seen bool, err error) {
	err = nativeEnum(dir).enumerateAllHistory(context.Background(), func(content []byte, _ types.BlobID, _ types.Provenance) error {
		if string(content) == b1Secret {
			seen = true
		}
		return nil
	})
	return seen, err
}

// appendConfig appends raw text to the repository's .git/config, so the
// key spelling is exactly what the test gives (git config would normalise
// it).
func appendConfig(t *testing.T, dir, text string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

// dropFormatVersion removes every core.repositoryformatversion line from
// the repository's .git/config, so a case can state the version (or its
// absence) and the order of [core] sections itself.
func dropFormatVersion(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, ".git", "config")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if !strings.Contains(strings.ToLower(line), "repositoryformatversion") {
			kept = append(kept, line)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "")), 0o644); err != nil {
		t.Fatal(err)
	}
}

// B1: go-git does not read reftable refs, so a walk of a reftable
// repository would see no refs and report nothing, without an error. The
// go-git walk must fail closed with an error that names the extension and
// the remedy; the native walk reads the repository as before.
func TestGoGitHistory_ReftableRejected(t *testing.T) {
	r7SkipIfGitOlder(t, 2, 45)
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", "--ref-format=reftable", dir).CombinedOutput(); err != nil {
		t.Skipf("git cannot create a reftable repository: %v %s", err, out)
	}
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test User")
	writeFile(t, filepath.Join(dir, "s.txt"), b1Secret)
	commitAt(t, dir, "c", "2026-01-01T00:00:00Z")

	seen, err := goGitWalkErr(dir)
	if err == nil {
		t.Fatalf("go-git walk of a reftable repository succeeded (secret seen %v), want an error", seen)
	}
	for _, want := range []string{"extensions.refstorage=reftable", "install git"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	t.Run("native unaffected", func(t *testing.T) {
		got, _ := runWalkWarn(t, dir, enumWalks["native"])
		if !got[b1Secret] {
			t.Errorf("native walk of the reftable repository missed the secret")
		}
	})
}

// B1: the formats go-git does not read are rejected; the ones it does read
// still walk, and the native walk agrees on the result. Config text is
// written raw so mixed-case keys reach the check as a user could write them
// (git keys are case-insensitive; git rejects an upper-case objectformat
// value, so the values stay lower-case where the native walk is the
// control).
func TestGoGitHistory_RepositoryFormatGate(t *testing.T) {
	cases := []struct {
		name   string
		config string
		reject string // substring of the error; "" means the walk succeeds
		// dropVersion removes the repositoryformatversion git init wrote,
		// so config alone decides the version.
		dropVersion bool
	}{
		{"unknown extension", "[core]\n\trepositoryformatversion = 1\n[extensions]\n\ttitusfuture = true\n", "extensions.titusfuture=true", false},
		{"objectformat sha256 value", "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha256\n", "extensions.objectformat=sha256", false},
		{"version 2", "[core]\n\trepositoryformatversion = 2\n", "repositoryformatversion 2", false},
		{"mixed-case reftable", "[Core]\n\tRepositoryFormatVersion = 1\n[Extensions]\n\tRefStorage = reftable\n", "extensions.refstorage=reftable", false},
		{"worktreeconfig and objectformat sha1", "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tworktreeconfig = true\n\tobjectformat = sha1\n", "", false},
		{"mixed-case allowed extensions", "[CORE]\n\tRepositoryFormatVersion = 1\n[Extensions]\n\tWorktreeConfig = true\n\tObjectFormat = sha1\n\tPreciousObjects = true\n", "", false},
		// R9-1: a version 0 (or unset) repository runs the same extensions
		// check as version 1, so a walk never silently yields no history.
		{"version 0 unknown extension", "[core]\n\trepositoryformatversion = 0\n[extensions]\n\ttitusfuture = true\n", "extensions.titusfuture=true", false},
		{"version 0 reftable", "[core]\n\trepositoryformatversion = 0\n[extensions]\n\trefstorage = reftable\n", "extensions.refstorage=reftable", true},
		{"no version key reftable", "[extensions]\n\trefstorage = reftable\n", "extensions.refstorage=reftable", true},
		{"no version key objectformat sha256", "[extensions]\n\tobjectformat = sha256\n", "extensions.objectformat=sha256", true},
		{"duplicate core last version 0 reftable", "[core]\n\trepositoryformatversion = 1\n[extensions]\n\trefstorage = reftable\n[core]\n\trepositoryformatversion = 0\n", "extensions.refstorage=reftable", true},
		// Allowed extensions still walk at version 0 or unset. objectformat
		// is left out: git refuses it in a version 0 repository ("v1-only
		// extension"), so the native control could not read the fixture.
		{"version 0 allowed extension", "[core]\n\trepositoryformatversion = 0\n[extensions]\n\tpreciousobjects = true\n", "", true},
		{"no version key allowed extensions", "[extensions]\n\tworktreeconfig = true\n\tpreciousobjects = true\n", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := b1Repo(t)
			if c.dropVersion {
				dropFormatVersion(t, dir)
			}
			// The last repositoryformatversion in the file wins, as in git.
			appendConfig(t, dir, c.config)

			seen, err := goGitWalkErr(dir)
			if c.reject != "" {
				if err == nil {
					t.Fatalf("go-git walk succeeded (secret seen %v), want an error containing %q", seen, c.reject)
				}
				if !strings.Contains(err.Error(), c.reject) || !strings.Contains(err.Error(), "install git") {
					t.Errorf("error %q, want it to contain %q and the remedy", err, c.reject)
				}
				return
			}
			if err != nil {
				t.Fatalf("go-git walk: %v, want it to walk", err)
			}
			if !seen {
				t.Errorf("go-git walk did not report the secret")
			}
			if got, _ := runWalkWarn(t, dir, enumWalks["native"]); !got[b1Secret] {
				t.Errorf("native walk did not report the secret")
			}
		})
	}
}
