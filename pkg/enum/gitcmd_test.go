package enum

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestHardenedGit_ArgvAndEnv asserts the exact hardening the helper applies
// (SEC-13): repository config overrides come before the caller's subcommand,
// and the environment disables replace refs, system config, prompts and the
// pager.
func TestHardenedGit_ArgvAndEnv(t *testing.T) {
	cmd := hardenedGit(context.Background(), "/repo", "log", "--all")

	wantArgs := []string{
		"git",
		"-c", "log.showSignature=false",
		"-c", "core.fsmonitor=false",
		"-c", "core.quotePath=true",
		"-c", "log.showRoot=true",
		"-c", "i18n.logOutputEncoding=UTF-8",
		"-c", "diff.external=",
		"-c", "diff.relative=false",
		"-c", "core.hooksPath=/dev/null",
		"-c", "protocol.allow=never",
		"-c", "maintenance.auto=false",
		"-c", "gc.auto=0",
		"log", "--all",
	}
	if !slices.Equal(cmd.Args, wantArgs) {
		t.Fatalf("argv:\n got %q\nwant %q", cmd.Args, wantArgs)
	}
	if cmd.Dir != "/repo" {
		t.Errorf("Dir = %q, want /repo", cmd.Dir)
	}

	for _, kv := range []string{
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_PAGER=cat",
		// V1: no lazy fetch from a partial clone's promisor remote, and an
		// empty transport allow-list (the value is empty, not unset).
		"GIT_NO_LAZY_FETCH=1",
		"GIT_ALLOW_PROTOCOL=",
		"LC_ALL=C",
	} {
		if !slices.Contains(cmd.Env, kv) {
			t.Errorf("env lacks %q", kv)
		}
	}
	for _, kv := range cmd.Env[len(os.Environ()):] {
		if strings.HasPrefix(kv, "GIT_CONFIG_GLOBAL=") {
			t.Errorf("helper must not override GIT_CONFIG_GLOBAL (safe.directory may live there), got %q", kv)
		}
	}
}

// TestHardenedGit_OverridesInheritedEnv asserts that a conflicting inherited
// value is overridden: exec keeps the last duplicate, so the hardened values
// must come after os.Environ().
func TestHardenedGit_OverridesInheritedEnv(t *testing.T) {
	skipIfNoGit(t)
	t.Setenv("GIT_PAGER", "less")

	out, err := hardenedGit(context.Background(), t.TempDir(), "var", "GIT_PAGER").Output()
	if err != nil {
		t.Fatalf("git var: %v", err)
	}
	if got := string(out); got != "cat\n" {
		t.Errorf("GIT_PAGER seen by git = %q, want %q", got, "cat\n")
	}
}

// TestBuildBlobIndex_DoesNotRunSignatureProgram is the SEC-13 fixture: a repo
// whose config turns on log.showSignature with a gpg.program that leaves a
// marker. Indexing must not run that program. The sanity half proves the
// fixture is live: an unhardened `git log` does run it.
func TestBuildBlobIndex_DoesNotRunSignatureProgram(t *testing.T) {
	skipIfNoGit(t)

	dir := t.TempDir()
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "a.txt"), "content")
	runGit(t, dir, "add", ".")

	marker := filepath.Join(t.TempDir(), "gpg-ran")
	script := filepath.Join(t.TempDir(), "fake-gpg.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch '"+marker+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	tree := gitOutput(t, dir, "write-tree")
	commitObj := "tree " + tree + "\n" +
		"author A <a@x> 1767225600 +0000\n" +
		"committer A <a@x> 1767225600 +0000\n" +
		"gpgsig -----BEGIN PGP SIGNATURE-----\n \n AAAA\n -----END PGP SIGNATURE-----\n" +
		"\nsigned-looking\n"
	commit := hashObjectLiterally(t, dir, "commit", commitObj)
	runGit(t, dir, "update-ref", "refs/heads/signed", commit)
	runGit(t, dir, "config", "log.showSignature", "true")
	runGit(t, dir, "config", "gpg.program", script)

	idx := mustBuild(t, dir)
	if got := locsOf(idx.lookup(contentHash("content"))); !slices.Equal(got, []locWant{{"a.txt", commit}}) {
		t.Fatalf("lookup(a.txt) = %+v, want one a.txt location at %s", got, commit)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("buildBlobIndex ran the repository's gpg.program")
	}

	// Sanity: the fixture really does trigger the program without hardening.
	runGit(t, dir, "log", "--all")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("fixture is not live: plain git log did not run gpg.program: %v", err)
	}
}
