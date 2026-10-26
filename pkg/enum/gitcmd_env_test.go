package enum

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// envNames returns the variable names of env, in order.
func envNames(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		out = append(out, name)
	}
	return out
}

// S2: inheritedGitEnv drops every inherited variable that selects another
// repository, object store or config, and keeps the rest of the
// environment, including the user's global config (safe.directory may live
// there). Names are compared upper-cased on every OS, so a lower-case
// git_dir is dropped too: Windows treats it as GIT_DIR.
func TestInheritedGitEnv_DropsRepoSelectingVars(t *testing.T) {
	dropped := []string{
		"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
		"GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE",
		"GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
		"GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
		"GIT_CONFIG_KEY_17", "GIT_CONFIG_PARAMETERS", "GIT_REPLACE_REF_BASE",
		"GIT_GRAFT_FILE", "GIT_SHALLOW_FILE", "GIT_QUARANTINE_PATH", "GIT_PREFIX",
		"git_dir", "Git_Config_Parameters",
	}
	for _, name := range dropped {
		t.Setenv(name, "decoy")
	}
	kept := map[string]string{
		"HOME":              t.TempDir(),
		"PATH":              "/usr/bin:/bin",
		"GIT_CONFIG_GLOBAL": filepath.Join(t.TempDir(), "gitconfig"),
		"GIT_AUTHOR_NAME":   "Kept Author",
		"TITUS_UNRELATED":   "x",
	}
	for k, v := range kept {
		t.Setenv(k, v)
	}

	env := inheritedGitEnv()
	names := envNames(env)
	for _, name := range dropped {
		if slices.Contains(names, name) {
			t.Errorf("inheritedGitEnv kept %s", name)
		}
	}
	for k, v := range kept {
		if !slices.Contains(env, k+"="+v) {
			t.Errorf("inheritedGitEnv dropped %s=%s", k, v)
		}
	}
}

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

// S2: config injected through the environment (GIT_CONFIG_COUNT/KEY/VALUE
// or GIT_CONFIG_PARAMETERS) does not reach a hardened git command; config
// set in the repository still does (benign control).
func TestHardenedGit_EnvConfigNotInjected(t *testing.T) {
	target, _ := s2Repos(t)
	runGit(t, target, "config", "titus.repoowned", "yes")

	cases := map[string]map[string]string{
		"GIT_CONFIG_COUNT":      {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "titus.injected", "GIT_CONFIG_VALUE_0": "yes"},
		"GIT_CONFIG_PARAMETERS": {"GIT_CONFIG_PARAMETERS": "'titus.injected'='yes'"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			for k, v := range env {
				t.Setenv(k, v)
			}
			if out, err := hardenedGit(context.Background(), target, "config", "--get", "titus.injected").Output(); err == nil {
				t.Errorf("injected config reached git: titus.injected = %q", strings.TrimSpace(string(out)))
			}
			out, err := hardenedGit(context.Background(), target, "config", "--get", "titus.repoowned").Output()
			if err != nil || strings.TrimSpace(string(out)) != "yes" {
				t.Errorf("repository config titus.repoowned = %q, %v; want yes", out, err)
			}
		})
	}
}

// S3: RemoteURL reads the target's origin.
func TestRemoteURL_ReadsOrigin(t *testing.T) {
	target, _ := s2Repos(t)
	runGit(t, target, "remote", "add", "origin", "https://github.com/acme/target.git")

	got, err := RemoteURL(context.Background(), target)
	if err != nil || got != "https://github.com/acme/target.git" {
		t.Errorf("RemoteURL = %q, %v; want https://github.com/acme/target.git", got, err)
	}
}

// S3: RemoteURL reads the target's own origin even with GIT_DIR or an
// injected remote.origin.url in the environment, so the accessibility
// check and the location identity name the scanned repository.
func TestRemoteURL_IgnoresDecoyEnvironment(t *testing.T) {
	cases := map[string]func(t *testing.T, decoy string){
		"GIT_DIR": func(t *testing.T, decoy string) { t.Setenv("GIT_DIR", filepath.Join(decoy, ".git")) },
		"GIT_CONFIG_COUNT": func(t *testing.T, _ string) {
			t.Setenv("GIT_CONFIG_COUNT", "1")
			t.Setenv("GIT_CONFIG_KEY_0", "remote.origin.url")
			t.Setenv("GIT_CONFIG_VALUE_0", "https://github.com/decoy/injected.git")
		},
	}
	for name, setDecoy := range cases {
		t.Run(name, func(t *testing.T) {
			target, decoy := s2Repos(t)
			runGit(t, target, "remote", "add", "origin", "https://github.com/acme/target.git")
			setDecoy(t, decoy)

			got, err := RemoteURL(context.Background(), target)
			if err != nil || got != "https://github.com/acme/target.git" {
				t.Errorf("RemoteURL = %q, %v; want the target's own origin https://github.com/acme/target.git", got, err)
			}
		})
	}
}

// S3: a repository with no origin is an error, also with a decoy GIT_DIR
// whose repository has one.
func TestRemoteURL_NoRemoteIsError(t *testing.T) {
	target, decoy := s2Repos(t)
	if got, err := RemoteURL(context.Background(), target); err == nil {
		t.Errorf("RemoteURL with no origin = %q, want an error", got)
	}
	t.Setenv("GIT_DIR", filepath.Join(decoy, ".git"))
	if got, err := RemoteURL(context.Background(), target); err == nil {
		t.Errorf("RemoteURL with no origin and a decoy GIT_DIR = %q, want an error", got)
	}
}
