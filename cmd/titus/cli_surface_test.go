package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/capability-sdk/pkg/clisurface"
)

// updateGoldens regenerates the committed CLI-surface artifacts from the live
// cobra tree instead of asserting against them. The Makefile's cli-docs target
// is the supported entry point; running the flag by hand is equivalent.
var updateGoldens = flag.Bool("update", false, "rewrite docs/cli-surface.json, docs/CLI.md and the generated README.md regions from the live cobra tree")

// cliDocs builds the drift gate's configuration.
//
// It is a constructor rather than a package-level value so that a bad config
// surfaces as a test failure carrying New's error, instead of panicking during
// package initialization where no test name is attached to the blame.
//
// The two lint scopes are pinned deliberately, not inherited:
//
//   - LintedGoDirs. The SDK's default is {"cmd", "internal", "pkg"}. titus has
//     no internal/ directory — only cmd/ and pkg/ exist — and the SDK silently
//     skips a configured directory that is absent, so the default would have
//     worked by accident. Pinning {"cmd", "pkg"} makes the scope a decision
//     titus owns: when internal/ is added, adding it here is a deliberate,
//     reviewable line rather than a silent widening of what the gate reads.
//
//   - LintedMarkdown. The SDK's default is READMEPath alone. "README.md" has
//     to be spelled literally here because defaultREADMEPath is unexported, so
//     naming any other file means re-stating the README too or losing it.
//     CONTRIBUTING.md is added even though it names no titus flag today: it is
//     the repo's other hand-written contributor document, it already carries
//     fenced shell blocks, and the failure it forecloses is a silent one:
//     a `titus scan` example added there later would name flags that
//     nothing ever checks. The marginal cost is one more file read per run.
//
// Everything under docs/ is linted regardless of this list: the SDK walks
// DocsWalkRoot recursively for *.md on top of whatever LintedMarkdown names.
func cliDocs(t *testing.T) *clisurface.Docs {
	t.Helper()

	docs, err := clisurface.New(clisurface.Config{
		RegenerateCommand: "make cli-docs",
		LintedMarkdown:    []string{"README.md", "CONTRIBUTING.md"},
		LintedGoDirs:      []string{"cmd", "pkg"},
	})
	require.NoError(t, err)

	return docs
}

// TestCLISurface fails when the committed CLI documentation and the cobra
// command tree disagree, in either direction: a command or flag that cobra
// registers but the docs omit, and one the docs still describe but cobra no
// longer accepts.
func TestCLISurface(t *testing.T) {
	docs := cliDocs(t)
	cfg := docs.Config()
	root := repoRoot(t)
	live := clisurface.Walk(rootCmd)

	if *updateGoldens {
		require.NoError(t, docs.Write(root, live))
		t.Logf("regenerated %s", strings.Join(docs.GeneratedPaths(), ", "))
		return
	}

	golden, err := os.ReadFile(filepath.Join(root, cfg.JSONPath))
	require.NoErrorf(t, err, "%s is missing; create it with %q", cfg.JSONPath, cfg.RegenerateCommand)

	documented, err := docs.ParseJSON(golden)
	require.NoError(t, err)

	// require.Fail rather than require.Empty: Empty dumps the raw finding
	// slice, which prints every disagreement twice and reads far worse than
	// the report.
	if findings := clisurface.Diff(documented, live); len(findings) > 0 {
		require.Fail(t, "CLI surface drift", docs.Report(findings))
	}

	stale, err := docs.CheckArtifacts(root, live)
	require.NoError(t, err)
	if len(stale) > 0 {
		assert.Fail(t, "generated CLI documentation is stale", stalenessReport(stale))
	}
}

// TestCLISurfaceDocLint fails when hand-written documentation or a Go comment
// names a flag or subcommand the CLI does not accept.
func TestCLISurfaceDocLint(t *testing.T) {
	docs := cliDocs(t)
	root := repoRoot(t)

	allow, err := docs.LoadAllowlist(root)
	require.NoError(t, err)

	issues, scope, err := docs.LintRepo(root, clisurface.Walk(rootCmd), allow)
	require.NoError(t, err)

	// Logged on a pass as well as a failure: a gate that silently stops
	// reading a file still reports success, so the coverage it actually
	// achieved has to be visible in the run output, not inferred.
	t.Logf("linted %d markdown file(s) [%s] and %d Go file(s) under %d Go dir(s) [%s], with %d token(s) allowlisted; skipped %d entr(y/ies) that are not regular files [%s]",
		len(scope.MarkdownFiles), scopeList(scope.MarkdownFiles),
		len(scope.GoFiles), len(scope.GoDirs), scopeList(scope.GoDirs),
		len(scope.Allowlist.Entries()),
		len(scope.SkippedIrregular), scopeList(scope.SkippedIrregular))

	if len(issues) > 0 {
		assert.Fail(t, "documentation names flags the CLI does not accept", clisurface.LintReport(issues, scope))
	}
}

// TestCLISurfaceGateDetectsRename proves the gate above can fail. A drift gate
// that never reddens passes over exactly the change it exists to catch, so the
// mutations here are the evidence that TestCLISurface and
// TestCLISurfaceDocLint are load-bearing rather than decorative.
func TestCLISurfaceGateDetectsRename(t *testing.T) {
	docs := cliDocs(t)
	documented := clisurface.Walk(rootCmd)

	t.Run("renaming a registered flag is reported", func(t *testing.T) {
		// Mutating a live pflag.Flag is safe here only because nothing in
		// this package calls t.Parallel, so no other test observes the
		// window. pflag also keys its lookup map by the flag's original
		// name, so Lookup("token") keeps working after the rename and only
		// VisitAll — which Walk uses — sees the new name.
		//
		// The fixture is --token on `titus enum linear`: a real local flag on
		// a real subcommand, on a leaf command so nothing inherits it, and
		// registered through registerLinearFlags into a pflag.Flag distinct
		// from the one the hidden `titus linear` alias gets, so the blast
		// radius is one command. "token" sorts before "tokon", and Diff
		// sorts by command then flag, which fixes the two findings' indices.
		flagObj := linearCmd.Flags().Lookup("token")
		require.NotNil(t, flagObj, "the fixture flag must exist for this test to mean anything")
		t.Cleanup(func() { flagObj.Name = "token" })
		flagObj.Name = "tokon"

		findings := clisurface.Diff(documented, clisurface.Walk(rootCmd))
		require.Len(t, findings, 2, "a rename is exactly one removal and one addition, and nothing else:\n%s", docs.Report(findings))

		assert.Equal(t, clisurface.FlagRemoved, findings[0].Kind)
		assert.Equal(t, "token", findings[0].Flag)
		assert.Equal(t, "titus enum linear", findings[0].Command)

		assert.Equal(t, clisurface.FlagUndocumented, findings[1].Kind)
		assert.Equal(t, "tokon", findings[1].Flag)
		assert.Equal(t, "titus enum linear", findings[1].Command)

		assert.Contains(t, findings[0].String(), `flag --token on "titus enum linear" is in the generated docs but cobra no longer accepts it`)
		assert.Contains(t, findings[1].String(), `flag --tokon on "titus enum linear" is registered by cobra but missing from the generated docs`)
	})

	t.Run("the tree is restored", func(t *testing.T) {
		assert.Empty(t, clisurface.Diff(documented, clisurface.Walk(rootCmd)), "the rename above must not leak into the rest of the suite")
	})

	t.Run("a document naming a removed flag is reported", func(t *testing.T) {
		empty, err := docs.ParseAllowlist("")
		require.NoError(t, err)

		// The invocation has to sit inside a fenced block or a backticked
		// span: the prose linter only inspects backticked text, and the shell
		// linter only inspects fenced segments whose argv[0] is `titus`.
		// Unfenced, unbackticked prose is never read at all.
		doc := "Historic note.\n\n```bash\ntitus enum linear --token lin_api_xxx --linear-token lin_api_xxx\n```\n"

		issues := docs.LintMarkdown(documented, "docs/example.md", doc, empty)
		require.Len(t, issues, 1, "only the bogus flag is an issue; --token is real")

		assert.Equal(t, "--linear-token", issues[0].Token)
		assert.Equal(t, "titus enum linear", issues[0].Command)
		assert.Contains(t, issues[0].String(), `docs/example.md:4: --linear-token is not a flag of "titus enum linear"`)
		assert.Contains(t, issues[0].String(), docs.Config().AllowlistPath, "the message says how to allow a deliberate mention")
	})

	t.Run("the allowlist suppresses a deliberate mention", func(t *testing.T) {
		allow, err := docs.ParseAllowlist("--linear-token # renamed to --token; the migration note names the old flag\n")
		require.NoError(t, err)

		doc := "Historic note.\n\n```bash\ntitus enum linear --token lin_api_xxx --linear-token lin_api_xxx\n```\n"

		assert.Empty(t, docs.LintMarkdown(documented, "docs/example.md", doc, allow))
	})

	t.Run("prose is inspected only inside backticks", func(t *testing.T) {
		empty, err := docs.ParseAllowlist("")
		require.NoError(t, err)

		// Measured behavior, asserted so that a future probe written as bare
		// prose is recognized as a broken probe rather than a clean gate: the
		// linter's backtickPattern is applied to every prose line, so a flag
		// named outside backticks is invisible to it.
		backticked := docs.LintMarkdown(documented, "docs/example.md", "Pass `--linear-token` to authenticate.\n", empty)
		require.Len(t, backticked, 1)
		assert.Equal(t, "--linear-token", backticked[0].Token)

		bare := docs.LintMarkdown(documented, "docs/example.md", "Pass --linear-token to authenticate.\n", empty)
		assert.Empty(t, bare, "unbackticked prose is not inspected; a probe written this way would pass against a working gate")
	})
}

// repoRoot resolves the repository root from the test's working directory,
// which `go test` sets to the package directory.
func repoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	require.NoError(t, err)

	root, err := clisurface.FindRepoRoot(wd)
	require.NoError(t, err)

	return root
}

// stalenessReport renders one stale artifact per line.
func stalenessReport(stale []clisurface.Staleness) string {
	lines := make([]string, 0, len(stale))
	for _, s := range stale {
		lines = append(lines, s.String())
	}

	return strings.Join(lines, "\n")
}

// scopeList renders a scope list for the coverage log, naming the empty case
// rather than printing nothing and reading as truncated output.
func scopeList(items []string) string {
	if len(items) == 0 {
		return "none"
	}

	return strings.Join(items, ", ")
}
