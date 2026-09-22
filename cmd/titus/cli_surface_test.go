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

var updateGoldens = flag.Bool("update", false, "rewrite docs/cli-surface.json, docs/CLI.md and the generated README.md regions from the live cobra tree")

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

	if findings := clisurface.Diff(documented, live); len(findings) > 0 {
		require.Fail(t, "CLI surface drift", docs.Report(findings))
	}

	stale, err := docs.CheckArtifacts(root, live)
	require.NoError(t, err)
	if len(stale) > 0 {
		assert.Fail(t, "generated CLI documentation is stale", stalenessReport(stale))
	}
}

func TestCLISurfaceDocLint(t *testing.T) {
	docs := cliDocs(t)
	root := repoRoot(t)

	allow, err := docs.LoadAllowlist(root)
	require.NoError(t, err)

	issues, scope, err := docs.LintRepo(root, clisurface.Walk(rootCmd), allow)
	require.NoError(t, err)

	t.Logf("linted %d markdown file(s) [%s] and %d Go file(s) under %d Go dir(s) [%s], with %d token(s) allowlisted; skipped %d entr(y/ies) that are not regular files [%s]",
		len(scope.MarkdownFiles), scopeList(scope.MarkdownFiles),
		len(scope.GoFiles), len(scope.GoDirs), scopeList(scope.GoDirs),
		len(scope.Allowlist.Entries()),
		len(scope.SkippedIrregular), scopeList(scope.SkippedIrregular))

	if len(issues) > 0 {
		assert.Fail(t, "documentation names flags the CLI does not accept", clisurface.LintReport(issues, scope))
	}
}

func TestCLISurfaceGateDetectsRename(t *testing.T) {
	docs := cliDocs(t)
	documented := clisurface.Walk(rootCmd)

	t.Run("renaming a registered flag is reported", func(t *testing.T) {
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

		backticked := docs.LintMarkdown(documented, "docs/example.md", "Pass `--linear-token` to authenticate.\n", empty)
		require.Len(t, backticked, 1)
		assert.Equal(t, "--linear-token", backticked[0].Token)

		bare := docs.LintMarkdown(documented, "docs/example.md", "Pass --linear-token to authenticate.\n", empty)
		assert.Empty(t, bare, "unbackticked prose is not inspected; a probe written this way would pass against a working gate")
	})
}

func repoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	require.NoError(t, err)

	root, err := clisurface.FindRepoRoot(wd)
	require.NoError(t, err)

	return root
}

func stalenessReport(stale []clisurface.Staleness) string {
	lines := make([]string, 0, len(stale))
	for _, s := range stale {
		lines = append(lines, s.String())
	}

	return strings.Join(lines, "\n")
}

func scopeList(items []string) string {
	if len(items) == 0 {
		return "none"
	}

	return strings.Join(items, ", ")
}
