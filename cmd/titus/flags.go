package main

import (
	"runtime"
	"time"

	"github.com/spf13/cobra"
)

// addRulesFlags registers rule-loading flags onto cmd.
// Flags bind into scanRulesPath, scanRulesInclude, scanRulesExclude, scanRuleset
// globals defined in scan.go and consumed by loadRules.
func addRulesFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules file or directory (merged with builtins)")
	cmd.Flags().StringVar(&scanRulesInclude, "rules-include", "", "Include rules matching regex pattern (comma-separated)")
	cmd.Flags().StringVar(&scanRulesExclude, "rules-exclude", "", "Exclude rules matching regex pattern (comma-separated)")
	cmd.Flags().StringVar(&scanRuleset, "ruleset", "default", "Ruleset to use: default, np.assets, np.hashes, all (all = no filtering)")
}

// addOutputFlags registers output-path and format flags onto cmd.
// Flags bind into scanOutputPath and scanOutputFormat globals.
//
// Default output path is "titus.ds" (datastore directory). Subcommands that
// historically defaulted to "titus.db" (a single sqlite file) opt in to the
// datastore default by calling this helper. Override with cmd.Flags().Lookup
// after the call if a different default is required.
func addOutputFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&scanOutputPath, "output", "titus.ds", "Output datastore path (:memory: for in-memory, :auto: to derive from target name)")
	cmd.Flags().StringVar(&scanOutputFormat, "format", "human", "Output format: json, sarif, human")
}

// addPipelineFlags registers all flags that runPipeline reads from package
// globals: worker pool sizing, file-size/context limits, validation, scoring,
// extraction limits, accessibility, ignore file, blob storage, incremental.
func addPipelineFlags(cmd *cobra.Command) {
	cmd.Flags().IntVar(&scanWorkers, "workers", runtime.NumCPU(), "Number of parallel scan workers")
	cmd.Flags().IntVar(&scanReaders, "readers", 0, "Number of parallel file readers (0 = NumCPU)")
	cmd.Flags().Int64Var(&scanMaxFileSize, "max-file-size", 10*1024*1024, "Maximum file size to scan (bytes)")
	cmd.Flags().IntVar(&scanContextLines, "context-lines", 3, "Lines of context before/after matches (0 to disable)")
	cmd.Flags().BoolVar(&scanIncremental, "incremental", false, "Skip already-scanned blobs")
	cmd.Flags().BoolVar(&scanValidate, "validate", false, "Validate detected secrets against their source APIs")
	cmd.Flags().IntVar(&scanValidateWorkers, "validate-workers", 4, "Number of concurrent validation workers")
	cmd.Flags().BoolVar(&scanStoreBlobs, "store-blobs", false, "Store file contents in blobs/ directory")
	cmd.Flags().StringVar(&scanAccessibility, "accessibility", "auto",
		`code accessibility: "public" (no penalty), "private" (-25 to all scores),`+"\n"+
			`or "auto" (detect via git remote/GitHub API, defaults to private if undetermined)`)
	cmd.Flags().StringVar(&scanIgnoreFile, "ignore", "", "Path to gitignore-style ignore file (replaces built-in defaults; use /dev/null to disable)")
	cmd.Flags().Var(&scanExtractArchivesFlag, "extract", "Extract text from binary files (extensions: xlsx,docx,pdf,zip or 'all')")
	cmd.Flags().StringVar(&extractMaxSize, "extract-max-size", "10MB", "Max uncompressed size per extracted file")
	cmd.Flags().StringVar(&extractMaxTotal, "extract-max-total", "100MB", "Max total bytes to extract from one archive")
	cmd.Flags().IntVar(&extractMaxDepth, "extract-max-depth", 5, "Max nested archive depth")
	cmd.Flags().IntVar(&scanSQLiteRowLimit, "sqlite-row-limit", 1000, "Max rows per table for SQLite extraction (0 for unlimited)")
	cmd.Flags().BoolVar(&scanScopeEnabled, "score-scope", false, "Enable HTTP dynamic scoring modifiers")
	cmd.Flags().DurationVar(&scanScoreTimeout, "score-timeout", 10*time.Second, "Per-modifier HTTP timeout for dynamic scoring")
	cmd.Flags().DurationVar(&scanScoreBudget, "score-budget", 60*time.Second, "Per-finding overall scoring budget across all modifiers (0 = unlimited)")
}
