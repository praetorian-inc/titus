package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/praetorian-inc/titus/pkg/datastore"
	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/sarif"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

// extensionsValue is a custom flag type that displays as "extensions" in help
type extensionsValue string

func (e *extensionsValue) String() string {
	return string(*e)
}

func (e *extensionsValue) Set(val string) error {
	*e = extensionsValue(val)
	return nil
}

func (e *extensionsValue) Type() string {
	return "extensions"
}

var (
	scanRulesPath           string
	scanRulesInclude        string
	scanRulesExclude        string
	scanOutputPath          string
	scanOutputFormat        string
	scanGit                 bool
	scanMaxFileSize         int64
	scanIncludeHidden       bool
	scanContextLines        int
	scanIncremental         bool
	scanValidate            bool
	scanValidateWorkers     int
	scanStoreBlobs          bool
	scanExtractArchivesFlag extensionsValue
	extractMaxSize          string
	extractMaxTotal         string
	extractMaxDepth         int
	scanWorkers             int
)

var scanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Scan a target for secrets",
	Long:  "Scan a file, directory, git repository, or remote GitHub/GitLab repository for secrets using detection rules.\nSupports github.com/org/repo and gitlab.com/namespace/project URLs for direct remote scanning.",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules file or directory")
	scanCmd.Flags().StringVar(&scanRulesInclude, "rules-include", "", "Include rules matching regex pattern (comma-separated)")
	scanCmd.Flags().StringVar(&scanRulesExclude, "rules-exclude", "", "Exclude rules matching regex pattern (comma-separated)")
	scanCmd.Flags().StringVar(&scanOutputPath, "output", "titus.ds", "Output datastore path (use :memory: for in-memory only)")
	scanCmd.Flags().StringVar(&scanOutputFormat, "format", "human", "Output format: json, sarif, human")
	scanCmd.Flags().BoolVar(&scanGit, "git", false, "Treat target as git repository (enumerate git history)")
	scanCmd.Flags().Int64Var(&scanMaxFileSize, "max-file-size", 10*1024*1024, "Maximum file size to scan (bytes)")
	scanCmd.Flags().BoolVar(&scanIncludeHidden, "include-hidden", false, "Include hidden files and directories")
	scanCmd.Flags().IntVar(&scanContextLines, "context-lines", 3, "Lines of context before/after matches (0 to disable)")
	scanCmd.Flags().BoolVar(&scanIncremental, "incremental", false, "Skip already-scanned blobs")
	scanCmd.Flags().BoolVar(&scanValidate, "validate", false, "validate detected secrets against their source APIs")
	scanCmd.Flags().IntVar(&scanValidateWorkers, "validate-workers", 4, "number of concurrent validation workers")
	scanCmd.Flags().BoolVar(&scanStoreBlobs, "store-blobs", false, "Store file contents in blobs/ directory")
	scanCmd.Flags().Var(&scanExtractArchivesFlag, "extract", "Extract text from binary files (extensions: xlsx,docx,pdf,zip or 'all')")
	scanCmd.Flags().StringVar(&extractMaxSize, "extract-max-size", "10MB", "Max uncompressed size per extracted file")
	scanCmd.Flags().StringVar(&extractMaxTotal, "extract-max-total", "100MB", "Max total bytes to extract from one archive")
	scanCmd.Flags().IntVar(&extractMaxDepth, "extract-max-depth", 5, "Max nested archive depth")
	scanCmd.Flags().IntVar(&scanWorkers, "workers", runtime.NumCPU(), "Number of parallel scan workers")
}

// blobJob represents a unit of work for the worker pool.
type blobJob struct {
	content []byte
	blobID  types.BlobID
	prov    types.Provenance
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	// Check if target is a GitHub or GitLab URL
	if repoTarget, ok := parseRepoURL(target); ok {
		return runRepoScan(cmd, repoTarget)
	}

	// Validate target exists (filesystem path)
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("target does not exist: %s", target)
	}

	// Load rules
	rules, err := loadRules(scanRulesPath, scanRulesInclude, scanRulesExclude)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	// Create rule map for finding ID computation
	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	// Create matcher
	m, err := matcher.New(matcher.Config{
		Rules:        rules,
		ContextLines: scanContextLines,
	})
	if err != nil {
		return fmt.Errorf("creating matcher: %w", err)
	}
	defer m.Close()

	// Create store (memory or datastore)
	s, ds, err := openScanStore(scanOutputPath, scanStoreBlobs)
	if err != nil {
		return err
	}
	if ds != nil {
		defer ds.Close()
	} else {
		defer s.Close()
	}

	// Store rules for foreign key constraints
	for _, r := range rules {
		if err := s.AddRule(r); err != nil {
			return fmt.Errorf("storing rule: %w", err)
		}
	}

	// Initialize validation engine (nil if validation disabled)
	validationEngine := initValidationEngine()

	// Create enumerator
	enumerator, err := createEnumerator(target, scanGit)
	if err != nil {
		return fmt.Errorf("creating enumerator: %w", err)
	}

	// Scan with parallel workers
	ctx := context.Background()
	var matchCount atomic.Int64
	var findingCount atomic.Int64
	var skippedCount atomic.Int64
	var totalBytes atomic.Int64
	var blobCount atomic.Int64
	startTime := time.Now()

	numWorkers := scanWorkers
	if numWorkers < 1 {
		numWorkers = 1
	}
	jobs := make(chan blobJob, 2*numWorkers)

	g, ctx := errgroup.WithContext(ctx)

	// Producer: enumerate blobs and send to workers (NO DB writes)
	g.Go(func() error {
		defer close(jobs)
		return enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			totalBytes.Add(int64(len(content)))
			blobCount.Add(1)

			// Check for incremental scanning
			if scanIncremental {
				exists, err := s.BlobExists(blobID)
				if err != nil {
					return fmt.Errorf("checking blob: %w", err)
				}
				if exists {
					skippedCount.Add(1)
					return nil
				}
			}

			select {
			case jobs <- blobJob{content: content, blobID: blobID, prov: prov}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	})

	// Consumer workers: match, compute line/col, validate, write to DB in batches
	const batchSize = 64
	for i := 0; i < numWorkers; i++ {
		g.Go(func() error {
			type batchItem struct {
				blobID  types.BlobID
				prov    types.Provenance
				size    int64
				matches []*types.Match
			}
			var batch []batchItem

			flush := func() error {
				if len(batch) == 0 {
					return nil
				}
				err := s.ExecBatch(func(tx store.Store) error {
					for _, item := range batch {
						if err := tx.AddBlob(item.blobID, item.size); err != nil {
							return fmt.Errorf("storing blob: %w", err)
						}
						if err := tx.AddProvenance(item.blobID, item.prov); err != nil {
							return fmt.Errorf("storing provenance: %w", err)
						}
						for _, match := range item.matches {
							if err := tx.AddMatch(match); err != nil {
								return fmt.Errorf("storing match: %w", err)
							}
							rule, ok := ruleMap[match.RuleID]
							if !ok {
								return fmt.Errorf("rule not found: %s", match.RuleID)
							}
							findingID := types.ComputeFindingID(rule.StructuralID, match.Groups)
							exists, err := tx.FindingExists(findingID)
							if err != nil {
								return fmt.Errorf("checking finding: %w", err)
							}
							if !exists {
								findingCount.Add(1)
								if err := tx.AddFinding(&types.Finding{
									ID:     findingID,
									RuleID: match.RuleID,
									Groups: match.Groups,
								}); err != nil {
									return fmt.Errorf("storing finding: %w", err)
								}
							}
						}
					}
					return nil
				})
				batch = batch[:0]
				return err
			}

			for job := range jobs {
				matches, err := m.MatchWithBlobID(job.content, job.blobID)
				if err != nil {
					return fmt.Errorf("matching content: %w", err)
				}

				for _, match := range matches {
					startLine, startCol := types.ComputeLineColumn(job.content, int(match.Location.Offset.Start))
					endLine, endCol := types.ComputeLineColumn(job.content, int(match.Location.Offset.End))
					match.Location.Source.Start.Line = startLine
					match.Location.Source.Start.Column = startCol
					match.Location.Source.End.Line = endLine
					match.Location.Source.End.Column = endCol
				}

				validateMatches(ctx, validationEngine, matches, verbose)
				matchCount.Add(int64(len(matches)))

				batch = append(batch, batchItem{
					blobID:  job.blobID,
					prov:    job.prov,
					size:    int64(len(job.content)),
					matches: matches,
				})
				if len(batch) >= batchSize {
					if err := flush(); err != nil {
						return err
					}
				}
			}
			return flush()
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	duration := time.Since(startTime)
	printScanStats(cmd, scanOutputFormat, scanOutputPath,
		totalBytes.Load(), blobCount.Load(), matchCount.Load(), skippedCount.Load(), duration)

	return outputScanResults(cmd, s, rules, ruleMap)
}

// =============================================================================
// HELPERS
// =============================================================================

func loadRules(path, include, exclude string) ([]*types.Rule, error) {
	loader := rule.NewLoader()

	var rules []*types.Rule
	var err error

	if path != "" {
		// Custom rules from file
		r, err := loader.LoadRuleFile(path)
		if err != nil {
			return nil, err
		}
		rules = []*types.Rule{r}
	} else {
		// Builtin rules
		rules, err = loader.LoadBuiltinRules()
		if err != nil {
			return nil, err
		}
	}

	// Apply filtering if patterns specified
	if include != "" || exclude != "" {
		config := rule.FilterConfig{
			Include: rule.ParsePatterns(include),
			Exclude: rule.ParsePatterns(exclude),
		}
		rules, err = rule.Filter(rules, config)
		if err != nil {
			return nil, fmt.Errorf("filtering rules: %w", err)
		}
	}

	return rules, nil
}

// openScanStore creates the store backend based on the output path configuration.
func openScanStore(outputPath string, storeBlobs bool) (store.Store, *datastore.Datastore, error) {
	if outputPath == ":memory:" {
		s, err := store.New(store.Config{Path: ":memory:"})
		if err != nil {
			return nil, nil, fmt.Errorf("creating store: %w", err)
		}
		return s, nil, nil
	}

	ds, err := datastore.Open(outputPath, datastore.Options{
		StoreBlobs: storeBlobs,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating datastore: %w", err)
	}
	return ds.Store, ds, nil
}

// printScanStats formats and prints scan statistics.
func printScanStats(cmd *cobra.Command, format, outputPath string, totalBytes, blobCount, matchCount, skippedCount int64, duration time.Duration) {
	speed := float64(totalBytes) / duration.Seconds()
	newMatches := matchCount - skippedCount
	statsLine := fmt.Sprintf("Scanned %d B from %d blobs in %d second (%.0f B/s); %d/%d new matches\n",
		totalBytes, blobCount, int(duration.Seconds()), speed, newMatches, matchCount)

	if format == "json" || format == "sarif" {
		fmt.Fprint(cmd.ErrOrStderr(), statsLine)
		if outputPath != ":memory:" {
			fmt.Fprintf(cmd.ErrOrStderr(), "Results stored in: %s/datastore.db\n\n", outputPath)
		}
	} else {
		fmt.Fprint(cmd.OutOrStdout(), statsLine)
		fmt.Fprintf(cmd.OutOrStdout(), "\n")
	}
}

// outputScanResults routes scan output to the appropriate formatter based on scanOutputFormat.
func outputScanResults(cmd *cobra.Command, s store.Store, rules []*types.Rule, ruleMap map[string]*types.Rule) error {
	if scanOutputFormat == "json" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputMatches(cmd, matches)
	}

	if scanOutputFormat == "sarif" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputSARIF(cmd, s, rules, matches)
	}

	// Human format outputs findings in noseyparker table format
	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}

	allMatches, err := s.GetAllMatches()
	if err != nil {
		return fmt.Errorf("retrieving matches: %w", err)
	}

	findingMatches := make(map[string][]*types.Match)
	for _, m := range allMatches {
		rule, ok := ruleMap[m.RuleID]
		if !ok {
			return fmt.Errorf("rule not found: %s", m.RuleID)
		}
		findingID := types.ComputeFindingID(rule.StructuralID, m.Groups)
		findingMatches[findingID] = append(findingMatches[findingID], m)
	}

	for _, f := range findings {
		f.Matches = findingMatches[f.ID]
	}

	return outputNoseyParkerSummary(cmd, findings, ruleMap)
}

// parseSize converts size strings like "10MB" to bytes.
func parseSize(sizeStr string) (int64, error) {
	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))
	
	// Parse multiplier suffix
	multiplier := int64(1)
	if strings.HasSuffix(sizeStr, "KB") {
		multiplier = 1024
		sizeStr = strings.TrimSuffix(sizeStr, "KB")
	} else if strings.HasSuffix(sizeStr, "MB") {
		multiplier = 1024 * 1024
		sizeStr = strings.TrimSuffix(sizeStr, "MB")
	} else if strings.HasSuffix(sizeStr, "GB") {
		multiplier = 1024 * 1024 * 1024
		sizeStr = strings.TrimSuffix(sizeStr, "GB")
	}
	
	// Parse numeric value
	val, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size format: %s", sizeStr)
	}
	
	return val * multiplier, nil
}

func createEnumerator(target string, useGit bool) (enum.Enumerator, error) {
	// Parse extraction limits
	limits := enum.DefaultExtractionLimits()
	
	if extractMaxSize != "" {
		size, err := parseSize(extractMaxSize)
		if err != nil {
			return nil, fmt.Errorf("parsing extract-max-size: %w", err)
		}
		limits.MaxSize = size
	}
	
	if extractMaxTotal != "" {
		size, err := parseSize(extractMaxTotal)
		if err != nil {
			return nil, fmt.Errorf("parsing extract-max-total: %w", err)
		}
		limits.MaxTotal = size
	}
	
	limits.MaxDepth = extractMaxDepth

	config := enum.Config{
		Root:            target,
		IncludeHidden:   scanIncludeHidden,
		MaxFileSize:     scanMaxFileSize,
		FollowSymlinks:  false,
		ExtractArchives: string(scanExtractArchivesFlag),
		ExtractLimits:   limits,
	}

	if useGit {
		gitEnum := enum.NewGitEnumerator(config)
		gitEnum.WalkAll = true
		fsEnum := enum.NewFilesystemEnumerator(config)
		return enum.NewCombinedEnumerator(gitEnum, fsEnum), nil
	}

	return enum.NewFilesystemEnumerator(config), nil
}

// repoTarget holds parsed repository URL information.
type repoTarget struct {
	Platform string // "github" or "gitlab"
	Owner    string // org/user
	Repo     string // repository/project name
	FullPath string // "owner/repo"
}

// parseRepoURL detects if a target string is a GitHub or GitLab repository reference.
// Supports formats:
//   - github.com/owner/repo
//   - https://github.com/owner/repo
//   - https://github.com/owner/repo.git
//   - gitlab.com/namespace/project
//   - https://gitlab.com/namespace/project
func parseRepoURL(target string) (repoTarget, bool) {
	// Strip common URL prefixes
	cleaned := target
	cleaned = strings.TrimPrefix(cleaned, "https://")
	cleaned = strings.TrimPrefix(cleaned, "http://")
	cleaned = strings.TrimSuffix(cleaned, ".git")
	cleaned = strings.TrimSuffix(cleaned, "/")

	parts := strings.SplitN(cleaned, "/", 4) // host/owner/repo[/extra]
	if len(parts) < 3 {
		return repoTarget{}, false
	}

	host := strings.ToLower(parts[0])
	owner := parts[1]
	repo := parts[2]

	var platform string
	switch host {
	case "github.com":
		platform = "github"
	case "gitlab.com":
		platform = "gitlab"
	default:
		return repoTarget{}, false
	}

	return repoTarget{
		Platform: platform,
		Owner:    owner,
		Repo:     repo,
		FullPath: owner + "/" + repo,
	}, true
}

// runRepoScan handles scanning of GitHub/GitLab repositories detected from URL-like targets.
func runRepoScan(cmd *cobra.Command, rt repoTarget) error {
	// Resolve token from environment
	var token string
	switch rt.Platform {
	case "github":
		token = os.Getenv("GITHUB_TOKEN")
	case "gitlab":
		token = os.Getenv("GITLAB_TOKEN")
	}

	if token == "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "Note: No %s token provided. Using unauthenticated access (public repos only).\n\n", rt.Platform)
	}

	// Build clone URL
	var cloneURL string
	switch rt.Platform {
	case "github":
		cloneURL = "https://github.com/" + rt.FullPath + ".git"
	case "gitlab":
		cloneURL = "https://gitlab.com/" + rt.FullPath + ".git"
	}

	repos := []enum.RepoInfo{{
		Name:     rt.FullPath,
		CloneURL: cloneURL,
	}}

	cloneEnum := enum.NewCloneEnumerator(repos, enum.Config{
		MaxFileSize: scanMaxFileSize,
	})
	cloneEnum.Git = scanGit

	// Load rules
	rules, err := loadRules(scanRulesPath, scanRulesInclude, scanRulesExclude)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	// Create matcher
	m, err := matcher.New(matcher.Config{
		Rules:        rules,
		ContextLines: scanContextLines,
	})
	if err != nil {
		return fmt.Errorf("creating matcher: %w", err)
	}
	defer m.Close()

	// Create store
	s, ds, err := openScanStore(scanOutputPath, scanStoreBlobs)
	if err != nil {
		return err
	}
	if ds != nil {
		defer ds.Close()
	} else {
		defer s.Close()
	}

	for _, r := range rules {
		if err := s.AddRule(r); err != nil {
			return fmt.Errorf("storing rule: %w", err)
		}
	}

	validationEngine := initValidationEngine()

	ctx := context.Background()
	var matchCount atomic.Int64
	var findingCount atomic.Int64
	var skippedCount atomic.Int64
	var totalBytes atomic.Int64
	var blobCount atomic.Int64
	startTime := time.Now()

	numWorkers := scanWorkers
	if numWorkers < 1 {
		numWorkers = 1
	}
	jobs := make(chan blobJob, 2*numWorkers)

	g, ctx := errgroup.WithContext(ctx)

	// Producer
	g.Go(func() error {
		defer close(jobs)
		return cloneEnum.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			totalBytes.Add(int64(len(content)))
			blobCount.Add(1)

			if scanIncremental {
				exists, err := s.BlobExists(blobID)
				if err != nil {
					return fmt.Errorf("checking blob: %w", err)
				}
				if exists {
					skippedCount.Add(1)
					return nil
				}
			}

			select {
			case jobs <- blobJob{content: content, blobID: blobID, prov: prov}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	})

	// Consumer workers (same as runScan)
	const batchSize = 64
	for i := 0; i < numWorkers; i++ {
		g.Go(func() error {
			type batchItem struct {
				blobID  types.BlobID
				prov    types.Provenance
				size    int64
				matches []*types.Match
			}
			var batch []batchItem

			flush := func() error {
				if len(batch) == 0 {
					return nil
				}
				err := s.ExecBatch(func(tx store.Store) error {
					for _, item := range batch {
						if err := tx.AddBlob(item.blobID, item.size); err != nil {
							return fmt.Errorf("storing blob: %w", err)
						}
						if err := tx.AddProvenance(item.blobID, item.prov); err != nil {
							return fmt.Errorf("storing provenance: %w", err)
						}
						for _, match := range item.matches {
							if err := tx.AddMatch(match); err != nil {
								return fmt.Errorf("storing match: %w", err)
							}
							rule, ok := ruleMap[match.RuleID]
							if !ok {
								return fmt.Errorf("rule not found: %s", match.RuleID)
							}
							findingID := types.ComputeFindingID(rule.StructuralID, match.Groups)
							exists, err := tx.FindingExists(findingID)
							if err != nil {
								return fmt.Errorf("checking finding: %w", err)
							}
							if !exists {
								findingCount.Add(1)
								if err := tx.AddFinding(&types.Finding{
									ID:     findingID,
									RuleID: match.RuleID,
									Groups: match.Groups,
								}); err != nil {
									return fmt.Errorf("storing finding: %w", err)
								}
							}
						}
					}
					return nil
				})
				batch = batch[:0]
				return err
			}

			for job := range jobs {
				matches, err := m.MatchWithBlobID(job.content, job.blobID)
				if err != nil {
					return fmt.Errorf("matching content: %w", err)
				}

				for _, match := range matches {
					startLine, startCol := types.ComputeLineColumn(job.content, int(match.Location.Offset.Start))
					endLine, endCol := types.ComputeLineColumn(job.content, int(match.Location.Offset.End))
					match.Location.Source.Start.Line = startLine
					match.Location.Source.Start.Column = startCol
					match.Location.Source.End.Line = endLine
					match.Location.Source.End.Column = endCol
				}

				validateMatches(ctx, validationEngine, matches, verbose)
				matchCount.Add(int64(len(matches)))

				batch = append(batch, batchItem{
					blobID:  job.blobID,
					prov:    job.prov,
					size:    int64(len(job.content)),
					matches: matches,
				})
				if len(batch) >= batchSize {
					if err := flush(); err != nil {
						return err
					}
				}
			}
			return flush()
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	duration := time.Since(startTime)
	printScanStats(cmd, scanOutputFormat, scanOutputPath,
		totalBytes.Load(), blobCount.Load(), matchCount.Load(), skippedCount.Load(), duration)

	return outputScanResults(cmd, s, rules, ruleMap)
}

// outputNoseyParkerSummary outputs findings in noseyparker table format
func outputNoseyParkerSummary(cmd *cobra.Command, findings []*types.Finding, ruleMap map[string]*types.Rule) error {
	if len(findings) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No findings.\n")
		return nil
	}

	// Build aggregation by rule
	type ruleStats struct {
		name     string
		findings int
		matches  int
	}
	statsMap := make(map[string]*ruleStats)

	for _, f := range findings {
		rule, ok := ruleMap[f.RuleID]
		if !ok {
			continue
		}

		if _, exists := statsMap[f.RuleID]; !exists {
			statsMap[f.RuleID] = &ruleStats{name: rule.Name}
		}

		statsMap[f.RuleID].findings++
		statsMap[f.RuleID].matches += len(f.Matches)
	}

	// Find longest rule name for column width
	maxNameLen := len("Rule")
	for _, stats := range statsMap {
		if len(stats.name) > maxNameLen {
			maxNameLen = len(stats.name)
		}
	}

	// Print header
	fmt.Fprintf(cmd.OutOrStdout(), " %-*s   Findings   Matches \n", maxNameLen, "Rule")

	// Print separator line using box-drawing character
	separatorLen := maxNameLen + 3 + 10 + 3 + 8
	fmt.Fprintf(cmd.OutOrStdout(), "%s\n", strings.Repeat("─", separatorLen))

	// Print data rows
	for _, stats := range statsMap {
		fmt.Fprintf(cmd.OutOrStdout(), " %-*s   %8d   %7d \n",
			maxNameLen, stats.name, stats.findings, stats.matches)
	}

	// Print footer
	fmt.Fprintf(cmd.OutOrStdout(), "\nRun the `report` command next to show finding details.\n")

	return nil
}

func outputMatches(cmd *cobra.Command, matches []*types.Match) error {
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(matches)
}

func outputFindings(cmd *cobra.Command, findings []*types.Finding) error {
	switch scanOutputFormat {
	case "json":
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(findings)
	case "human":
		if len(findings) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "\nNo findings.\n")
			return nil
		}

		fmt.Fprintf(cmd.OutOrStdout(), "\nFindings:\n")
		for i, f := range findings {
			fmt.Fprintf(cmd.OutOrStdout(), "%d. Rule: %s", i+1, f.RuleID)

			// Show validation status if available
			if len(f.Matches) > 0 && f.Matches[0].ValidationResult != nil {
				vr := f.Matches[0].ValidationResult
				fmt.Fprintf(cmd.OutOrStdout(), " [%s]", vr.Status)
			}
			fmt.Fprintln(cmd.OutOrStdout())
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", scanOutputFormat)
	}
}

// outputSARIF outputs matches in SARIF 2.1.0 format
func outputSARIF(cmd *cobra.Command, s store.Store, rules []*types.Rule, matches []*types.Match) error {
	// Create SARIF report
	report := sarif.NewReport()

	// Add all rules
	for _, rule := range rules {
		report.AddRule(rule)
	}

	// Cache provenance by blob ID to avoid repeated queries
	provenanceCache := make(map[types.BlobID]string)

	// Get provenance for each match and add results
	for _, match := range matches {
		// Check cache first
		filePath, ok := provenanceCache[match.BlobID]
		if !ok {
			// Query provenance
			prov, err := s.GetProvenance(match.BlobID)
			if err != nil {
				// If no provenance found, use blob ID as fallback
				filePath = match.BlobID.Hex()
			} else {
				filePath = prov.Path()
			}
			provenanceCache[match.BlobID] = filePath
		}

		report.AddResult(match, filePath)
	}

	// Serialize to JSON
	jsonBytes, err := report.ToJSON()
	if err != nil {
		return fmt.Errorf("serializing SARIF: %w", err)
	}

	// Write to stdout
	_, err = cmd.OutOrStdout().Write(jsonBytes)
	if err != nil {
		return fmt.Errorf("writing SARIF output: %w", err)
	}

	return nil
}

// initValidationEngine creates the validation engine if validation is enabled.
func initValidationEngine() *validator.Engine {
	if !scanValidate {
		return nil
	}

	var validators []validator.Validator

	// Add Go validators (complex multi-credential validation)
	validators = append(validators, validator.NewAWSValidator())
	validators = append(validators, validator.NewSauceLabsValidator())
	validators = append(validators, validator.NewTwilioValidator())
	validators = append(validators, validator.NewAzureStorageValidator())
	validators = append(validators, validator.NewPostgresValidator())

	// Add embedded YAML validators
	embedded, err := validator.LoadEmbeddedValidators()
	if err != nil {
		// Log warning but continue
		fmt.Fprintf(os.Stderr, "warning: failed to load embedded validators: %v\n", err)
	} else {
		validators = append(validators, embedded...)
	}

	return validator.NewEngine(scanValidateWorkers, validators...)
}

// validateMatches validates matches using the validation engine.
func validateMatches(ctx context.Context, engine *validator.Engine, matches []*types.Match, verbose bool) {
	if engine == nil || len(matches) == 0 {
		return
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[validate] Starting validation for %d matches\n", len(matches))
	}

	// Submit all matches for async validation
	results := make([]<-chan *types.ValidationResult, len(matches))
	for i := range matches {
		if verbose {
			fmt.Fprintf(os.Stderr, "[validate] Queueing match %d: rule=%s\n", i+1, matches[i].RuleID)
		}
		results[i] = engine.ValidateAsync(ctx, matches[i])
	}

	// Wait for all validations and attach results
	for i, ch := range results {
		result := <-ch
		matches[i].ValidationResult = result
		if verbose {
			fmt.Fprintf(os.Stderr, "[validate] Result %d: rule=%s status=%s confidence=%.1f message=%s\n",
				i+1, matches[i].RuleID, result.Status, result.Confidence, result.Message)
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[validate] Validation complete\n")
	}
}
