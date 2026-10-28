package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/praetorian-inc/titus/pkg/datastore"
	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/scoring"
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
	scanDocker              bool
	scanAMI                 bool
	scanRegion              string
	scanMaxFileSize         int64
	scanContextLines        int
	scanIncremental         bool
	scanValidate            bool
	scanValidateWorkers     int
	scanStoreBlobs          bool
	scanExtractArchivesFlag extensionsValue
	extractMaxSize          string
	extractMaxTotal         string
	scanAccessibility       string // "public" | "private" | "auto"
	extractMaxDepth         int
	scanSQLiteRowLimit      int
	scanWorkers             int
	scanReaders             int
	scanRuleset             string
	scanIgnoreFile          string
	scanIncludeNoisy        bool

	// Dynamic scoring flags (M3).
	scanScopeEnabled bool
	scanScoreTimeout time.Duration
	scanScoreBudget  time.Duration

	// Asana scan flags.
	scanAsanaIncludeAttachments bool
	scanAsanaAttachmentMaxSize  int64
	scanAsanaRateLimit          float64
	scanAsanaConcurrency        int

	// Google Drive flags.
	scanGDriveRateLimit   float64
	scanGDriveConcurrency int
)

var scanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Scan a target for secrets",
	Long:  "Scan a file, directory, git repository, Docker image, Amazon Machine Image, or remote GitHub/GitLab repository for secrets using detection rules.\nSupports github.com/org/repo and gitlab.com/namespace/project URLs for direct remote scanning.\nUse --docker for container image references or prefix the target with docker://.\nUse --ami for an AMI ID or a raw disk image, or prefix an AMI ID with ami://.",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules file or directory")
	scanCmd.Flags().StringVar(&scanRulesInclude, "rules-include", "", "Include rules matching regex pattern (comma-separated)")
	scanCmd.Flags().StringVar(&scanRulesExclude, "rules-exclude", "", "Exclude rules matching regex pattern (comma-separated)")
	scanCmd.Flags().StringVar(&scanRuleset, "ruleset", "default", "Ruleset to use: default, np.assets, np.hashes, all (all = no filtering)")
	scanCmd.Flags().StringVar(&scanOutputPath, "output", "titus.ds", "Output datastore path (:memory: for in-memory, :auto: to derive from target name)")
	scanCmd.Flags().StringVar(&scanOutputFormat, "format", "human", "Output format: json, sarif, human")
	scanCmd.Flags().BoolVar(&scanGit, "git", false, "Treat target as git repository (enumerate git history)")
	scanCmd.Flags().BoolVar(&scanDocker, "docker", false, "Treat target as Docker image (uses docker image save)")
	scanCmd.Flags().BoolVar(&scanAMI, "ami", false, "Treat target as an Amazon Machine Image (AMI ID or raw disk image)")
	scanCmd.Flags().StringVar(&scanRegion, "region", "", "AWS region for AMI scans (ami://region/ami-id overrides this; otherwise the SDK default)")
	scanCmd.Flags().Int64Var(&scanMaxFileSize, "max-file-size", 10*1024*1024, "Maximum file size to scan (bytes)")
	scanCmd.Flags().IntVar(&scanContextLines, "context-lines", 3, "Lines of context before/after matches (0 to disable)")
	scanCmd.Flags().BoolVar(&scanIncremental, "incremental", false, "Skip already-scanned blobs")
	scanCmd.Flags().BoolVar(&scanValidate, "validate", false, "validate detected secrets against their source APIs")
	scanCmd.Flags().IntVar(&scanValidateWorkers, "validate-workers", 4, "number of concurrent validation workers")
	scanCmd.Flags().BoolVar(&scanStoreBlobs, "store-blobs", false, "Store file contents in blobs/ directory")
	scanCmd.Flags().Var(&scanExtractArchivesFlag, "extract", "Extract text from binary files (extensions: xlsx,docx,pdf,zip or 'all')")
	scanCmd.Flags().StringVar(&extractMaxSize, "extract-max-size", "10MB", "Max uncompressed size per extracted file")
	scanCmd.Flags().StringVar(&extractMaxTotal, "extract-max-total", "100MB", "Max total bytes to extract from one archive")
	scanCmd.Flags().IntVar(&extractMaxDepth, "extract-max-depth", 5, "Max nested archive depth")
	scanCmd.Flags().IntVar(&scanSQLiteRowLimit, "sqlite-row-limit", 1000, "Max rows per table for SQLite extraction (0 for unlimited)")
	scanCmd.Flags().IntVar(&scanWorkers, "workers", runtime.NumCPU(), "Number of parallel scan workers")
	// The runtime default is one worker per CPU, but the *documented* default must be
	// machine-independent or the CLI-surface golden drifts with the generating host.
	scanCmd.Flags().Lookup("workers").DefValue = "NumCPU"
	scanCmd.Flags().IntVar(&scanReaders, "readers", 0, "Number of parallel file readers (0 = NumCPU)")
	scanCmd.Flags().StringVar(&scanIgnoreFile, "ignore", "", "Path to gitignore-style ignore file (replaces built-in defaults; use /dev/null to disable)")
	scanCmd.Flags().BoolVar(&scanIncludeNoisy, "include-noisy", false, "Enable rules marked noisy: true (off by default; high false-positive rate)")
	scanCmd.Flags().StringVar(&scanAccessibility, "accessibility", "auto",
		`code accessibility: "public" (no penalty), "private" (-25 to all scores),`+"\n"+
			`or "auto" (detect via git remote/GitHub API, defaults to private if undetermined)`)
	scanCmd.Flags().BoolVar(&scanScopeEnabled, "score-scope", false,
		"enable HTTP dynamic scoring modifiers (calls external APIs to determine secret scope/permissions)")
	scanCmd.Flags().DurationVar(&scanScoreTimeout, "score-timeout", 10*time.Second,
		"per-modifier HTTP timeout for dynamic scoring (default 10s)")
	scanCmd.Flags().DurationVar(&scanScoreBudget, "score-budget", 60*time.Second,
		"per-finding overall scoring budget across all modifiers (default 60s; 0 = unlimited)")

	scanCmd.Flags().BoolVar(&scanAsanaIncludeAttachments, "asana-include-attachments", false, "Download and scan Asana-hosted file attachments")
	scanCmd.Flags().Int64Var(&scanAsanaAttachmentMaxSize, "asana-attachment-max-size", 50*1024*1024, "Maximum Asana attachment size in bytes to download")
	scanCmd.Flags().Float64Var(&scanAsanaRateLimit, "asana-rate-limit", 10.0, "Asana API requests per second (free tier ≈ 2.5/sec; paid tier ≈ 25/sec)")
	scanCmd.Flags().IntVar(&scanAsanaConcurrency, "asana-concurrency", 0, "Number of workers processing tasks within a project (0 = use default of 5)")
	scanCmd.Flags().Float64Var(&scanGDriveRateLimit, "gdrive-rate-limit", 0,
		"Google Drive API requests per second (default 16; 0 = use default). Per-user cap is ~325k quota units/min")
	scanCmd.Flags().IntVar(&scanGDriveConcurrency, "gdrive-concurrency", 0,
		"Google Drive parallel file workers (default 5; 0 = use default; clamped to [1, 100])")
}

// blobJob represents a unit of work for the worker pool.
type blobJob struct {
	content []byte
	blobID  types.BlobID
	prov    types.Provenance
	// known marks a blob an earlier --incremental scan already matched: it is
	// not matched again, only its location is recorded.
	known bool
}

// incrementalJob decides what --incremental does with job. A blob not yet in
// the store is scanned as usual. A stored blob is known when it has matches,
// or when this scan queued it in m for a timed-out rule retry: its matches
// are still pending and drainTimedOutMatches adds them after the parallel
// pass. A known blob is sent so the worker records this location (a new path
// or commit) without matching the content again. Any other stored blob is
// skipped, as it has nothing to report. skipped reports a stored blob, whose
// content is not matched again either way.
func incrementalJob(s store.Store, m matcher.Matcher, job *blobJob) (send, skipped bool, err error) {
	exists, err := s.BlobExists(job.blobID)
	if err != nil {
		return false, false, fmt.Errorf("checking blob: %w", err)
	}
	if !exists {
		return true, false, nil
	}
	job.known, err = s.HasMatches(job.blobID)
	if err != nil {
		return false, false, fmt.Errorf("checking matches of blob: %w", err)
	}
	job.known = job.known || matcher.HasPendingRetry(m, job.blobID)
	return job.known, true, nil
}

// matchJob matches the content of job. A known blob already has its matches
// in the store, so it returns none.
func matchJob(m matcher.Matcher, job blobJob) ([]*types.Match, error) {
	if job.known {
		return nil, nil
	}
	return m.MatchWithBlobID(job.content, job.blobID)
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]
	dockerImage, amiTarget, isDockerTarget, isAMITarget, err := resolveSpecialTarget(target, scanDocker, scanAMI)
	if err != nil {
		return err
	}

	if scanOutputPath == ":auto:" {
		switch {
		case isDockerTarget:
			scanOutputPath = dockerAutoOutputName(dockerImage)
		case isAMITarget:
			scanOutputPath = amiAutoOutputName(amiTarget)
		default:
			scanOutputPath = resolveAutoOutput(target)
		}
	}

	if !isDockerTarget && !isAMITarget {
		// Check if target is a GitHub or GitLab URL
		if repoTarget, ok := parseRepoURL(target); ok {
			return runRepoScan(cmd, repoTarget)
		}

		// Check if target is an S3 URL
		if bucket, prefix, ok := enum.ParseS3URL(target); ok {
			return runS3Scan(cmd, bucket, prefix)
		}

		// Check if target is an Asana URL
		if scope, gid, ok := enum.ParseAsanaURL(target); ok {
			return runAsanaScan(cmd, scope, gid)
		}

		// Check if target is a Google Drive URL
		if scope, driveID, ok := enum.ParseGDriveURL(target); ok {
			return runGDriveScan(cmd, scope, driveID)
		}

		// Validate target exists (filesystem path)
		if _, err := os.Stat(target); err != nil {
			return fmt.Errorf("target does not exist: %s", target)
		}
	}

	// Load rules
	rules, err := loadRules(scanRulesPath, scanRulesInclude, scanRulesExclude, scanRuleset, scanIncludeNoisy)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	// Create rule map for finding ID computation
	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	// Create matcher
	m, err := newMatcher(matcher.Config{
		Rules:        rules,
		ContextLines: scanContextLines,
		WarnFunc: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
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

	// Wire validator awareness into the matcher's built-in deduplicator
	if validationEngine != nil {
		matcher.SetCanValidate(m, validationEngine.CanValidate)
	}

	// Build the scoring engine once per scan.
	engine, err := buildScoringEngine()
	if err != nil {
		return fmt.Errorf("initializing scoring engine: %w", err)
	}
	if scanScopeEnabled && !scanValidate {
		fmt.Fprintf(os.Stderr, "[warn] --score-scope set without --validate; dynamic modifiers will use unvalidated credentials (results may be less accurate)\n")
	}

	// Resolve code accessibility for score adjustment.
	// Use GITHUB_TOKEN env var for auto-detection; the user can also pass --accessibility directly.
	ghToken := os.Getenv("GITHUB_TOKEN")
	accessibility := ResolveAccessibility(scanAccessibility, target, ghToken)

	// Create enumerator
	var enumerator enum.Enumerator
	if isDockerTarget {
		enumerator, err = createDockerEnumerator(dockerImage)
	} else if isAMITarget {
		enumerator, err = createAMIEnumerator(amiTarget)
	} else {
		enumerator, err = createEnumerator(target, scanGit)
	}
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

	if verbose {
		fmt.Fprintf(os.Stderr, "[scan] Starting scan with %d workers and %d rules\n", numWorkers, len(rules))
	}

	jobs := make(chan blobJob, 2*numWorkers)

	g, ctx := errgroup.WithContext(ctx)

	// Producer: enumerate blobs and send to workers (NO DB writes)
	g.Go(func() error {
		defer close(jobs)
		if verbose {
			fmt.Fprintf(os.Stderr, "[enumerate] Starting enumeration of %s\n", target)
		}
		return enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			totalBytes.Add(int64(len(content)))
			count := blobCount.Add(1)
			if verbose && count%1000 == 0 {
				fmt.Fprintf(os.Stderr, "[enumerate] %d files discovered (%d bytes)\n", count, totalBytes.Load())
			}

			// Check for incremental scanning
			job := blobJob{content: content, blobID: blobID, prov: prov}
			if scanIncremental {
				send, skipped, err := incrementalJob(s, m, &job)
				if err != nil {
					return err
				}
				if skipped {
					skippedCount.Add(1)
				}
				if !send {
					return nil
				}
			}

			select {
			case jobs <- job:
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
				// locate is true when the blob's locations must be stored: it
				// matched, or a timed-out rule queued it for DrainTimedOut.
				locate bool
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
						if err := storeLocations(tx, item.blobID, item.prov, item.locate); err != nil {
							return err
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
								f := &types.Finding{
									ID:     findingID,
									RuleID: match.RuleID,
									Groups: match.Groups,
								}
								f.Score = engine.Score(ctx, f, []*types.Match{match}, rule)
								if accessibility == AccessibilityPrivate {
									ApplyAccessibilityModifier(f.Score)
								}
								if err := tx.AddFinding(f); err != nil {
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
				matches, err := matchJob(m, job)
				if err != nil {
					// Log warning but continue scanning other files
					fmt.Fprintf(os.Stderr, "[warn] match error (skipping blob %s): %v\n", job.blobID.Hex(), err)
					continue
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
					locate:  job.known || len(matches) > 0 || matcher.HasPendingRetry(m, job.blobID),
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
		if ctx.Err() != nil && errors.Is(err, context.Canceled) {
			// Normal shutdown, not an error
		} else {
			return fmt.Errorf("scanning: %w", err)
		}
	}

	// Retry any blobs that timed out during the parallel pass.
	// This runs single-threaded so there is no CPU contention, resolving
	// starvation-caused false timeouts while still catching real backtracking.
	if err := drainTimedOutMatches(ctx, m, s, ruleMap, engine, &findingCount, &matchCount, accessibility); err != nil {
		return fmt.Errorf("retrying timed-out blobs: %w", err)
	}

	// Emit aggregate dynamic modifier stats if any errors occurred.
	if s := engine.Stats(); s.Any() {
		fmt.Fprintf(os.Stderr, "[scoring] Dynamic modifiers: %d timeouts, %d rate-limited, %d server errors, %d network errors\n",
			s.Timeouts, s.RateLimited, s.ServerErrors, s.NetworkErrors)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[scan] Scan complete: %d blobs, %d matches, %d findings\n", blobCount.Load(), matchCount.Load(), findingCount.Load())
	}

	duration := time.Since(startTime)
	printScanStats(cmd, scanOutputFormat, scanOutputPath,
		totalBytes.Load(), blobCount.Load(), matchCount.Load(), skippedCount.Load(), duration)

	return outputScanResults(cmd, s, rules, ruleMap)
}

// drainTimedOutMatches replays blobs that timed out during the parallel scan
// pass using the matcher's single-threaded retry queue, then writes the
// resulting matches and findings to the store. It is called after g.Wait() in
// each of the scan entry points (runScan, runRepoScan, runS3Scan).
// The resolvedAccess parameter ensures that retried findings receive the same
// accessibility penalty as findings scored on the normal path.
func drainTimedOutMatches(ctx context.Context, m matcher.Matcher, s store.Store, ruleMap map[string]*types.Rule, engine scoringEngineInterface, findingCount, matchCount *atomic.Int64, resolvedAccess Accessibility) error {
	retryMatches, err := m.DrainTimedOut()
	if err != nil {
		return fmt.Errorf("drain timed-out blobs: %w", err)
	}
	if len(retryMatches) == 0 {
		return nil
	}
	return s.ExecBatch(func(tx store.Store) error {
		for _, match := range retryMatches {
			if err := tx.AddMatch(match); err != nil {
				return fmt.Errorf("storing retry match: %w", err)
			}
			rule, ok := ruleMap[match.RuleID]
			if !ok {
				return fmt.Errorf("rule not found: %s", match.RuleID)
			}
			findingID := types.ComputeFindingID(rule.StructuralID, match.Groups)
			exists, err := tx.FindingExists(findingID)
			if err != nil {
				return fmt.Errorf("checking retry finding: %w", err)
			}
			if !exists {
				findingCount.Add(1)
				matchCount.Add(1)
				f := &types.Finding{
					ID:     findingID,
					RuleID: match.RuleID,
					Groups: match.Groups,
				}
				f.Score = engine.Score(ctx, f, []*types.Match{match}, rule)
				if resolvedAccess == AccessibilityPrivate {
					ApplyAccessibilityModifier(f.Score)
				}
				if err := tx.AddFinding(f); err != nil {
					return fmt.Errorf("storing retry finding: %w", err)
				}
			}
		}
		return nil
	})
}

// =============================================================================
// HELPERS
// =============================================================================

func loadRules(path, include, exclude, rulesetID string, includeNoisy bool) ([]*types.Rule, error) {
	loader := rule.NewLoader()

	var rules []*types.Rule
	var err error

	if path != "" {
		// Custom rules merged with builtins
		builtins, err := loader.LoadBuiltinRules()
		if err != nil {
			return nil, err
		}
		custom, err := loadCustomRulesPath(loader, path)
		if err != nil {
			return nil, err
		}
		rules = append(builtins, custom...)
	} else {
		// Builtin rules
		rules, err = loader.LoadBuiltinRules()
		if err != nil {
			return nil, err
		}

		// Apply ruleset filtering (skip if "all")
		if rulesetID != "all" {
			rulesets, err := loader.LoadBuiltinRulesets()
			if err != nil {
				return nil, fmt.Errorf("loading rulesets: %w", err)
			}
			rs := rule.FindRuleset(rulesets, rulesetID)
			if rs == nil {
				available := make([]string, len(rulesets))
				for i, r := range rulesets {
					available[i] = r.ID
				}
				return nil, fmt.Errorf("unknown ruleset %q (available: %s, all)", rulesetID, strings.Join(available, ", "))
			}
			rules = rule.ApplyRuleset(rules, rs)
		}
	}

	// Drop noisy rules unless the user opted in.
	rules = rule.FilterNoisy(rules, includeNoisy)

	// Apply regex filtering if patterns specified
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

// loadCustomRulesPath loads rules from a file or directory.
// If path is a file, it is parsed as a (possibly multi-rule) YAML file.
// If path is a directory, it is walked recursively for .yml/.yaml files
// (case-insensitive) and all rules from all files are returned.
func loadCustomRulesPath(loader *rule.Loader, path string) ([]*types.Rule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	var files []string
	if info.IsDir() {
		walkErr := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext == ".yml" || ext == ".yaml" {
				files = append(files, p)
			}
			return nil
		})
		if walkErr != nil {
			return nil, fmt.Errorf("walking %s: %w", path, walkErr)
		}
	} else {
		files = []string{path}
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no .yml or .yaml files found in %s", path)
	}

	var allRules []*types.Rule
	for _, f := range files {
		fileRules, err := loader.LoadRulesFromFileMulti(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		allRules = append(allRules, fileRules...)
	}
	return allRules, nil
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

// scanStatsLine is the scan statistics line. matchCount counts the matches
// this scan found, all of them new: an incremental scan does not match a
// stored blob again. skippedCount is those stored blobs, a count of blobs,
// not of matches, so it is reported on its own.
func scanStatsLine(totalBytes, blobCount, matchCount, skippedCount int64, duration time.Duration) string {
	speed := float64(totalBytes) / duration.Seconds()
	line := fmt.Sprintf("Scanned %d B from %d blobs in %d second (%.0f B/s); %d new matches",
		totalBytes, blobCount, int(duration.Seconds()), speed, matchCount)
	if skippedCount > 0 {
		line += fmt.Sprintf("; %d blobs already scanned, not matched again", skippedCount)
	}
	return line + "\n"
}

// printScanStats formats and prints scan statistics.
func printScanStats(cmd *cobra.Command, format, outputPath string, totalBytes, blobCount, matchCount, skippedCount int64, duration time.Duration) {
	statsLine := scanStatsLine(totalBytes, blobCount, matchCount, skippedCount, duration)

	if format == "json" || format == "sarif" {
		_, _ = fmt.Fprint(cmd.ErrOrStderr(), statsLine)
		if outputPath != ":memory:" {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Results stored in: %s/datastore.db\n\n", outputPath)
		}
	} else {
		_, _ = fmt.Fprint(cmd.OutOrStdout(), statsLine)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n")
	}
}

// outputScanResults routes scan output to the appropriate formatter based on scanOutputFormat.
func outputScanResults(cmd *cobra.Command, s store.Store, rules []*types.Rule, ruleMap map[string]*types.Rule) error {
	if scanOutputFormat == "json" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputMatches(cmd, s, matches)
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

func enumConfigForTarget(target string) (enum.Config, error) {
	// Parse extraction limits
	limits := enum.DefaultExtractionLimits()

	if extractMaxSize != "" {
		size, err := parseSize(extractMaxSize)
		if err != nil {
			return enum.Config{}, fmt.Errorf("parsing extract-max-size: %w", err)
		}
		limits.MaxSize = size
	}

	if extractMaxTotal != "" {
		size, err := parseSize(extractMaxTotal)
		if err != nil {
			return enum.Config{}, fmt.Errorf("parsing extract-max-total: %w", err)
		}
		limits.MaxTotal = size
	}

	limits.MaxDepth = extractMaxDepth
	limits.SQLiteRowLimit = scanSQLiteRowLimit

	return enum.Config{
		Root:            target,
		MaxFileSize:     scanMaxFileSize,
		FollowSymlinks:  false,
		ExtractArchives: string(scanExtractArchivesFlag),
		ExtractLimits:   limits,
		IgnoreFile:      scanIgnoreFile,
		NumReaders:      scanReaders,
	}, nil
}

func createEnumerator(target string, useGit bool) (enum.Enumerator, error) {
	config, err := enumConfigForTarget(target)
	if err != nil {
		return nil, err
	}

	if useGit {
		gitEnum := enum.NewGitEnumerator(config)
		gitEnum.WalkAll = true
		fsEnum := enum.NewFilesystemEnumerator(config)
		return enum.NewCombinedEnumerator(gitEnum, fsEnum), nil
	}

	return enum.NewFilesystemEnumerator(config), nil
}

func createDockerEnumerator(image string) (enum.Enumerator, error) {
	config, err := enumConfigForTarget(image)
	if err != nil {
		return nil, err
	}
	return enum.NewDockerImageEnumerator(image, config), nil
}

func createAMIEnumerator(target enum.AMITarget) (enum.Enumerator, error) {
	root := target.ImageID
	if target.Path != "" {
		root = target.Path
	}
	config, err := enumConfigForTarget(root)
	if err != nil {
		return nil, err
	}
	return enum.NewAMIEnumerator(target, scanRegion, config), nil
}

// resolveSpecialTarget classifies Docker and AMI scan targets. Other targets
// (filesystem, git, s3://, repo URLs) return false, false.
func resolveSpecialTarget(target string, dockerFlag, amiFlag bool) (dockerImage string, ami enum.AMITarget, isDocker, isAMI bool, err error) {
	target = strings.TrimSpace(target)
	if dockerFlag && amiFlag {
		return "", enum.AMITarget{}, false, false, fmt.Errorf("--docker and --ami cannot be combined")
	}
	if image, ok := enum.ParseDockerImageReference(target); ok {
		if amiFlag {
			return "", enum.AMITarget{}, false, false, fmt.Errorf("target %s is a Docker image, not an AMI", target)
		}
		return image, enum.AMITarget{}, true, false, nil
	}
	if strings.HasPrefix(strings.ToLower(target), "ami://") {
		if dockerFlag {
			return "", enum.AMITarget{}, false, false, fmt.Errorf("target %s is an AMI, not a Docker image", target)
		}
		parsed, ok := enum.ParseAMIReference(target)
		if !ok {
			return "", enum.AMITarget{}, false, false, fmt.Errorf("invalid AMI reference %q (want ami://ami-id or ami://region/ami-id)", target)
		}
		return "", parsed, false, true, nil
	}
	if dockerFlag {
		return target, enum.AMITarget{}, true, false, nil
	}
	if amiFlag {
		parsed, err := enum.AMITargetFromFlag(target)
		if err != nil {
			return "", enum.AMITarget{}, false, false, err
		}
		return "", parsed, false, true, nil
	}
	return "", enum.AMITarget{}, false, false, nil
}

func amiAutoOutputName(target enum.AMITarget) string {
	if target.ImageID != "" {
		name := target.ImageID
		if target.Region != "" {
			name = target.Region + "_" + name
		}
		return name + ".ds"
	}
	base := filepath.Base(target.Path)
	if base == "." || base == "" || base == string(filepath.Separator) {
		return "ami.ds"
	}
	return base + ".ds"
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
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Note: No %s token provided. Using unauthenticated access (public repos only).\n\n", rt.Platform)
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
		IgnoreFile:  scanIgnoreFile,
	})
	cloneEnum.Git = scanGit
	cloneEnum.Token = token

	// Load rules
	rules, err := loadRules(scanRulesPath, scanRulesInclude, scanRulesExclude, scanRuleset, scanIncludeNoisy)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	// Create matcher
	m, err := newMatcher(matcher.Config{
		Rules:        rules,
		ContextLines: scanContextLines,
		WarnFunc: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
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

	// Wire validator awareness into the matcher's built-in deduplicator
	if validationEngine != nil {
		matcher.SetCanValidate(m, validationEngine.CanValidate)
	}

	// Build the scoring engine before workers start so the main worker pass
	// can score findings (not just the drain-path retries).
	repoEngine, err := buildScoringEngine()
	if err != nil {
		return fmt.Errorf("initializing scoring engine: %w", err)
	}

	// Resolve accessibility for score penalty (same logic as runScan).
	ghToken := os.Getenv("GITHUB_TOKEN")
	if rt.Platform == "gitlab" {
		ghToken = os.Getenv("GITLAB_TOKEN")
	}
	repoAccessibility := ResolveAccessibility(scanAccessibility, rt.FullPath, ghToken)

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

			job := blobJob{content: content, blobID: blobID, prov: prov}
			if scanIncremental {
				send, skipped, err := incrementalJob(s, m, &job)
				if err != nil {
					return err
				}
				if skipped {
					skippedCount.Add(1)
				}
				if !send {
					return nil
				}
			}

			select {
			case jobs <- job:
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
				// locate is true when the blob's locations must be stored: it
				// matched, or a timed-out rule queued it for DrainTimedOut.
				locate bool
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
						if err := storeLocations(tx, item.blobID, item.prov, item.locate); err != nil {
							return err
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
								f := &types.Finding{
									ID:     findingID,
									RuleID: match.RuleID,
									Groups: match.Groups,
								}
								f.Score = repoEngine.Score(ctx, f, []*types.Match{match}, rule)
								if repoAccessibility == AccessibilityPrivate {
									ApplyAccessibilityModifier(f.Score)
								}
								if err := tx.AddFinding(f); err != nil {
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
				matches, err := matchJob(m, job)
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
					locate:  job.known || len(matches) > 0 || matcher.HasPendingRetry(m, job.blobID),
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
		if ctx.Err() != nil && errors.Is(err, context.Canceled) {
			// Normal shutdown via Ctrl+C, not an error
		} else {
			return fmt.Errorf("scanning: %w", err)
		}
	}

	if err := drainTimedOutMatches(ctx, m, s, ruleMap, repoEngine, &findingCount, &matchCount, repoAccessibility); err != nil {
		return fmt.Errorf("retrying timed-out blobs: %w", err)
	}

	duration := time.Since(startTime)
	printScanStats(cmd, scanOutputFormat, scanOutputPath,
		totalBytes.Load(), blobCount.Load(), matchCount.Load(), skippedCount.Load(), duration)

	return outputScanResults(cmd, s, rules, ruleMap)
}

// runS3Scan handles scanning of S3 buckets detected from s3:// URLs.
func runS3Scan(cmd *cobra.Command, bucket, prefix string) error {
	// Load rules
	rules, err := loadRules(scanRulesPath, scanRulesInclude, scanRulesExclude, scanRuleset, scanIncludeNoisy)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	// Create matcher
	m, err := newMatcher(matcher.Config{
		Rules:        rules,
		ContextLines: scanContextLines,
		WarnFunc: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
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

	// Store rules for foreign key constraints
	for _, r := range rules {
		if err := s.AddRule(r); err != nil {
			return fmt.Errorf("storing rule: %w", err)
		}
	}

	validationEngine := initValidationEngine()
	if validationEngine != nil {
		matcher.SetCanValidate(m, validationEngine.CanValidate)
	}

	// Build the scoring engine before workers start so the main worker pass
	// can score findings (not just the drain-path retries).
	s3Engine, err := buildScoringEngine()
	if err != nil {
		return fmt.Errorf("initializing scoring engine: %w", err)
	}

	// S3 objects have no git remote; resolve accessibility from the flag only
	// (auto falls back to private, which is the conservative default).
	s3Accessibility := ResolveAccessibility(scanAccessibility, "", "")

	// Parse extraction limits
	limits := enum.DefaultExtractionLimits()
	if extractMaxSize != "" {
		size, err := parseSize(extractMaxSize)
		if err != nil {
			return fmt.Errorf("parsing extract-max-size: %w", err)
		}
		limits.MaxSize = size
	}
	if extractMaxTotal != "" {
		size, err := parseSize(extractMaxTotal)
		if err != nil {
			return fmt.Errorf("parsing extract-max-total: %w", err)
		}
		limits.MaxTotal = size
	}
	limits.MaxDepth = extractMaxDepth
	limits.SQLiteRowLimit = scanSQLiteRowLimit

	s3Enum := enum.NewS3Enumerator(bucket, prefix, enum.Config{
		MaxFileSize:     scanMaxFileSize,
		ExtractArchives: string(scanExtractArchivesFlag),
		ExtractLimits:   limits,
	})

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

	if verbose {
		fmt.Fprintf(os.Stderr, "[scan] Starting S3 scan of s3://%s/%s with %d workers and %d rules\n", bucket, prefix, numWorkers, len(rules))
	}

	jobs := make(chan blobJob, 2*numWorkers)

	g, ctx := errgroup.WithContext(ctx)

	// Producer
	g.Go(func() error {
		defer close(jobs)
		return s3Enum.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			totalBytes.Add(int64(len(content)))
			count := blobCount.Add(1)
			if verbose && count%1000 == 0 {
				fmt.Fprintf(os.Stderr, "[enumerate] %d objects processed (%d bytes)\n", count, totalBytes.Load())
			}

			job := blobJob{content: content, blobID: blobID, prov: prov}
			if scanIncremental {
				send, skipped, err := incrementalJob(s, m, &job)
				if err != nil {
					return err
				}
				if skipped {
					skippedCount.Add(1)
				}
				if !send {
					return nil
				}
			}

			select {
			case jobs <- job:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	})

	// Consumer workers
	const batchSize = 64
	for i := 0; i < numWorkers; i++ {
		g.Go(func() error {
			type batchItem struct {
				blobID  types.BlobID
				prov    types.Provenance
				size    int64
				matches []*types.Match
				// locate is true when the blob's locations must be stored: it
				// matched, or a timed-out rule queued it for DrainTimedOut.
				locate bool
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
						if err := storeLocations(tx, item.blobID, item.prov, item.locate); err != nil {
							return err
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
								f := &types.Finding{
									ID:     findingID,
									RuleID: match.RuleID,
									Groups: match.Groups,
								}
								f.Score = s3Engine.Score(ctx, f, []*types.Match{match}, rule)
								if s3Accessibility == AccessibilityPrivate {
									ApplyAccessibilityModifier(f.Score)
								}
								if err := tx.AddFinding(f); err != nil {
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
				matches, err := matchJob(m, job)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[warn] match error (skipping blob %s): %v\n", job.blobID.Hex(), err)
					continue
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
					locate:  job.known || len(matches) > 0 || matcher.HasPendingRetry(m, job.blobID),
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
		// Suppress context.Canceled errors during shutdown
		if ctx.Err() != nil && errors.Is(err, context.Canceled) {
			// Normal shutdown via Ctrl+C, not an error
		} else {
			return fmt.Errorf("scanning: %w", err)
		}
	}

	if err := drainTimedOutMatches(ctx, m, s, ruleMap, s3Engine, &findingCount, &matchCount, s3Accessibility); err != nil {
		return fmt.Errorf("retrying timed-out blobs: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[scan] S3 scan complete: %d objects, %d matches, %d findings\n", blobCount.Load(), matchCount.Load(), findingCount.Load())
	}

	duration := time.Since(startTime)
	printScanStats(cmd, scanOutputFormat, scanOutputPath,
		totalBytes.Load(), blobCount.Load(), matchCount.Load(), skippedCount.Load(), duration)

	return outputScanResults(cmd, s, rules, ruleMap)
}

// runAsanaScan handles scanning of Asana workspaces detected from asana:// URLs.
func runAsanaScan(cmd *cobra.Command, scope enum.AsanaScope, gid string) error {
	token := os.Getenv("ASANA_TOKEN")
	if token == "" {
		return fmt.Errorf("asana token is required: set ASANA_TOKEN")
	}

	rules, err := loadRules(scanRulesPath, scanRulesInclude, scanRulesExclude, scanRuleset, scanIncludeNoisy)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	m, err := newMatcher(matcher.Config{
		Rules:        rules,
		ContextLines: scanContextLines,
		WarnFunc: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
	})
	if err != nil {
		return fmt.Errorf("creating matcher: %w", err)
	}
	defer m.Close()

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
	if validationEngine != nil {
		matcher.SetCanValidate(m, validationEngine.CanValidate)
	}

	asanaEngine, err := buildScoringEngine()
	if err != nil {
		return fmt.Errorf("initializing scoring engine: %w", err)
	}

	// Asana content has no git remote; resolve accessibility from the flag only
	// (auto falls back to private, which is the conservative default).
	asanaAccessibility := ResolveAccessibility(scanAccessibility, "", "")

	// Parse extraction limits
	limits := enum.DefaultExtractionLimits()
	if extractMaxSize != "" {
		size, err := parseSize(extractMaxSize)
		if err != nil {
			return fmt.Errorf("parsing extract-max-size: %w", err)
		}
		limits.MaxSize = size
	}
	if extractMaxTotal != "" {
		size, err := parseSize(extractMaxTotal)
		if err != nil {
			return fmt.Errorf("parsing extract-max-total: %w", err)
		}
		limits.MaxTotal = size
	}
	limits.MaxDepth = extractMaxDepth
	limits.SQLiteRowLimit = scanSQLiteRowLimit

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	cfg := enum.AsanaConfig{
		Token:              token,
		IncludeAttachments: scanAsanaIncludeAttachments,
		AttachmentMaxBytes: scanAsanaAttachmentMaxSize,
		RatePerSec:         scanAsanaRateLimit,
		Concurrency:        scanAsanaConcurrency,
		Verbose:            verboseWriter,
		Config: enum.Config{
			MaxFileSize:     scanMaxFileSize,
			ExtractArchives: string(scanExtractArchivesFlag),
			ExtractLimits:   limits,
		},
	}
	switch scope {
	case enum.AsanaScopeWorkspace:
		cfg.Workspace = gid
	case enum.AsanaScopeTeam:
		cfg.Team = gid
	case enum.AsanaScopeProject:
		cfg.Project = gid
	}

	asanaEnum, err := enum.NewAsanaEnumerator(cfg)
	if err != nil {
		return fmt.Errorf("creating Asana enumerator: %w", err)
	}

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

	if verbose {
		fmt.Fprintf(os.Stderr, "[scan] Starting Asana scan with %d workers and %d rules\n", numWorkers, len(rules))
	}

	jobs := make(chan blobJob, 2*numWorkers)

	g, ctx := errgroup.WithContext(ctx)

	// Producer
	g.Go(func() error {
		defer close(jobs)
		return asanaEnum.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			totalBytes.Add(int64(len(content)))
			count := blobCount.Add(1)
			if verbose && count%1000 == 0 {
				fmt.Fprintf(os.Stderr, "[enumerate] %d blobs processed (%d bytes)\n", count, totalBytes.Load())
			}

			job := blobJob{content: content, blobID: blobID, prov: prov}
			if scanIncremental {
				send, skipped, err := incrementalJob(s, m, &job)
				if err != nil {
					return err
				}
				if skipped {
					skippedCount.Add(1)
				}
				if !send {
					return nil
				}
			}

			select {
			case jobs <- job:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	})

	// Consumer workers
	const batchSize = 64
	for i := 0; i < numWorkers; i++ {
		g.Go(func() error {
			type batchItem struct {
				blobID  types.BlobID
				prov    types.Provenance
				size    int64
				matches []*types.Match
				// locate is true when the blob's locations must be stored: it
				// matched, or a timed-out rule queued it for DrainTimedOut.
				locate bool
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
						if err := storeLocations(tx, item.blobID, item.prov, item.locate); err != nil {
							return err
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
								f := &types.Finding{
									ID:     findingID,
									RuleID: match.RuleID,
									Groups: match.Groups,
								}
								f.Score = asanaEngine.Score(ctx, f, []*types.Match{match}, rule)
								if asanaAccessibility == AccessibilityPrivate {
									ApplyAccessibilityModifier(f.Score)
								}
								if err := tx.AddFinding(f); err != nil {
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
				matches, err := matchJob(m, job)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[warn] match error (skipping blob %s): %v\n", job.blobID.Hex(), err)
					continue
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
					locate:  job.known || len(matches) > 0 || matcher.HasPendingRetry(m, job.blobID),
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
		if ctx.Err() != nil && errors.Is(err, context.Canceled) {
			// Normal shutdown via Ctrl+C, not an error
		} else {
			return fmt.Errorf("scanning: %w", err)
		}
	}

	if err := drainTimedOutMatches(ctx, m, s, ruleMap, asanaEngine, &findingCount, &matchCount, asanaAccessibility); err != nil {
		return fmt.Errorf("retrying timed-out blobs: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[scan] Asana scan complete: %d blobs, %d matches, %d findings\n", blobCount.Load(), matchCount.Load(), findingCount.Load())
	}

	duration := time.Since(startTime)
	printScanStats(cmd, scanOutputFormat, scanOutputPath,
		totalBytes.Load(), blobCount.Load(), matchCount.Load(), skippedCount.Load(), duration)

	return outputScanResults(cmd, s, rules, ruleMap)
}

// runGDriveScan handles scanning of Google Drive targets detected from gdrive:// URLs.
func runGDriveScan(cmd *cobra.Command, scope enum.GDriveScope, driveID string) error {
	token := os.Getenv("GOOGLE_DRIVE_TOKEN")
	refresh := os.Getenv("GOOGLE_DRIVE_REFRESH_TOKEN")
	clientID := os.Getenv("GOOGLE_DRIVE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_DRIVE_CLIENT_SECRET")

	if token == "" && refresh == "" {
		return fmt.Errorf("auth required for Google Drive: set GOOGLE_DRIVE_TOKEN, or GOOGLE_DRIVE_REFRESH_TOKEN + GOOGLE_DRIVE_CLIENT_ID + GOOGLE_DRIVE_CLIENT_SECRET")
	}

	// Load rules
	rules, err := loadRules(scanRulesPath, scanRulesInclude, scanRulesExclude, scanRuleset, scanIncludeNoisy)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	// Create matcher
	m, err := newMatcher(matcher.Config{
		Rules:        rules,
		ContextLines: scanContextLines,
		WarnFunc: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
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

	// Store rules for foreign key constraints
	for _, r := range rules {
		if err := s.AddRule(r); err != nil {
			return fmt.Errorf("storing rule: %w", err)
		}
	}

	validationEngine := initValidationEngine()
	if validationEngine != nil {
		matcher.SetCanValidate(m, validationEngine.CanValidate)
	}

	gdriveEngine, err := buildScoringEngine()
	if err != nil {
		return fmt.Errorf("initializing scoring engine: %w", err)
	}

	// Drive content has no git remote; resolve from flag only.
	gdriveAccessibility := ResolveAccessibility(scanAccessibility, "", "")

	// Parse extraction limits
	limits := enum.DefaultExtractionLimits()
	if extractMaxSize != "" {
		size, err := parseSize(extractMaxSize)
		if err != nil {
			return fmt.Errorf("parsing extract-max-size: %w", err)
		}
		limits.MaxSize = size
	}
	if extractMaxTotal != "" {
		size, err := parseSize(extractMaxTotal)
		if err != nil {
			return fmt.Errorf("parsing extract-max-total: %w", err)
		}
		limits.MaxTotal = size
	}
	limits.MaxDepth = extractMaxDepth
	limits.SQLiteRowLimit = scanSQLiteRowLimit

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	gdriveEnum, err := enum.NewGDriveEnumerator(enum.GDriveConfig{
		Token:        token,
		RefreshToken: refresh,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
		DriveID:      driveID,
		Verbose:      verboseWriter,
		RateLimit:    scanGDriveRateLimit,
		Concurrency:  scanGDriveConcurrency,
		Config: enum.Config{
			MaxFileSize:     scanMaxFileSize,
			ExtractArchives: string(scanExtractArchivesFlag),
			ExtractLimits:   limits,
		},
	})
	if err != nil {
		return fmt.Errorf("creating Google Drive enumerator: %w", err)
	}

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

	if verbose {
		fmt.Fprintf(os.Stderr, "[scan] Starting Google Drive scan (scope=%d driveID=%q) with %d workers and %d rules\n", scope, driveID, numWorkers, len(rules))
	}

	jobs := make(chan blobJob, 2*numWorkers)

	g, ctx := errgroup.WithContext(ctx)

	// Producer
	g.Go(func() error {
		defer close(jobs)
		return gdriveEnum.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			totalBytes.Add(int64(len(content)))
			count := blobCount.Add(1)
			if verbose && count%1000 == 0 {
				fmt.Fprintf(os.Stderr, "[enumerate] %d objects processed (%d bytes)\n", count, totalBytes.Load())
			}

			job := blobJob{content: content, blobID: blobID, prov: prov}
			if scanIncremental {
				send, skipped, err := incrementalJob(s, m, &job)
				if err != nil {
					return err
				}
				if skipped {
					skippedCount.Add(1)
				}
				if !send {
					return nil
				}
			}

			select {
			case jobs <- job:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	})

	// Consumer workers
	const gdriveBatchSize = 64
	for i := 0; i < numWorkers; i++ {
		g.Go(func() error {
			type batchItem struct {
				blobID  types.BlobID
				prov    types.Provenance
				size    int64
				matches []*types.Match
				// locate is true when the blob's locations must be stored: it
				// matched, or a timed-out rule queued it for DrainTimedOut.
				locate bool
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
						if err := storeLocations(tx, item.blobID, item.prov, item.locate); err != nil {
							return err
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
								f := &types.Finding{
									ID:     findingID,
									RuleID: match.RuleID,
									Groups: match.Groups,
								}
								f.Score = gdriveEngine.Score(ctx, f, []*types.Match{match}, rule)
								if gdriveAccessibility == AccessibilityPrivate {
									ApplyAccessibilityModifier(f.Score)
								}
								if err := tx.AddFinding(f); err != nil {
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
				matches, err := matchJob(m, job)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[warn] match error (skipping blob %s): %v\n", job.blobID.Hex(), err)
					continue
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
					locate:  job.known || len(matches) > 0 || matcher.HasPendingRetry(m, job.blobID),
				})
				if len(batch) >= gdriveBatchSize {
					if err := flush(); err != nil {
						return err
					}
				}
			}
			return flush()
		})
	}

	if err := g.Wait(); err != nil {
		if ctx.Err() != nil && errors.Is(err, context.Canceled) {
			// Normal shutdown via Ctrl+C, not an error
		} else {
			return fmt.Errorf("scanning: %w", err)
		}
	}

	if err := drainTimedOutMatches(ctx, m, s, ruleMap, gdriveEngine, &findingCount, &matchCount, gdriveAccessibility); err != nil {
		return fmt.Errorf("retrying timed-out blobs: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[scan] Google Drive scan complete: %d objects, %d matches, %d findings\n", blobCount.Load(), matchCount.Load(), findingCount.Load())
	}

	duration := time.Since(startTime)
	printScanStats(cmd, scanOutputFormat, scanOutputPath,
		totalBytes.Load(), blobCount.Load(), matchCount.Load(), skippedCount.Load(), duration)

	return outputScanResults(cmd, s, rules, ruleMap)
}

// outputNoseyParkerSummary outputs findings in noseyparker table format
func outputNoseyParkerSummary(cmd *cobra.Command, findings []*types.Finding, ruleMap map[string]*types.Rule) error {
	if len(findings) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No findings.\n")
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
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), " %-*s   Findings   Matches \n", maxNameLen, "Rule")

	// Print separator line using box-drawing character
	separatorLen := maxNameLen + 3 + 10 + 3 + 8
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", strings.Repeat("─", separatorLen))

	// Print data rows
	for _, stats := range statsMap {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), " %-*s   %8d   %7d \n",
			maxNameLen, stats.name, stats.findings, stats.matches)
	}

	// Print footer
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nRun the `report` command next to show finding details.\n")

	return nil
}

// newMatcher builds the scan matcher. Tests replace it to drive the
// timeout-and-retry path deterministically.
var newMatcher = matcher.New

// storeLocations records the locations of a blob when locate is true: the
// blob has a match, or a timed-out rule queued it for DrainTimedOut, whose
// matches carry no provenance of their own. Other blobs get no location rows,
// which keeps the blob_locations table proportional to findings rather than
// to the tree.
func storeLocations(tx store.Store, blobID types.BlobID, prov types.Provenance, locate bool) error {
	if !locate {
		return nil
	}
	if err := tx.AddOccurrences(blobID, types.OccurrencesOf(prov)); err != nil {
		return fmt.Errorf("storing locations: %w", err)
	}
	return nil
}

// scanJSONMatch is one element of `titus scan --format=json` output: the
// match with every existing field unchanged, plus every location of its blob.
type scanJSONMatch struct {
	*types.Match
	Locations []jsonLocation `json:"locations"`
	// LocationsTruncated marks a blob with more locations than were recorded.
	LocationsTruncated bool `json:"locations_truncated,omitempty"`
}

// outputMatches emits the scan's raw matches as JSON for `titus scan --format=json`.
// Each match carries the locations of its blob. This is NOT the score-bearing
// output — findings (with their Score) are persisted in the datastore and
// surfaced via `titus report --format=json`. Downstream consumers (Chariot, CI)
// that need severity should use the report output.
func outputMatches(cmd *cobra.Command, s store.Store, matches []*types.Match) error {
	out := make([]scanJSONMatch, 0, len(matches))
	cache := make(map[types.BlobID]blobLocations)
	for _, m := range matches {
		locs, ok := cache[m.BlobID]
		if !ok {
			var err error
			if locs, err = loadBlobLocations(s, m); err != nil {
				return err
			}
			cache[m.BlobID] = locs
		}
		out = append(out, scanJSONMatch{
			Match:              m,
			Locations:          toJSONLocations(m, locs.occs),
			LocationsTruncated: locs.truncated,
		})
	}
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

// outputFindings writes `titus enum` human output: one line per finding, then
// every location of every match of that finding and the truncation marker.
// runEnumScan validates its own --format and handles json before calling
// this, so the output is always human; it must not read scan's
// scanOutputFormat, which belongs to another command.
func outputFindings(cmd *cobra.Command, s store.Store, ruleMap map[string]*types.Rule, findings []*types.Finding) error {
	out := cmd.OutOrStdout()
	if len(findings) == 0 {
		_, _ = fmt.Fprintf(out, "\nNo findings.\n")
		return nil
	}

	matches, err := s.GetAllMatches()
	if err != nil {
		return fmt.Errorf("retrieving matches: %w", err)
	}
	matchesByFinding := buildFindingMatchMap(findings, matches, ruleMap)
	cache := make(map[types.BlobID]blobLocations)

	_, _ = fmt.Fprintf(out, "\nFindings:\n")
	for i, f := range findings {
		_, _ = fmt.Fprintf(out, "%d. Rule: %s", i+1, f.RuleID)

		// Show validation status if available
		if len(f.Matches) > 0 && f.Matches[0].ValidationResult != nil {
			vr := f.Matches[0].ValidationResult
			_, _ = fmt.Fprintf(out, " [%s]", vr.Status)
		}
		_, _ = fmt.Fprintln(out)

		for _, m := range matchesByFinding[f.ID] {
			locs, ok := cache[m.BlobID]
			if !ok {
				if locs, err = loadBlobLocations(s, m); err != nil {
					return err
				}
				cache[m.BlobID] = locs
			}
			writeLocationLines(out, m.Location.Source.Start.Line, locs.occs, nil)
			writeLocationsTruncated(out, locs.truncated, nil)
		}
	}
	return nil
}

// outputSARIF outputs matches in SARIF 2.1.0 format, one result per
// location of each match's blob.
func outputSARIF(cmd *cobra.Command, s store.Store, rules []*types.Rule, matches []*types.Match) error {
	ruleMap := make(map[string]*types.Rule, len(rules))
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	// Build finding lookup so we can attach Score to each SARIF result
	findingByID := make(map[string]*types.Finding)
	if findings, err := s.GetFindings(); err == nil {
		for _, f := range findings {
			findingByID[f.ID] = f
		}
	}

	scoreFor := func(m *types.Match) *types.Score {
		r, ok := ruleMap[m.RuleID]
		if !ok {
			return nil
		}
		if f, ok := findingByID[types.ComputeFindingID(r.StructuralID, m.Groups)]; ok {
			return f.Score
		}
		return nil
	}
	return writeSARIF(cmd.OutOrStdout(), s, rules, matches, scoreFor)
}

// initValidationEngine creates the validation engine if validation is enabled.
func initValidationEngine() *validator.Engine {
	if !scanValidate {
		return nil
	}
	return validator.NewDefaultEngine(scanValidateWorkers)
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
				i+1, matches[i].RuleID, result.Status, result.Confidence, types.SanitizeDisplay(result.Message))
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[validate] Validation complete\n")
	}
}

// resolveAutoName picks the best name for auto output from the available identifiers.
// Priority: group/org > user > project/repo argument > fallback "output".
func resolveAutoName(group, user, project string) string {
	if group != "" {
		// Use last segment of group path (e.g. "ctp1/tmna-ct/tmna-ev" → "tmna-ev")
		parts := strings.Split(group, "/")
		return parts[len(parts)-1] + ".db"
	}
	if user != "" {
		return user + ".db"
	}
	if project != "" {
		// project may be "owner/repo" — take repo part
		parts := strings.Split(project, "/")
		return parts[len(parts)-1] + ".db"
	}
	return "output.db"
}

// resolveAutoOutput derives a datastore name from a scan target.
// For repo URLs (github.com/ or gitlab.com/), it extracts the repo name.
// For filesystem paths, it uses the base name of the path.
func resolveAutoOutput(target string) string {
	if image, ok := enum.ParseDockerImageReference(target); ok {
		return dockerAutoOutputName(image)
	}
	if ami, ok := enum.ParseAMIReference(target); ok {
		return amiAutoOutputName(ami)
	}

	// Strip scheme prefix (e.g. "https://")
	cleaned := target
	if idx := strings.Index(cleaned, "://"); idx >= 0 {
		cleaned = cleaned[idx+3:]
	}

	// Strip trailing slashes before domain matching so that
	// "https://github.com/org/repo.git/" resolves correctly.
	cleaned = strings.TrimRight(cleaned, "/")

	// Check for known git hosting domains
	for _, prefix := range []string{"github.com/", "gitlab.com/"} {
		if strings.HasPrefix(cleaned, prefix) {
			rest := cleaned[len(prefix):]
			// rest is "owner/repo" or "owner/repo.git"
			parts := strings.SplitN(rest, "/", 2)
			if len(parts) == 2 {
				repo := strings.TrimSuffix(parts[1], ".git")
				return repo + ".ds"
			}
		}
	}

	// Filesystem path: strip trailing slash then take base name.
	path := strings.TrimRight(target, "/")
	if path == "." || path == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "output.ds"
		}
		path = wd
	}
	return filepath.Base(path) + ".ds"
}

func dockerAutoOutputName(image string) string {
	image = strings.TrimSpace(image)
	image = strings.TrimPrefix(image, "docker://")
	if image == "" {
		return "docker-image.ds"
	}
	if idx := strings.LastIndex(image, "@"); idx >= 0 {
		image = image[:idx]
	}
	image = strings.TrimRight(image, "/")
	replacer := strings.NewReplacer("/", "_", ":", "_", "@", "_")
	return replacer.Replace(image) + ".ds"
}

// scoringEngineInterface is the narrow surface runScan needs, kept as an
// interface for ease of swapping in tests (currently always *scoring.Engine).
type scoringEngineInterface interface {
	Score(ctx context.Context, f *types.Finding, matches []*types.Match, rule *types.Rule) *types.Score
	Stats() scoring.HTTPModifierStats
}

// buildScoringEngine constructs the M2 scoring engine from the embedded scorer
// YAMLs. Returns a non-nil engine even when no scorers load — in that case
// Score() always returns base-only.
//
// Loader errors (malformed YAML, bad regex) are hard failures: scan startup
// must abort rather than silently scoring all findings at base.
func buildScoringEngine() (scoringEngineInterface, error) {
	allScorers, err := scoring.AllBuiltinScorers()
	if err != nil {
		return nil, fmt.Errorf("loading scorers: %w", err)
	}
	cfg := scoring.EngineConfig{
		ScopeEnabled: scanScopeEnabled,
		Timeout:      scanScoreTimeout,
		Budget:       scanScoreBudget,
	}
	return scoring.NewEngine(allScorers, cfg), nil
}
