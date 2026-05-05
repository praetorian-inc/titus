package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

// pipelineOpts captures the per-call inputs for runPipeline. All other
// configuration is read from package-level scan* globals (set by cobra flags).
type pipelineOpts struct {
	Target       string // for accessibility detection + log messages
	OutputPath   string // already :auto:-resolved by caller
	OutputFormat string // "json" | "sarif" | "human"
	TokenEnvVar  string // env var name for accessibility token; "" = filesystem/no token
}

// runPipeline executes the full scan pipeline (rules -> matcher -> store ->
// producer/consumer workers -> drain -> output) for an arbitrary enumerator.
// It is the shared core extracted from runScan; URL routing and :auto:
// resolution remain in the caller.
func runPipeline(ctx context.Context, cmd *cobra.Command, enumerator enum.Enumerator, opts pipelineOpts) error {
	// Load rules
	rules, err := loadRules(scanRulesPath, scanRulesInclude, scanRulesExclude, scanRuleset)
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
		WarnFunc: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
	})
	if err != nil {
		return fmt.Errorf("creating matcher: %w", err)
	}
	defer m.Close()

	// Create store (memory or datastore)
	s, ds, err := openScanStore(opts.OutputPath, scanStoreBlobs)
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
	var token string
	if opts.TokenEnvVar != "" {
		token = os.Getenv(opts.TokenEnvVar)
	}
	accessibility := ResolveAccessibility(scanAccessibility, opts.Target, token)

	// Scan with parallel workers
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

	// errgroup.WithContext cancels the derived ctx when g.Wait() returns, so
	// keep parentCtx aside for post-Wait work (drainTimedOutMatches scores
	// retry findings via engine.Score, which short-circuits on a canceled ctx).
	parentCtx := ctx
	g, ctx := errgroup.WithContext(parentCtx)

	// Producer: enumerate blobs and send to workers (NO DB writes)
	g.Go(func() error {
		defer close(jobs)
		if verbose {
			fmt.Fprintf(os.Stderr, "[enumerate] Starting enumeration of %s\n", opts.Target)
		}
		return enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			totalBytes.Add(int64(len(content)))
			count := blobCount.Add(1)
			if verbose && count%1000 == 0 {
				fmt.Fprintf(os.Stderr, "[enumerate] %d files discovered (%d bytes)\n", count, totalBytes.Load())
			}

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
							added, err := upsertFinding(ctx, tx, match, ruleMap, engine, accessibility)
							if err != nil {
								return err
							}
							if added {
								findingCount.Add(1)
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

	// Retry any blobs that timed out during the parallel pass. Use parentCtx
	// because the errgroup-derived ctx is canceled by g.Wait().
	if err := drainTimedOutMatches(parentCtx, m, s, ruleMap, engine, &findingCount, &matchCount, accessibility); err != nil {
		return fmt.Errorf("retrying timed-out blobs: %w", err)
	}

	// Emit aggregate dynamic modifier stats if any errors occurred.
	if st := engine.Stats(); st.Any() {
		fmt.Fprintf(os.Stderr, "[scoring] Dynamic modifiers: %d timeouts, %d rate-limited, %d server errors, %d network errors\n",
			st.Timeouts, st.RateLimited, st.ServerErrors, st.NetworkErrors)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[scan] Scan complete: %d blobs, %d matches, %d findings\n", blobCount.Load(), matchCount.Load(), findingCount.Load())
	}

	duration := time.Since(startTime)
	printScanStats(cmd, opts.OutputFormat, opts.OutputPath,
		totalBytes.Load(), blobCount.Load(), matchCount.Load(), skippedCount.Load(), duration)

	return outputScanResults(cmd, s, rules, ruleMap)
}

// upsertFinding adds a finding for match if no finding with the same
// structural ID already exists. Returns true when a new finding was inserted.
// Shared between runPipeline's worker flush and drainTimedOutMatches so
// scoring + accessibility semantics cannot drift between the two paths.
func upsertFinding(ctx context.Context, tx store.Store, match *types.Match, ruleMap map[string]*types.Rule, engine scoringEngineInterface, accessibility Accessibility) (bool, error) {
	rule, ok := ruleMap[match.RuleID]
	if !ok {
		return false, fmt.Errorf("rule not found: %s", match.RuleID)
	}
	findingID := types.ComputeFindingID(rule.StructuralID, match.Groups)
	exists, err := tx.FindingExists(findingID)
	if err != nil {
		return false, fmt.Errorf("checking finding: %w", err)
	}
	if exists {
		return false, nil
	}
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
		return false, fmt.Errorf("storing finding: %w", err)
	}
	return true, nil
}
